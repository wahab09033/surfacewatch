"""Report rendering.

Runs on its own queue: WeasyPrint is CPU and memory heavy, and rendering a
200-page PDF should never stall a scan worker.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from jinja2 import Environment, select_autoescape
from sqlalchemy import desc, func, select

from db.database import session_scope
from models import Asset, Finding, FindingStatus, Organisation, Report, Scan, Severity

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title }}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; @bottom-center { content: counter(page); font-size: 9pt; color: #64748b; } }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; font-size: 10pt; color: #0f172a; line-height: 1.5; }
  h1 { font-size: 22pt; margin: 0 0 4pt; }
  h2 { font-size: 14pt; margin: 20pt 0 8pt; border-bottom: 1px solid #cbd5e1; padding-bottom: 4pt; }
  h3 { font-size: 11pt; margin: 14pt 0 4pt; }
  .meta { color: #64748b; font-size: 9pt; margin-bottom: 18pt; }
  table { width: 100%; border-collapse: collapse; margin: 8pt 0; }
  th, td { text-align: left; padding: 5pt 6pt; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { background: #f1f5f9; font-size: 9pt; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
  td { font-size: 9.5pt; }
  .sev { display: inline-block; padding: 1pt 6pt; border-radius: 3pt; font-size: 8.5pt; font-weight: 600; color: #fff; }
  .critical { background: #7f1d1d; } .high { background: #b91c1c; }
  .medium { background: #c2410c; } .low { background: #a16207; } .info { background: #475569; }
  .summary-grid { display: flex; gap: 10pt; margin: 10pt 0 4pt; }
  .card { flex: 1; border: 1px solid #e2e8f0; border-radius: 4pt; padding: 8pt; }
  .card .n { font-size: 18pt; font-weight: 700; }
  .card .l { font-size: 8.5pt; color: #64748b; text-transform: uppercase; }
  .finding { break-inside: avoid; border-left: 3pt solid #cbd5e1; padding-left: 8pt; margin: 10pt 0; }
  .finding.critical, .finding.high { border-left-color: #b91c1c; }
  .finding.medium { border-left-color: #c2410c; }
  .muted { color: #64748b; font-size: 9pt; }
  code { background: #f1f5f9; padding: 1pt 3pt; border-radius: 2pt; font-size: 8.5pt; }
</style>
</head>
<body>
  <h1>{{ title }}</h1>
  <div class="meta">
    {{ org.name }} &middot; {{ org.domain }}<br>
    Generated {{ generated_at }}{% if scan %} &middot; scan of {{ scan.target }}{% endif %}
  </div>

  <h2>Executive summary</h2>
  <div class="summary-grid">
    <div class="card"><div class="n">{{ stats.assets }}</div><div class="l">Assets</div></div>
    <div class="card"><div class="n">{{ stats.open }}</div><div class="l">Open findings</div></div>
    <div class="card"><div class="n">{{ stats.by_severity.critical }}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n">{{ stats.by_severity.high }}</div><div class="l">High</div></div>
  </div>
  <p>
    This report covers {{ stats.assets }} asset{{ '' if stats.assets == 1 else 's' }}
    across {{ org.domain }}. {{ stats.open }} finding{{ '' if stats.open == 1 else 's' }}
    {{ 'is' if stats.open == 1 else 'are' }} currently open, of which
    {{ stats.by_severity.critical + stats.by_severity.high }} rate high or critical
    and warrant attention first.
  </p>

  <h2>Highest-risk assets</h2>
  <table>
    <thead><tr><th>Host</th><th>IP</th><th>Risk</th><th>Open ports</th><th>Technologies</th></tr></thead>
    <tbody>
    {% for a in assets %}
      <tr>
        <td>{{ a.hostname }}</td>
        <td class="muted">{{ a.ip or '—' }}</td>
        <td>{{ '%.1f'|format(a.risk_score) }}</td>
        <td class="muted">{{ a.open_ports|join(', ') or '—' }}</td>
        <td class="muted">{{ a.technologies[:6]|join(', ') or '—' }}</td>
      </tr>
    {% else %}
      <tr><td colspan="5" class="muted">No assets recorded.</td></tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Findings</h2>
  {% for f in findings %}
    <div class="finding {{ f.severity.value }}">
      <h3>
        <span class="sev {{ f.severity.value }}">{{ f.severity.value|upper }}</span>
        {{ f.title }}
      </h3>
      <div class="muted">
        {% if f.cve_id %}<code>{{ f.cve_id }}</code>{% endif %}
        {% if f.cvss_score %} &middot; CVSS {{ f.cvss_score }}{% endif %}
        {% if f.asset_hostname %} &middot; {{ f.asset_hostname }}{% endif %}
        &middot; {{ f.status.value }}
      </div>
      {% if f.description %}<p>{{ f.description }}</p>{% endif %}
      {% if f.remediation %}<p><strong>Remediation.</strong> {{ f.remediation }}</p>{% endif %}
    </div>
  {% else %}
    <p class="muted">No findings matched the selected filters.</p>
  {% endfor %}
</body>
</html>
"""


def _collect(org_id: uuid.UUID, options: dict[str, Any]) -> dict[str, Any]:
    """Gather everything the report needs, scoped to one organisation."""
    min_severity = Severity(options.get("min_severity") or "low")
    min_rank = _SEVERITY_RANK[min_severity]
    scan_id = options.get("scan_id")

    with session_scope() as session:
        org = session.get(Organisation, org_id)
        if org is None:
            raise ValueError(f"Organisation {org_id} not found")
        org_data = {"name": org.name, "domain": org.domain}

        scan = None
        if scan_id:
            scan_row = session.scalar(
                select(Scan).where(Scan.id == uuid.UUID(str(scan_id)), Scan.org_id == org_id)
            )
            if scan_row is not None:
                scan = {"target": scan_row.target, "id": str(scan_row.id)}

        conditions = [Finding.org_id == org_id]
        if scan_id:
            conditions.append(Finding.scan_id == uuid.UUID(str(scan_id)))
        if not options.get("include_remediated"):
            conditions.append(
                Finding.status.in_(
                    [FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.CONFIRMED]
                )
            )

        rows = session.execute(
            select(Finding, Asset.hostname)
            .outerjoin(Asset, Asset.id == Finding.asset_id)
            .where(*conditions)
            .order_by(desc(Finding.cvss_score).nullslast(), desc(Finding.created_at))
        ).all()

        findings = []
        for finding, hostname in rows:
            if _SEVERITY_RANK[finding.severity] < min_rank:
                continue
            if finding.severity == Severity.INFO and not options.get("include_info"):
                continue
            findings.append(
                {
                    "id": str(finding.id),
                    "title": finding.title,
                    "severity": finding.severity,
                    "cve_id": finding.cve_id,
                    "cvss_score": finding.cvss_score,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "status": finding.status,
                    "asset_hostname": hostname,
                    "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
                }
            )

        asset_rows = list(
            session.scalars(
                select(Asset)
                .where(Asset.org_id == org_id)
                .order_by(desc(Asset.risk_score))
                .limit(50)
            )
        )
        assets = [
            {
                "hostname": a.hostname,
                "ip": a.ip,
                "risk_score": a.risk_score,
                "open_ports": a.open_ports,
                "technologies": a.technologies,
                "status": a.status.value,
            }
            for a in asset_rows
        ]

        asset_total = (
            session.scalar(select(func.count(Asset.id)).where(Asset.org_id == org_id)) or 0
        )

    by_severity = {s.value: 0 for s in Severity}
    for f in findings:
        by_severity[f["severity"].value] += 1

    return {
        "org": org_data,
        "scan": scan,
        "assets": assets,
        "findings": findings,
        "stats": {
            "assets": asset_total,
            "open": len(findings),
            "by_severity": by_severity,
        },
    }


def _render_pdf(data: dict[str, Any], title: str, path: str) -> int:
    env = Environment(autoescape=select_autoescape(["html"]))
    template = env.from_string(_HTML_TEMPLATE)
    html = template.render(
        title=title,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        **data,
    )

    try:
        from weasyprint import HTML

        HTML(string=html).write_pdf(path)
    except (ImportError, OSError) as exc:
        # WeasyPrint needs native libs (pango/cairo). Rather than failing the
        # job, fall back to HTML so the user still gets a readable artefact.
        logger.warning("PDF rendering unavailable (%s); writing HTML instead", exc)
        fallback = path.rsplit(".", 1)[0] + ".html"
        with open(fallback, "w", encoding="utf-8") as handle:
            handle.write(html)
        os.replace(fallback, path)

    return os.path.getsize(path)


def _render_json(data: dict[str, Any], path: str) -> int:
    payload = {
        "organisation": data["org"],
        "scan": data["scan"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "statistics": data["stats"],
        "assets": data["assets"],
        "findings": [
            {**f, "severity": f["severity"].value, "status": f["status"].value}
            for f in data["findings"]
        ],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
    return os.path.getsize(path)


def _render_csv(data: dict[str, Any], path: str) -> int:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["severity", "cvss", "cve", "asset", "title", "status", "remediation", "first_seen"]
    )
    for f in data["findings"]:
        writer.writerow(
            [
                f["severity"].value,
                f["cvss_score"] or "",
                f["cve_id"] or "",
                f["asset_hostname"] or "",
                f["title"],
                f["status"].value,
                (f["remediation"] or "").replace("\n", " "),
                f["first_seen"] or "",
            ]
        )
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(buffer.getvalue())
    return os.path.getsize(path)


@shared_task(
    name="workers.report_builder.build_report",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    soft_time_limit=600,
)
def build_report(self, report_id: str, org_id: str, options: dict[str, Any]) -> str:
    """Render a report and flip its row to ``ready``."""
    rid = uuid.UUID(report_id)
    oid = uuid.UUID(org_id)

    with session_scope() as session:
        report = session.get(Report, rid)
        if report is None:
            return "missing"
        # Belt and braces: the row must belong to the org named in the task.
        if report.org_id != oid:
            logger.error("report %s does not belong to org %s", rid, oid)
            return "forbidden"
        path = report.file_path
        fmt = report.format
        title = report.title or "Attack surface report"

    os.makedirs(os.path.dirname(path), exist_ok=True)

    try:
        data = _collect(oid, options)
        if fmt == "json":
            size = _render_json(data, path)
        elif fmt == "csv":
            size = _render_csv(data, path)
        else:
            size = _render_pdf(data, title, path)
    except Exception as exc:
        logger.exception("report generation failed for %s", rid)
        with session_scope() as session:
            report = session.get(Report, rid)
            if report is not None:
                report.status = "failed"
                report.summary = {**(report.summary or {}), "error": str(exc)[:1000]}
        raise

    with session_scope() as session:
        report = session.get(Report, rid)
        if report is not None:
            report.status = "ready"
            report.size_bytes = size
            report.summary = {
                **(report.summary or {}),
                "assets": data["stats"]["assets"],
                "findings": data["stats"]["open"],
                "by_severity": data["stats"]["by_severity"],
            }

    return "ready"
