"""AI remediation worker.

Runs after the CVE correlator, over the findings it just wrote. Separate task
rather than inline in the correlator for three reasons: the correlator is
already rate-limited against NVD and should not also be waiting on a second
API; a failure here must not fail the scan that produced the findings; and
enrichment is worth retrying on its own schedule when the correlation is not.

Ordering is by severity descending — if the per-scan cap truncates the work,
the critical findings are the ones that got the good advice.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx
from celery import shared_task
from sqlalchemy import select

from config import settings
from core.events import sync_redis
from db.database import session_scope
from models import Asset, Finding, Severity
from services import ai_remediation
from workers.context import ScanContext

logger = logging.getLogger(__name__)

STAGE = "ai_remediation"

# Worst-first, so a truncated run still enriched what matters.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@shared_task(
    name="workers.ai_remediation.run",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
    soft_time_limit=1_800,
)
def run(self, payload: dict[str, Any]) -> dict[str, Any]:
    """Enrich the findings listed in ``payload['finding_ids']``.

    Returns ``payload`` unchanged so this can sit in a chain, though it is
    currently dispatched standalone by the correlator.
    """
    ctx = ScanContext.load(
        scan_id=payload["scan_id"],
        org_id=payload["org_id"],
        target=payload.get("target") or "",
        config=payload.get("config") or {},
    ).for_stage(STAGE)

    finding_ids = [uuid.UUID(str(f)) for f in (payload.get("finding_ids") or [])]
    if not finding_ids:
        return payload

    if not settings.ai_remediation_active:
        # Said once, at info level, rather than per finding. The findings keep
        # their template remediation, which is a working product.
        ctx.log(
            "AI remediation is not configured (AI_REMEDIATION_API_KEY unset); "
            "findings keep the standard remediation text"
        )
        return payload

    ctx.log(f"Generating context-specific remediation for {len(finding_ids)} finding(s)")

    # Load everything up front, then close the session. The model calls take
    # seconds each and holding a transaction open across them would pin a
    # connection from the pool for the whole run.
    with session_scope() as session:
        rows = list(
            session.execute(
                select(Finding, Asset)
                .join(Asset, Finding.asset_id == Asset.id)
                # org_id on both sides: the join alone would let a finding
                # reach an asset from another tenant if an id were ever reused.
                .where(
                    Finding.id.in_(finding_ids),
                    Finding.org_id == ctx.org_id,
                    Asset.org_id == ctx.org_id,
                )
            )
        )
        work = [
            {
                "finding_id": finding.id,
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "cvss_vector": finding.cvss_vector,
                "severity": finding.severity,
                "description": finding.description,
                "fallback": finding.remediation or "",
                "evidence": dict(finding.evidence or {}),
                "asset": ai_remediation.AssetContext(
                    hostname=asset.hostname,
                    ip=asset.ip,
                    open_ports=[
                        p for p in (asset.ports or []) if p.get("state") == "open"
                    ],
                    tech_stack=list(asset.tech_stack or []),
                ),
            }
            for finding, asset in rows
        ]

    work = [w for w in work if w["cve_id"]]
    work.sort(key=lambda w: _SEVERITY_RANK.get(w["severity"], 9))

    capped = len(work) > settings.ai_remediation_max_per_scan
    if capped:
        skipped = len(work) - settings.ai_remediation_max_per_scan
        work = work[: settings.ai_remediation_max_per_scan]
        # Announced, not silent. A truncated enrichment that says nothing looks
        # identical to one where the model simply had little to add.
        ctx.warn(
            f"Capped at {settings.ai_remediation_max_per_scan} AI remediations for this scan; "
            f"{skipped} lower-severity finding(s) keep the standard text "
            f"(raise AI_REMEDIATION_MAX_PER_SCAN to change this)"
        )

    redis_client = sync_redis()
    enriched = 0
    fell_back = 0

    # One HTTP client for the whole run — connection reuse matters when this is
    # dozens of sequential calls to the same host.
    with httpx.Client(timeout=settings.ai_remediation_timeout) as client:
        for item in work:
            if ctx.is_cancelled():
                ctx.log("Scan cancelled; stopping AI remediation")
                break

            evidence = item["evidence"]
            product = str(evidence.get("product") or "").strip()
            version = str(evidence.get("version") or "").strip()
            if not product:
                continue

            result = ai_remediation.generate(
                cve_id=item["cve_id"],
                cvss_score=item["cvss_score"],
                cvss_vector=item["cvss_vector"],
                severity=item["severity"].value,
                description=item["description"],
                product=product,
                version=version,
                asset=item["asset"],
                fallback=item["fallback"],
                redis_client=redis_client,
                http_client=client,
            )

            if not result.is_ai:
                fell_back += 1
                continue

            with session_scope() as session:
                finding = session.get(Finding, item["finding_id"])
                # Re-check the tenant after reload: this row was read in an
                # earlier transaction and the session.get above is by primary
                # key alone.
                if finding is None or finding.org_id != ctx.org_id:
                    continue
                finding.remediation = result.text
                # Replaced wholesale rather than mutated in place — JSONB
                # columns are only marked dirty on assignment, so mutating the
                # dict would not persist.
                finding.evidence = {
                    **(finding.evidence or {}),
                    "remediation_source": result.source,
                    "remediation_model": result.model,
                    "remediation_confidence": result.confidence,
                    "remediation_uncertain": result.uncertain or [],
                }
            enriched += 1

    if fell_back:
        ctx.warn(
            f"{fell_back} finding(s) kept the standard remediation because the "
            f"Claude API call did not return usable advice"
        )
    ctx.log(f"AI remediation complete: {enriched} finding(s) enriched")
    return payload


__all__ = ["run"]
