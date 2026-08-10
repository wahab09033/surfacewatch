"""CVE correlation.

Takes the technology/version pairs produced by the fingerprinter and looks up
matching CVEs in the NVD 2.0 API, then records one finding per (asset, CVE).

Two things keep this honest:

* Only versioned detections are queried. Matching "nginx" with no version would
  produce every nginx CVE ever published, which is noise, not intelligence.
* Results are cached in Redis. NVD rate-limits hard (5 requests / 30s without a
  key) and the same stack appears on dozens of hosts in one estate.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import redis
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config import settings
from core.events import sync_redis
from core.scoring import score_asset
from db.database import session_scope
from models import Asset, Finding, Severity
from workers.celery_app import celery_app
from workers.context import ScanContext
from workers.safe_http import safe_client

logger = logging.getLogger(__name__)

STAGE = "cve_correlator"

# NVD's documented ceiling is 5 req/30s anonymous, 50 req/30s with a key.
# Stay a little under both.
_RATE_DELAY_NO_KEY = 6.5
_RATE_DELAY_WITH_KEY = 0.7
_CACHE_PREFIX = "cve:lookup:"
_MAX_CVES_PER_PRODUCT = 25


def _cache_key(product: str, version: str) -> str:
    return f"{_CACHE_PREFIX}{product}:{version}"


def _cached(client: redis.Redis, product: str, version: str) -> list[dict[str, Any]] | None:
    try:
        raw = client.get(_cache_key(product, version))
    except redis.RedisError:
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _store_cache(
    client: redis.Redis, product: str, version: str, entries: list[dict[str, Any]]
) -> None:
    try:
        client.setex(
            _cache_key(product, version),
            settings.nvd_cache_ttl_seconds,
            json.dumps(entries),
        )
    except redis.RedisError:
        pass


def _parse_cve(item: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the fields we care about out of an NVD 2.0 record."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = ""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break

    score: float | None = None
    vector: str | None = None
    metrics = cve.get("metrics") or {}
    # Prefer v3.1, fall back to v3.0, then v2 — newest scoring wins.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        break

    references = [
        ref["url"] for ref in (cve.get("references") or []) if ref.get("url")
    ][:8]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": float(score) if score is not None else None,
        "cvss_vector": vector,
        "published": cve.get("published"),
        "references": references,
    }


def _query_nvd(
    ctx: ScanContext, client: httpx.Client, product: str, version: str
) -> list[dict[str, Any]]:
    """Query NVD by CPE match string for one product/version pair."""
    cpe = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
    params = {"cpeName": cpe, "resultsPerPage": _MAX_CVES_PER_PRODUCT}
    headers = {"User-Agent": settings.http_user_agent}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
        response = client.get(settings.nvd_api_base, params=params, headers=headers)
    except httpx.HTTPError as exc:
        ctx.warn(f"NVD lookup failed for {product} {version}: {exc}")
        return []

    if response.status_code == 404:
        return []
    if response.status_code == 403:
        ctx.warn("NVD rejected the request (rate limit or invalid API key)")
        return []
    if response.status_code != 200:
        ctx.warn(f"NVD returned HTTP {response.status_code} for {product} {version}")
        return []

    try:
        payload = response.json()
    except ValueError:
        return []

    results = []
    for item in payload.get("vulnerabilities", []):
        parsed = _parse_cve(item)
        if parsed:
            results.append(parsed)
    return results


def _remediation_for(product: str, version: str, cve_id: str) -> str:
    return (
        f"Upgrade {product} beyond {version} to a release that patches {cve_id}. "
        f"If an immediate upgrade is not possible, check the vendor advisory for a "
        f"workaround and restrict network access to the affected service in the meantime."
    )


@shared_task(
    name="workers.cve_correlator.run",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    soft_time_limit=1_800,
)
def run(self, payload: dict[str, Any]) -> dict[str, Any]:
    ctx = ScanContext.load(
        scan_id=payload["scan_id"],
        org_id=payload["org_id"],
        target=payload["target"],
        config=payload.get("config") or {},
    ).for_stage(STAGE)

    ctx.set_stage(STAGE, progress=80)

    hosts: list[str] = payload.get("hosts") or [ctx.target]

    # Collect versioned technologies across every asset in this scan, so each
    # product/version pair is queried once no matter how many hosts run it.
    with session_scope() as session:
        assets = list(
            session.scalars(
                select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname.in_(hosts))
            )
        )
        asset_tech: dict[uuid.UUID, tuple[str, list[dict[str, Any]]]] = {
            a.id: (a.hostname, list(a.tech_stack or [])) for a in assets
        }

    pairs: set[tuple[str, str]] = set()
    for _, technologies in asset_tech.values():
        for tech in technologies:
            name = (tech.get("name") or "").strip().lower()
            version = (tech.get("version") or "").strip()
            # Unversioned detections are skipped deliberately — see module docstring.
            if name and version:
                pairs.add((name, version))

    if not pairs:
        ctx.log("No versioned technologies detected; nothing to correlate against NVD")
        return payload

    ctx.log(f"Correlating {len(pairs)} product/version pair(s) against NVD")

    redis_client = sync_redis()
    delay = _RATE_DELAY_WITH_KEY if settings.nvd_api_key else _RATE_DELAY_NO_KEY
    if not settings.nvd_api_key:
        ctx.debug("No NVD API key configured; throttling to the anonymous rate limit")

    lookup: dict[tuple[str, str], list[dict[str, Any]]] = {}
    with safe_client(timeout=30.0, follow_redirects=True) as client:
        for index, (product, version) in enumerate(sorted(pairs)):
            if ctx.is_cancelled():
                ctx.log("Scan cancelled; stopping CVE correlation")
                break

            cached = _cached(redis_client, product, version)
            if cached is not None:
                lookup[(product, version)] = cached
                ctx.debug(f"{product} {version}: {len(cached)} CVE(s) from cache")
                continue

            if index > 0:
                time.sleep(delay)

            entries = _query_nvd(ctx, client, product, version)
            lookup[(product, version)] = entries
            _store_cache(redis_client, product, version, entries)
            if entries:
                ctx.log(f"{product} {version}: {len(entries)} known CVE(s)")

    # Attach findings to each asset running an affected version.
    now = datetime.now(timezone.utc)
    total_findings = 0
    # Findings created on this run, as opposed to re-confirmed by it. Both the
    # AI enrichment and the Slack alert key off creation: re-running a nightly
    # scan must not re-page the on-call for a CVE they triaged last week, and
    # must not pay for advice that is already stored on the row.
    new_finding_ids: list[str] = []
    new_critical: list[dict[str, Any]] = []

    for asset_id, (hostname, technologies) in asset_tech.items():
        asset_findings = 0
        with session_scope() as session:
            for tech in technologies:
                name = (tech.get("name") or "").strip().lower()
                version = (tech.get("version") or "").strip()
                if not (name and version):
                    continue

                for entry in lookup.get((name, version), []):
                    severity = Severity.from_cvss(entry["cvss_score"])
                    title = f"{entry['cve_id']} in {name} {version} on {hostname}"
                    stmt = (
                        pg_insert(Finding)
                        .values(
                            id=uuid.uuid4(),
                            org_id=ctx.org_id,
                            asset_id=asset_id,
                            scan_id=ctx.scan_id,
                            title=title,
                            cve_id=entry["cve_id"],
                            cvss_score=entry["cvss_score"],
                            cvss_vector=entry["cvss_vector"],
                            severity=severity,
                            description=entry["description"][:8000] or None,
                            remediation=_remediation_for(name, version, entry["cve_id"]),
                            source=STAGE,
                            fingerprint=Finding.build_fingerprint(
                                asset_id=asset_id, title=title, cve_id=entry["cve_id"]
                            ),
                            evidence={
                                "product": name,
                                "version": version,
                                "hostname": hostname,
                                "published": entry.get("published"),
                                "detection_confidence": tech.get("confidence"),
                            },
                            references=entry["references"],
                            first_seen=now,
                            last_seen=now,
                        )
                        .on_conflict_do_update(
                            index_elements=[Finding.org_id, Finding.fingerprint],
                            set_={
                                "last_seen": now,
                                "scan_id": ctx.scan_id,
                                "cvss_score": entry["cvss_score"],
                                "severity": severity,
                            },
                        )
                        # first_seen is only ever written by the INSERT branch —
                        # the ON CONFLICT set_ above leaves it alone — so a row
                        # coming back with first_seen == now is one this
                        # statement just created. That is cheaper and clearer
                        # than a separate existence check per finding.
                        .returning(Finding.id, Finding.first_seen)
                    )
                    row = session.execute(stmt).one()
                    asset_findings += 1

                    is_new = row.first_seen == now
                    if is_new:
                        new_finding_ids.append(str(row.id))

                    if severity in {Severity.CRITICAL, Severity.HIGH}:
                        ctx.log(
                            f"{hostname}: {entry['cve_id']} ({severity.value}, "
                            f"CVSS {entry['cvss_score']}) affects {name} {version}",
                            level="warning",
                        )
                        ctx.emit_result(
                            "finding",
                            {
                                "hostname": hostname,
                                "cve_id": entry["cve_id"],
                                "severity": severity.value,
                                "cvss_score": entry["cvss_score"],
                            },
                        )

                    if is_new and severity == Severity.CRITICAL:
                        new_critical.append(
                            {
                                "finding_id": str(row.id),
                                "title": title,
                                "hostname": hostname,
                                "cve_id": entry["cve_id"],
                                "cvss_score": entry["cvss_score"],
                                "severity": severity.value,
                            }
                        )

        if asset_findings:
            total_findings += asset_findings
            # Refresh the asset's risk score now that CVEs are attached.
            with session_scope() as session:
                asset = session.get(Asset, asset_id)
                if asset is not None:
                    severities = list(
                        session.scalars(
                            select(Finding.severity).where(
                                Finding.asset_id == asset_id, Finding.org_id == ctx.org_id
                            )
                        )
                    )
                    asset.risk_score = score_asset(
                        findings=severities, open_ports=asset.open_ports
                    )

    if total_findings:
        ctx.bump_counters(findings=total_findings)
    ctx.log(f"CVE correlation complete: {total_findings} vulnerability finding(s) recorded")

    # --- Hand off enrichment and alerting ---------------------------------
    #
    # Both are dispatched rather than called inline, and both are wrapped: this
    # stage's job is correlation, and neither a model API nor Slack being down
    # is a reason for the scan to fail after the findings are already durable.
    if new_finding_ids:
        try:
            enrich_payload = {**payload, "finding_ids": new_finding_ids}
            celery_app.send_task(
                "workers.ai_remediation.run", args=(enrich_payload,), queue="enrich"
            )
        except Exception:
            logger.exception("failed to dispatch AI remediation for scan %s", ctx.scan_id)
            ctx.warn("Could not queue AI remediation; findings keep the standard text")

    if new_critical:
        try:
            celery_app.send_task(
                "workers.notifier.notify_critical",
                kwargs={
                    "org_id": str(ctx.org_id),
                    "scan_id": str(ctx.scan_id),
                    "findings": new_critical,
                },
                queue="notify",
            )
        except Exception:
            logger.exception("failed to dispatch Slack alert for scan %s", ctx.scan_id)
            ctx.warn("Could not queue Slack notification for critical findings")

    return payload
