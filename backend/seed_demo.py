"""Seed a demo organisation with realistic data for local click-through testing.

The console is mostly aggregates — risk scores, severity breakdowns, blast-radius
graphs — and all of them render as zero against an empty database, which tells
you nothing about whether they work. This creates one organisation with enough
assets and findings to exercise the dashboard, filters, sorting and the graph.

Idempotent: re-running it does nothing if the demo org already exists.

    python seed_demo.py            # create
    python seed_demo.py --reset    # delete and recreate

Every hostname is under .example (RFC 2606) and every IP is in 203.0.113.0/24
(RFC 5737), both reserved and unregistrable — the same rule the marketing page
follows. Demo data naming real infrastructure would be advertising unpatched
criticals against somebody's actual hosts.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from core.security import hash_password
from db.database import AsyncSessionLocal
from models import (
    Asset,
    AssetStatus,
    Finding,
    FindingStatus,
    Organisation,
    Severity,
    User,
    UserRole,
)

DOMAIN = "democorp.example"
EMAIL = f"demo@{DOMAIN}"
PASSWORD = "demo-password-2026"  # 12+ chars with a digit, per the password policy

# (hostname, ip, risk, open ports, tech stack, age in days, status)
ASSETS = [
    ("www", "203.0.113.10", 34.0, [80, 443], [("nginx", "1.24.0")], 90, AssetStatus.ACTIVE),
    ("api", "203.0.113.15", 78.5, [22, 80, 443], [("nginx", "1.24.0"), ("OpenSSH", "9.6p1")], 90, AssetStatus.ACTIVE),
    ("vpn", "203.0.113.22", 94.0, [443, 4443], [("Citrix NetScaler", "13.1-48.47")], 60, AssetStatus.ACTIVE),
    ("mail", "203.0.113.8", 41.0, [25, 465, 587, 993], [("Postfix", "3.7.2"), ("Dovecot", "2.3.20")], 120, AssetStatus.ACTIVE),
    ("staging", "203.0.113.50", 82.0, [80, 443, 3000, 5432], [("Node.js", "18.16.0"), ("PostgreSQL", "15.3")], 14, AssetStatus.CHANGED),
    ("app", "203.0.113.101", 88.0, [443, 8080], [("Apache Tomcat", "9.0.75"), ("Spring Boot", "2.6.3")], 45, AssetStatus.ACTIVE),
    ("legacy", "203.0.113.77", 12.0, [80], [("Apache httpd", "2.4.57")], 200, AssetStatus.INACTIVE),
    ("cdn", "203.0.113.200", 8.0, [443], [("Cloudflare", None)], 30, AssetStatus.NEW),
]

# (asset index, title, cve, cvss, severity, status, description, remediation)
# The CVEs are real and the scores are the published CVSS v3.1 base scores.
FINDINGS = [
    (2, "Citrix NetScaler session token disclosure (CitrixBleed)", "CVE-2023-4966", 9.4,
     Severity.CRITICAL, FindingStatus.CONFIRMED,
     "The appliance leaks session tokens from uninitialised memory, allowing an "
     "unauthenticated attacker to hijack an authenticated session and bypass MFA.",
     "Upgrade to 13.1-49.15 or later, then terminate all active sessions — patching "
     "alone does not invalidate tokens already stolen."),
    (5, "Spring Framework RCE via data binding (Spring4Shell)", "CVE-2022-22965", 9.8,
     Severity.CRITICAL, FindingStatus.OPEN,
     "Spring Boot 2.6.3 on JDK 9+ permits remote code execution through crafted "
     "request parameters that reach the class loader via data binding.",
     "Upgrade Spring Framework to 5.3.18 / 5.2.20 or later."),
    (1, "OpenSSH signal handler race condition (regreSSHion)", "CVE-2024-6387", 8.1,
     Severity.HIGH, FindingStatus.TRIAGED,
     "A race in the SIGALRM handler allows unauthenticated remote code execution as "
     "root on glibc-based systems. Exploitation is slow but repeatable.",
     "Upgrade to OpenSSH 9.8p1, or set LoginGraceTime=0 as an interim mitigation."),
    (4, "PostgreSQL reachable from the public internet", None, 7.5,
     Severity.HIGH, FindingStatus.OPEN,
     "Port 5432 is open to 0.0.0.0/0 on a staging host. A database port on a public "
     "interface is exposed to credential stuffing and any unauthenticated CVE.",
     "Bind PostgreSQL to localhost or a private subnet and place it behind the VPN."),
    (5, "HTTP/2 rapid reset denial of service", "CVE-2023-44487", 7.5,
     Severity.HIGH, FindingStatus.OPEN,
     "The HTTP/2 implementation permits rapid stream creation and cancellation, "
     "letting a single connection exhaust server resources.",
     "Upgrade Tomcat and enable per-connection stream limits."),
    (1, "TLS 1.0 and 1.1 still enabled", None, 5.3,
     Severity.MEDIUM, FindingStatus.OPEN,
     "The endpoint negotiates deprecated protocol versions with known weaknesses.",
     "Restrict the server to TLS 1.2 and 1.3."),
    (4, "Development server exposed on port 3000", None, 5.0,
     Severity.MEDIUM, FindingStatus.TRIAGED,
     "A Node development server is reachable externally. These ship verbose errors "
     "and source maps, and are not hardened for public exposure.",
     "Firewall the port or serve a production build behind the reverse proxy."),
    (3, "SMTP server allows legacy STARTTLS downgrade", None, 4.3,
     Severity.MEDIUM, FindingStatus.OPEN,
     "The mail server accepts a plaintext fallback when STARTTLS negotiation fails.",
     "Require TLS for all submission traffic on 587."),
    (6, "Apache version disclosed in Server header", None, 2.6,
     Severity.LOW, FindingStatus.ACCEPTED_RISK,
     "The Server header reveals the exact version, helping an attacker select exploits.",
     "Set ServerTokens Prod."),
    (0, "Missing HTTP Strict-Transport-Security header", None, 3.1,
     Severity.LOW, FindingStatus.REMEDIATED,
     "Without HSTS a first request over HTTP can be intercepted before redirect.",
     "Add Strict-Transport-Security with a max-age of at least six months."),
    (7, "Certificate expires in 21 days", None, 0.0,
     Severity.INFO, FindingStatus.OPEN,
     "The TLS certificate is approaching expiry. An expired certificate is a "
     "full outage for every browser client.",
     "Renew and confirm automated renewal is actually running."),
]


async def seed(reset: bool = False) -> int:
    async with AsyncSessionLocal() as db:
        existing = await db.scalar(select(Organisation).where(Organisation.domain == DOMAIN))
        if existing is not None:
            if not reset:
                print(f"Demo organisation already exists ({DOMAIN}).")
                print(f"  Log in at http://localhost:3000/login  —  {EMAIL} / {PASSWORD}")
                print("  Re-run with --reset to rebuild it from scratch.")
                return 0
            # Assets, findings and users all cascade from the organisation.
            await db.execute(delete(Organisation).where(Organisation.id == existing.id))
            await db.commit()
            print("Removed the previous demo organisation.")

        now = datetime.now(timezone.utc)

        org = Organisation(
            name="DemoCorp",
            domain=DOMAIN,
            # Both are verified, so scans against either pass the scope gate.
            verified_domains=[DOMAIN, f"internal.{DOMAIN}"],
        )
        db.add(org)
        await db.flush()

        db.add(
            User(
                org_id=org.id,
                email=EMAIL,
                password_hash=hash_password(PASSWORD),
                full_name="Demo Owner",
                role=UserRole.OWNER,
            )
        )
        # A second account for checking that the role gate actually bites: this
        # one cannot create assets, queue scans, or invite anybody.
        db.add(
            User(
                org_id=org.id,
                email=f"viewer@{DOMAIN}",
                password_hash=hash_password(PASSWORD),
                full_name="Demo Viewer",
                role=UserRole.VIEWER,
            )
        )

        assets: list[Asset] = []
        for label, ip, risk, ports, tech, age_days, status in ASSETS:
            asset = Asset(
                org_id=org.id,
                hostname=f"{label}.{DOMAIN}",
                ip=ip,
                risk_score=risk,
                ports=[{"port": p, "state": "open", "service": None} for p in ports],
                tech_stack=[
                    {"name": name, "version": version} for name, version in tech
                ],
                status=status,
                discovery_source="seed",
                first_seen=now - timedelta(days=age_days),
                # Staggered so "last scanned" sorting shows a real ordering
                # rather than eight identical timestamps.
                last_scanned=now - timedelta(hours=len(assets) * 3),
            )
            db.add(asset)
            assets.append(asset)

        await db.flush()

        for idx, title, cve, cvss, severity, status, description, remediation in FINDINGS:
            asset = assets[idx]
            db.add(
                Finding(
                    org_id=org.id,
                    asset_id=asset.id,
                    title=title,
                    cve_id=cve,
                    cvss_score=cvss,
                    severity=severity,
                    status=status,
                    description=description,
                    remediation=remediation,
                    source="seed",
                    # The model's own helper, not a hand-rolled hash: a repeat
                    # scan finding the same issue must land on the same row.
                    fingerprint=Finding.build_fingerprint(
                        asset_id=asset.id, title=title, cve_id=cve
                    ),
                    first_seen=now - timedelta(days=3),
                    last_seen=now,
                    resolved_at=now if status == FindingStatus.REMEDIATED else None,
                )
            )

        await db.commit()

    print("\n  Demo organisation created.\n")
    print(f"    URL:      http://localhost:3000/login")
    print(f"    Email:    {EMAIL}")
    print(f"    Password: {PASSWORD}")
    print(f"\n    Also seeded: viewer@{DOMAIN} (same password, read-only role)")
    print(f"    {len(ASSETS)} assets, {len(FINDINGS)} findings across every severity.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(seed(reset="--reset" in sys.argv)))
