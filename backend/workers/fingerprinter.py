"""Technology fingerprinting.

For every open HTTP(S) port: fetch the root document, then identify the stack
from response headers, cookies, HTML markers and well-known paths. Also checks
TLS certificate expiry and the usual security-header hygiene, both of which
produce findings on their own.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

import httpx
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config import settings
from core.scoring import UnsafeAddressError, resolve_public_addresses
from db.database import session_scope
from models import Asset, Finding, Severity
from workers.context import ScanContext, run_async
from workers.safe_http import safe_async_client

STAGE = "fingerprinter"

_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000}
_HTTPS_PORTS = {443, 8443, 9443, 4443, 8834, 10443}

# name -> (category, header regexes, body regexes, cookie names)
_SIGNATURES: dict[str, dict[str, Any]] = {
    "nginx": {"category": "web-server", "server": r"nginx(?:/([\d.]+))?"},
    "apache": {"category": "web-server", "server": r"apache(?:/([\d.]+))?"},
    "iis": {"category": "web-server", "server": r"microsoft-iis(?:/([\d.]+))?"},
    "litespeed": {"category": "web-server", "server": r"litespeed(?:/([\d.]+))?"},
    "caddy": {"category": "web-server", "server": r"caddy(?:/([\d.]+))?"},
    "tomcat": {"category": "app-server", "server": r"tomcat(?:/([\d.]+))?"},
    "jetty": {"category": "app-server", "server": r"jetty\(?([\d.]+)?\)?"},
    "gunicorn": {"category": "app-server", "server": r"gunicorn(?:/([\d.]+))?"},
    "uvicorn": {"category": "app-server", "server": r"uvicorn(?:/([\d.]+))?"},
    "express": {"category": "framework", "powered_by": r"express(?:/([\d.]+))?"},
    "php": {"category": "language", "powered_by": r"php(?:/([\d.]+))?"},
    "asp.net": {"category": "framework", "powered_by": r"asp\.net(?:/([\d.]+))?"},
    "django": {"category": "framework", "cookies": ("csrftoken", "django_language")},
    "rails": {"category": "framework", "cookies": ("_rails_session",), "powered_by": r"phusion"},
    "laravel": {"category": "framework", "cookies": ("laravel_session", "xsrf-token")},
    "wordpress": {
        "category": "cms",
        "body": r"wp-content|wp-includes|/wp-json/",
        "generator": r"wordpress\s*([\d.]+)?",
    },
    "drupal": {"category": "cms", "body": r"drupal\.settings|/sites/default/files", "generator": r"drupal\s*([\d.]+)?"},
    "joomla": {"category": "cms", "generator": r"joomla!?\s*([\d.]+)?"},
    "magento": {"category": "ecommerce", "body": r"mage/|magento", "cookies": ("frontend",)},
    "shopify": {"category": "ecommerce", "body": r"cdn\.shopify\.com"},
    "react": {"category": "js-framework", "body": r"__REACT_DEVTOOLS|data-reactroot|react(?:-dom)?[.-]"},
    "vue": {"category": "js-framework", "body": r"__VUE__|data-v-[0-9a-f]{8}"},
    "angular": {"category": "js-framework", "body": r"ng-version=|angular(?:\.min)?\.js"},
    "next.js": {"category": "js-framework", "body": r"__NEXT_DATA__|/_next/static"},
    "nuxt": {"category": "js-framework", "body": r"__NUXT__|/_nuxt/"},
    "jquery": {"category": "js-library", "body": r"jquery[.-]([\d.]+)?(?:\.min)?\.js"},
    "bootstrap": {"category": "css-framework", "body": r"bootstrap[.-]([\d.]+)?(?:\.min)?\.(?:css|js)"},
    "cloudflare": {"category": "cdn", "server": r"cloudflare"},
    "akamai": {"category": "cdn", "server": r"akamai"},
    "fastly": {"category": "cdn", "headers": ("x-served-by", "x-fastly-request-id")},
    "varnish": {"category": "cache", "headers": ("x-varnish",)},
    "kubernetes-ingress": {"category": "infrastructure", "headers": ("x-kubernetes-ingress",)},
    "grafana": {"category": "monitoring", "body": r"grafana[_-]?bootdata|grafana\.app"},
    "kibana": {"category": "monitoring", "body": r"kbn-name|kibana"},
    "jenkins": {"category": "ci", "headers": ("x-jenkins",)},
    "gitlab": {"category": "devops", "body": r"gitlab|gon\.gitlab"},
    "sentry": {"category": "monitoring", "body": r"sentry[_-]?dsn"},
    "swagger": {"category": "api-docs", "body": r"swagger-ui|openapi\.json"},
    "phpmyadmin": {"category": "admin-panel", "body": r"phpmyadmin"},
}

# Security headers whose absence is worth reporting, with why it matters.
_SECURITY_HEADERS: dict[str, tuple[str, Severity, str]] = {
    "strict-transport-security": (
        "HSTS not enforced",
        Severity.MEDIUM,
        "Without Strict-Transport-Security a first request over plain HTTP can be "
        "intercepted and downgraded. Send "
        "'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "content-security-policy": (
        "No Content-Security-Policy",
        Severity.LOW,
        "A CSP is the main defence-in-depth control against XSS. Start in "
        "report-only mode, then enforce a policy without 'unsafe-inline'.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options",
        Severity.LOW,
        "Send 'X-Content-Type-Options: nosniff' so browsers do not MIME-sniff "
        "responses into executable types.",
    ),
    "x-frame-options": (
        "Clickjacking protection missing",
        Severity.LOW,
        "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        "No Referrer-Policy",
        Severity.INFO,
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' to avoid leaking "
        "full URLs to third parties.",
    ),
}

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _match_version(pattern: str, value: str) -> tuple[bool, str | None]:
    match = re.search(pattern, value, re.I)
    if not match:
        return False, None
    version = match.group(1) if match.groups() else None
    return True, version


def _identify(
    headers: dict[str, str], body: str, cookies: Iterable[str]
) -> list[dict[str, Any]]:
    """Run every signature against one response."""
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    generator_match = _GENERATOR_RE.search(body)
    generator = generator_match.group(1) if generator_match else ""
    cookie_names = {c.lower() for c in cookies}
    detected: list[dict[str, Any]] = []

    for name, sig in _SIGNATURES.items():
        version: str | None = None
        confidence = 0

        if "server" in sig:
            hit, version = _match_version(sig["server"], server)
            if hit:
                confidence = max(confidence, 95 if version else 85)
        if "powered_by" in sig and confidence < 95:
            hit, ver = _match_version(sig["powered_by"], powered_by)
            if hit:
                version = version or ver
                confidence = max(confidence, 90 if ver else 80)
        if "generator" in sig and confidence < 95:
            hit, ver = _match_version(sig["generator"], generator)
            if hit:
                version = version or ver
                confidence = max(confidence, 95 if ver else 85)
        if "headers" in sig and confidence < 80:
            if any(h in headers for h in sig["headers"]):
                confidence = max(confidence, 80)
        if "cookies" in sig and confidence < 80:
            if any(c in cookie_names for c in sig["cookies"]):
                confidence = max(confidence, 75)
        if "body" in sig and confidence < 70:
            hit, ver = _match_version(sig["body"], body)
            if hit:
                version = version or ver
                # Body markers are the weakest signal — a CDN reference is not
                # proof the app is built on that framework.
                confidence = max(confidence, 60)

        if confidence:
            entry: dict[str, Any] = {
                "name": name,
                "version": version,
                "categories": [sig["category"]],
                "confidence": confidence,
            }
            if version:
                # CPE lets the CVE correlator query NVD precisely.
                entry["cpe"] = f"cpe:2.3:a:{name}:{name}:{version}:*:*:*:*:*:*:*"
            detected.append(entry)

    return sorted(detected, key=lambda d: -d["confidence"])


def _check_tls(hostname: str, port: int) -> dict[str, Any] | None:
    """Read the certificate and report expiry/hostname problems.

    Resolves and validates before connecting, then connects to that literal
    address while still sending ``hostname`` as SNI — so the handshake is
    against the certificate we care about, but the packets can only go to an
    address we already confirmed is public.
    """
    context = ssl.create_default_context()
    # We want to inspect a bad certificate, not fail closed on it.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        addresses = resolve_public_addresses(hostname, port=port)
    except UnsafeAddressError:
        return None
    address = next(
        (a for a in addresses if ipaddress.ip_address(a).version == 4), addresses[0]
    )
    try:
        with socket.create_connection((address, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                info = {
                    "version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                }
    except (OSError, ssl.SSLError, socket.timeout):
        return None

    if not cert:
        return info

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            info["not_after"] = expiry.isoformat()
            info["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    subject = {k: v for entry in cert.get("subject", ()) for k, v in entry}
    issuer = {k: v for entry in cert.get("issuer", ()) for k, v in entry}
    info["subject_cn"] = subject.get("commonName")
    info["issuer_cn"] = issuer.get("commonName")
    info["san"] = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
    return info


async def _probe_url(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    try:
        response = await client.get(url)
    except httpx.HTTPError:
        return None

    body = response.text[:200_000]  # cap: some pages are enormous
    headers = {k.lower(): v for k, v in response.headers.items()}
    title_match = _TITLE_RE.search(body)
    return {
        "url": url,
        "status": response.status_code,
        "headers": headers,
        "body": body,
        "title": (title_match.group(1).strip()[:200] if title_match else None),
        "cookies": list(response.cookies.keys()),
    }


async def _fingerprint_host(
    ctx: ScanContext, hostname: str, ports: list[dict[str, Any]]
) -> dict[str, Any]:
    """Probe every HTTP-ish port on one host."""
    open_ports = {p["port"] for p in ports if p.get("state") == "open"} or {80, 443}
    targets: list[tuple[str, int]] = []
    for port in sorted(open_ports):
        if port in _HTTPS_PORTS:
            targets.append(("https", port))
        elif port in _HTTP_PORTS:
            targets.append(("http", port))

    if not targets:
        return {"technologies": [], "http": [], "tls": None}

    technologies: dict[str, dict[str, Any]] = {}
    http_results: list[dict[str, Any]] = []

    # safe_async_client, not httpx.AsyncClient: follow_redirects below is only
    # safe because every hop is resolved and pinned to a public address first.
    # An in-scope host answering "302 -> http://169.254.169.254/" gets refused
    # instead of fetched.
    async with safe_async_client(
        timeout=httpx.Timeout(10.0),
        follow_redirects=True,
        max_redirects=5,
        verify=False,  # we inspect broken TLS rather than refusing to look
        headers={"User-Agent": settings.http_user_agent},
        limits=httpx.Limits(max_connections=20),
    ) as client:
        for scheme, port in targets:
            default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            url = f"{scheme}://{hostname}" + ("" if default_port else f":{port}")
            try:
                result = await _probe_url(client, url)
            except UnsafeAddressError as exc:
                # Either the host resolves into reserved space, or it redirected
                # us there. Both are refusals worth recording, not silent skips.
                ctx.warn(f"Refusing {url}: {exc}")
                continue
            if result is None:
                continue

            detected = _identify(result["headers"], result["body"], result["cookies"])
            for tech in detected:
                existing = technologies.get(tech["name"])
                if existing is None or tech["confidence"] > existing["confidence"]:
                    technologies[tech["name"]] = tech

            http_results.append(
                {
                    "url": result["url"],
                    "status": result["status"],
                    "title": result["title"],
                    "server": result["headers"].get("server"),
                    "headers": result["headers"],
                    "technologies": [t["name"] for t in detected],
                }
            )

    tls_info = None
    https_ports = [p for _, p in targets if p in _HTTPS_PORTS]
    if https_ports:
        tls_info = await asyncio.to_thread(_check_tls, hostname, https_ports[0])

    return {
        "technologies": list(technologies.values()),
        "http": http_results,
        "tls": tls_info,
    }


def _record_findings(
    ctx: ScanContext,
    asset_id: uuid.UUID,
    hostname: str,
    http_results: list[dict[str, Any]],
    tls: dict[str, Any] | None,
) -> int:
    """Raise header-hygiene and certificate findings."""
    now = datetime.now(timezone.utc)
    count = 0

    with session_scope() as session:

        def upsert(
            title: str, severity: Severity, description: str, remediation: str,
            evidence: dict[str, Any], port: int | None = None,
        ) -> None:
            nonlocal count
            stmt = (
                pg_insert(Finding)
                .values(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    asset_id=asset_id,
                    scan_id=ctx.scan_id,
                    title=title,
                    severity=severity,
                    description=description,
                    remediation=remediation,
                    source=STAGE,
                    fingerprint=Finding.build_fingerprint(
                        asset_id=asset_id, title=title, port=port
                    ),
                    evidence=evidence,
                    first_seen=now,
                    last_seen=now,
                )
                .on_conflict_do_update(
                    index_elements=[Finding.org_id, Finding.fingerprint],
                    set_={"last_seen": now, "scan_id": ctx.scan_id},
                )
            )
            session.execute(stmt)
            count += 1

        for result in http_results:
            headers = result["headers"]
            # Only judge header hygiene on responses that actually rendered a page.
            if not (200 <= result["status"] < 400):
                continue

            if result["url"].startswith("https://"):
                for header, (title, severity, remediation) in _SECURITY_HEADERS.items():
                    if header not in headers:
                        upsert(
                            f"{title} on {hostname}",
                            severity,
                            f"{result['url']} responded without the '{header}' header.",
                            remediation,
                            {"url": result["url"], "missing_header": header},
                        )

            server = headers.get("server", "")
            # A version in the Server banner tells an attacker exactly which
            # exploits to try — low severity alone, but it feeds CVE matching.
            if re.search(r"\d+\.\d+", server):
                upsert(
                    f"Server version disclosed by {hostname}",
                    Severity.INFO,
                    f"{result['url']} advertises '{server}' in its Server header.",
                    "Suppress version details (nginx: server_tokens off; "
                    "Apache: ServerTokens Prod).",
                    {"url": result["url"], "server": server},
                )

        if tls and tls.get("days_until_expiry") is not None:
            days = tls["days_until_expiry"]
            if days < 0:
                upsert(
                    f"TLS certificate expired for {hostname}",
                    Severity.HIGH,
                    f"The certificate expired {abs(days)} day(s) ago "
                    f"(notAfter {tls.get('not_after')}). Browsers will block the site.",
                    "Renew the certificate and automate renewal (e.g. ACME/certbot).",
                    tls,
                )
            elif days < 30:
                upsert(
                    f"TLS certificate expiring soon for {hostname}",
                    Severity.LOW,
                    f"The certificate expires in {days} day(s) "
                    f"(notAfter {tls.get('not_after')}).",
                    "Renew ahead of expiry and set up automated renewal with alerting.",
                    tls,
                )

        if tls and tls.get("version") in {"TLSv1", "TLSv1.1", "SSLv3"}:
            upsert(
                f"Obsolete TLS version accepted by {hostname}",
                Severity.MEDIUM,
                f"The endpoint negotiated {tls['version']}, which is deprecated and "
                "vulnerable to known downgrade and padding-oracle attacks.",
                "Disable TLS 1.1 and below; require TLS 1.2 with modern ciphers, "
                "preferably TLS 1.3.",
                tls,
            )

    return count


@shared_task(
    name="workers.fingerprinter.run",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
    soft_time_limit=1_800,
)
def run(self, payload: dict[str, Any]) -> dict[str, Any]:
    ctx = ScanContext.load(
        scan_id=payload["scan_id"],
        org_id=payload["org_id"],
        target=payload["target"],
        config=payload.get("config") or {},
    ).for_stage(STAGE)

    ctx.set_stage(STAGE, progress=60)

    if ctx.passive_only:
        ctx.log("Passive mode: skipping HTTP fingerprinting")
        return payload

    hosts: list[str] = payload.get("hosts") or [ctx.target]
    port_results: dict[str, list[dict[str, Any]]] = payload.get("port_results") or {}

    ctx.log(f"Fingerprinting {len(hosts)} host(s)")
    fingerprinted = 0
    findings_total = 0

    for host in hosts:
        if ctx.is_cancelled():
            ctx.log("Scan cancelled; stopping fingerprinting")
            break

        ports = port_results.get(host) or []
        result = run_async(_fingerprint_host(ctx, host, ports))
        technologies = result["technologies"]

        if not result["http"]:
            ctx.debug(f"{host}: no HTTP service responded")
            continue

        fingerprinted += 1
        if technologies:
            names = ", ".join(
                f"{t['name']}{'/' + t['version'] if t['version'] else ''}"
                for t in technologies[:8]
            )
            ctx.log(f"{host}: {names}")
            ctx.emit_result("technologies", {"hostname": host, "technologies": technologies})
        else:
            ctx.debug(f"{host}: responded but no known technology signatures matched")

        now = datetime.now(timezone.utc)
        with session_scope() as session:
            asset = session.scalar(
                select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname == host)
            )
            if asset is None:
                continue
            asset.tech_stack = technologies
            asset.last_scanned = now
            asset_id = asset.id

        findings_total += _record_findings(ctx, asset_id, host, result["http"], result["tls"])

    if findings_total:
        ctx.bump_counters(findings=findings_total)
    ctx.log(
        f"Fingerprinting complete: {fingerprinted} host(s) profiled, "
        f"{findings_total} configuration finding(s)"
    )
    return payload
