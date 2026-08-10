"""AI remediation — context-specific fix steps from the Claude API.

The template advice the correlator writes ("upgrade nginx beyond 1.24.0") is
true and useless: it is what the CVE record already says, and the engineer
reading it already knows. What they do not have is the intersection of the CVE
with *this* host — that the vulnerable service sits behind a reverse proxy that
can filter the request, that the exploit path needs a port this host does not
expose, that the version is from a distro that backports fixes so the version
string alone does not settle it.

So the prompt carries the asset's real facts (open ports, full tech stack,
hostname role) and the model is asked to reason about that specific
configuration. Design constraints:

* **Never invents a version.** The model is told to say when it cannot
  determine a fixed version rather than guess one, because a wrong version
  number in a remediation field is worse than no version — someone will act on
  it and believe they are patched.
* **Degrades to the template.** No key, no budget, API down, malformed
  response: the finding keeps the deterministic advice the correlator wrote.
  This is enrichment, never a dependency.
* **Cached on (CVE, product, version, stack shape).** The same CVE against the
  same stack yields the same advice, and one estate can carry the same finding
  on dozens of hosts.
* **Provenance recorded.** ``evidence.remediation_source`` says whether a human
  is reading generated text or the template, because pretending otherwise about
  security advice is not acceptable.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from config import settings

logger = logging.getLogger(__name__)

CACHE_PREFIX = "ai:remediation:"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# Source markers written to evidence.remediation_source.
SOURCE_AI = "claude"
SOURCE_TEMPLATE = "template"
SOURCE_CACHE = "claude-cached"
# Not written by this module — set by routes/findings.py when an analyst edits
# the text, so the record stops crediting a model for a human's words.
SOURCE_ANALYST = "analyst"


SYSTEM_PROMPT = """\
You are a vulnerability remediation engineer writing for another engineer who \
has to fix this specific host today. You are given one CVE and the real \
observed configuration of the affected asset.

Write remediation that could only have been written for this host. Ground every \
step in the facts provided — the exact version running, the ports actually \
open, the other technologies detected on the same host.

Rules you must follow:

1. NEVER invent a fixed version number, patch identifier, or advisory URL. If \
the provided facts do not establish which release fixes this CVE, say so \
plainly and tell the reader where to confirm it. A wrong version number here \
gets someone owned while they believe they are patched.
2. Distinguish what you know from what you are inferring. If the reasoning \
depends on an assumption (for example that the distro package backports fixes, \
or that a proxy terminates TLS), state the assumption.
3. Prefer the mitigation that is actually available on this host. If an open \
port makes the exploit path reachable, say which port. If nothing in the \
provided facts suggests the service is reachable, say that the exposure may be \
lower than the CVSS score implies and why.
4. No filler. No "it is important to keep software up to date". Every sentence \
must carry information specific to this finding.

Respond with a JSON object and nothing else:

{
  "summary": "One sentence: what an attacker gets from this, on this host.",
  "steps": ["Ordered, concrete actions. 2-5 of them."],
  "mitigation": "What to do right now if the fix cannot ship today, or null.",
  "exposure_note": "Why this host's configuration raises or lowers the real \
risk versus the base CVSS, or null.",
  "confidence": "high" | "medium" | "low",
  "uncertain": ["Anything you could not determine from the facts given. Empty \
list if nothing."]
}
"""


@dataclass(frozen=True)
class AssetContext:
    """The observed facts about one host, as passed to the model."""

    hostname: str
    ip: str | None
    open_ports: list[dict[str, Any]]
    tech_stack: list[dict[str, Any]]

    def fingerprint(self) -> str:
        """Cache identity for this *shape* of host.

        Hostname and IP are excluded deliberately: two web servers running the
        same stack behind the same ports get the same advice, and including the
        hostname would drop the hit rate to zero across an estate. Ports and
        technologies are what actually change the answer.
        """
        ports = sorted(
            f"{p.get('port')}/{p.get('service') or '?'}"
            for p in self.open_ports
            if p.get("port") is not None
        )
        tech = sorted(
            f"{t.get('name')}@{t.get('version') or '?'}"
            for t in self.tech_stack
            if t.get("name")
        )
        return hashlib.sha256("|".join([*ports, "~", *tech]).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class RemediationResult:
    text: str
    source: str
    model: str | None = None
    confidence: str | None = None
    uncertain: list[str] | None = None

    @property
    def is_ai(self) -> bool:
        return self.source in {SOURCE_AI, SOURCE_CACHE}


def cache_key(cve_id: str, product: str, version: str, asset: AssetContext) -> str:
    return f"{CACHE_PREFIX}{cve_id}:{product}:{version}:{asset.fingerprint()}"


def _describe_ports(ports: list[dict[str, Any]]) -> str:
    if not ports:
        return "None detected as open."
    lines = []
    for port in sorted(ports, key=lambda p: p.get("port") or 0):
        bits = [f"  - {port.get('port')}/{port.get('protocol', 'tcp')}"]
        if port.get("service"):
            bits.append(f"service={port['service']}")
        if port.get("banner"):
            bits.append(f"banner={str(port['banner'])[:120]!r}")
        lines.append(" ".join(bits))
    return "\n".join(lines)


def _describe_tech(tech: list[dict[str, Any]]) -> str:
    if not tech:
        return "  Nothing fingerprinted."
    lines = []
    for entry in tech:
        name = entry.get("name")
        if not name:
            continue
        version = entry.get("version") or "version unknown"
        confidence = entry.get("confidence")
        suffix = f" (detection confidence {confidence}%)" if confidence else ""
        lines.append(f"  - {name} {version}{suffix}")
    return "\n".join(lines) or "  Nothing fingerprinted."


def build_prompt(
    *,
    cve_id: str,
    cvss_score: float | None,
    cvss_vector: str | None,
    severity: str,
    description: str | None,
    product: str,
    version: str,
    asset: AssetContext,
) -> str:
    """Assemble the user message.

    Everything here is observed fact from our own scan. The CVE description is
    truncated because NVD occasionally carries multi-kilobyte prose and the
    tail of it never changes the remediation.
    """
    return f"""\
CVE: {cve_id}
CVSS base score: {cvss_score if cvss_score is not None else "not scored by NVD"}
CVSS vector: {cvss_vector or "not published"}
Severity band we assigned: {severity}

NVD description:
{(description or "No description published.")[:2000]}

AFFECTED COMPONENT ON THIS HOST
  {product} {version}

HOST
  hostname: {asset.hostname}
  ip: {asset.ip or "not resolved"}

OPEN PORTS OBSERVED BY OUR SCAN
{_describe_ports(asset.open_ports)}

FULL TECHNOLOGY STACK FINGERPRINTED ON THIS HOST
{_describe_tech(asset.tech_stack)}

Write the remediation for this host.
"""


def _render(payload: dict[str, Any]) -> str:
    """Turn the model's JSON into the markdown stored in findings.remediation.

    Rendered server-side rather than stored as JSON so that the reports
    (PDF/CSV/JSON) and the findings UI all get the same text without each
    having to know the response shape.
    """
    parts: list[str] = []

    summary = (payload.get("summary") or "").strip()
    if summary:
        parts.append(summary)

    steps = [str(s).strip() for s in (payload.get("steps") or []) if str(s).strip()]
    if steps:
        parts.append(
            "\n".join(f"{i}. {step}" for i, step in enumerate(steps, start=1))
        )

    mitigation = (payload.get("mitigation") or "").strip()
    if mitigation and mitigation.lower() not in {"null", "none"}:
        parts.append(f"**If you cannot patch today:** {mitigation}")

    exposure = (payload.get("exposure_note") or "").strip()
    if exposure and exposure.lower() not in {"null", "none"}:
        parts.append(f"**Exposure on this host:** {exposure}")

    uncertain = [str(u).strip() for u in (payload.get("uncertain") or []) if str(u).strip()]
    if uncertain:
        # Surfaced, not hidden. An analyst needs to know which parts of this
        # were not determinable from the scan data before acting on them.
        parts.append(
            "**Not determined from scan data:**\n"
            + "\n".join(f"- {item}" for item in uncertain)
        )

    return "\n\n".join(parts).strip()


def _parse_response(raw: str) -> dict[str, Any] | None:
    """Extract the JSON object from the model's reply.

    Tolerates a fenced code block and surrounding prose, because a strict
    json.loads on the whole string would discard an otherwise good answer over
    a stray "Here is the remediation:" preamble.
    """
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text[3:]
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def call_claude(prompt: str, *, client: httpx.Client | None = None) -> dict[str, Any] | None:
    """One Messages API call. Returns the parsed object, or None on any failure.

    Every error path returns None rather than raising: the caller's contract is
    that a failure here leaves the template remediation in place, and a scan
    must never fail because an enrichment call did.
    """
    headers = {
        "x-api-key": settings.ai_remediation_api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    body = {
        "model": settings.ai_remediation_model,
        "max_tokens": settings.ai_remediation_max_tokens,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }

    owns_client = client is None
    client = client or httpx.Client(timeout=settings.ai_remediation_timeout)
    try:
        response = client.post(ANTHROPIC_API_URL, headers=headers, json=body)
    except httpx.HTTPError as exc:
        logger.warning("Claude API request failed: %s", exc)
        return None
    finally:
        if owns_client:
            client.close()

    if response.status_code == 401:
        logger.error("Claude API rejected the key; AI remediation is disabled for this run")
        return None
    if response.status_code == 429:
        logger.warning("Claude API rate limited; falling back to template remediation")
        return None
    if response.status_code >= 400:
        logger.warning("Claude API returned HTTP %s", response.status_code)
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    # Messages API returns content as a list of typed blocks.
    chunks = [
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ]
    if not chunks:
        return None

    return _parse_response("".join(chunks))


def generate(
    *,
    cve_id: str,
    cvss_score: float | None,
    cvss_vector: str | None,
    severity: str,
    description: str | None,
    product: str,
    version: str,
    asset: AssetContext,
    fallback: str,
    redis_client: Any | None = None,
    http_client: httpx.Client | None = None,
) -> RemediationResult:
    """Produce remediation for one finding, falling back to ``fallback``.

    This never raises. The worst case is that it returns the template text with
    ``source=template``.
    """
    if not settings.ai_remediation_active:
        return RemediationResult(text=fallback, source=SOURCE_TEMPLATE)

    key = cache_key(cve_id, product, version, asset)

    if redis_client is not None:
        try:
            cached = redis_client.get(key)
        except Exception:  # redis is optional here, never fatal
            cached = None
        if cached:
            try:
                stored = json.loads(cached)
                return RemediationResult(
                    text=stored["text"],
                    source=SOURCE_CACHE,
                    model=stored.get("model"),
                    confidence=stored.get("confidence"),
                    uncertain=stored.get("uncertain"),
                )
            except (json.JSONDecodeError, KeyError, TypeError):
                pass  # poisoned entry; regenerate

    prompt = build_prompt(
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        description=description,
        product=product,
        version=version,
        asset=asset,
    )

    payload = call_claude(prompt, client=http_client)
    if payload is None:
        return RemediationResult(text=fallback, source=SOURCE_TEMPLATE)

    text = _render(payload)
    if not text:
        # Well-formed JSON with nothing usable in it. The template is better
        # than an empty remediation field.
        return RemediationResult(text=fallback, source=SOURCE_TEMPLATE)

    result = RemediationResult(
        text=text,
        source=SOURCE_AI,
        model=settings.ai_remediation_model,
        confidence=payload.get("confidence"),
        uncertain=[str(u) for u in (payload.get("uncertain") or [])],
    )

    if redis_client is not None:
        try:
            redis_client.setex(
                key,
                settings.ai_remediation_cache_ttl_seconds,
                json.dumps(
                    {
                        "text": result.text,
                        "model": result.model,
                        "confidence": result.confidence,
                        "uncertain": result.uncertain,
                    }
                ),
            )
        except Exception:
            pass

    return result


__all__ = [
    "AssetContext",
    "RemediationResult",
    "SOURCE_AI",
    "SOURCE_ANALYST",
    "SOURCE_CACHE",
    "SOURCE_TEMPLATE",
    "build_prompt",
    "cache_key",
    "call_claude",
    "generate",
]
