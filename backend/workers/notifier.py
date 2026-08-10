"""Slack incoming-webhook alerts for critical findings.

Fired by the CVE correlator for findings it *created*, not for every finding it
re-confirms. A nightly scan re-detects yesterday's CVEs; paging the channel
again each night is how a security alert channel becomes one nobody reads.

The webhook URL is per-organisation and is a bearer credential — anyone holding
it can post into that channel — so it is never logged, never returned by the
API in full, and validated to be a real Slack hooks URL before we will store or
call it.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
from celery import shared_task

from config import settings
from db.database import session_scope
from models import Organisation

logger = logging.getLogger(__name__)

# Slack posts incoming webhooks only under this host. Restricting to it is what
# stops a stored webhook from becoming a server-side request forgery primitive:
# without this check an org admin could point the field at
# http://169.254.169.254/ and have the worker fetch cloud instance credentials
# for them.
_SLACK_HOST = "hooks.slack.com"

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Slack renders the bar to the left of an attachment in this colour. Muted
# rather than pure red — the same reasoning as the severity badges in the UI.
_SEVERITY_COLOUR = {
    "critical": "#c1443c",
    "high": "#c4703a",
    "medium": "#b08a2e",
    "low": "#3f7f6b",
    "info": "#6b6b78",
}


class InvalidWebhookURL(ValueError):
    """Raised when a URL is not a usable Slack incoming webhook."""


def validate_webhook_url(url: str) -> str:
    """Return the normalised URL, or raise ``InvalidWebhookURL``.

    Called both by the API before storing a URL and by the worker before using
    one, so a row written before this check existed still cannot be used to
    reach an internal address.
    """
    candidate = (url or "").strip()
    if not candidate:
        raise InvalidWebhookURL("Webhook URL is empty")

    parsed = urlparse(candidate)
    if parsed.scheme != "https":
        raise InvalidWebhookURL("Webhook URL must use https")
    if parsed.hostname != _SLACK_HOST:
        raise InvalidWebhookURL(f"Webhook URL must be on {_SLACK_HOST}")
    if not parsed.path.startswith("/services/"):
        raise InvalidWebhookURL("Not an incoming-webhook URL (expected /services/...)")
    if len(candidate) > 512:
        raise InvalidWebhookURL("Webhook URL is too long")
    return candidate


def redact(url: str | None) -> str | None:
    """A hint that identifies which webhook is configured without leaking it.

    Slack webhook paths look like /services/T00000000/B00000000/<24-char secret>.
    The team and channel segments are safe to show and are what an admin needs
    to recognise the integration; the last segment is the secret.
    """
    if not url:
        return None
    parts = urlparse(url).path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "services":
        return f"hooks.slack.com/services/{parts[1]}/{parts[2]}/{'•' * 8}"
    return "hooks.slack.com/services/…"


def _meets_threshold(severity: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(
            settings.slack_min_severity
        )
    except ValueError:
        return False


def build_blocks(
    *, findings: list[dict[str, Any]], org_name: str, scan_id: str | None
) -> dict[str, Any]:
    """Compose the Block Kit payload.

    One message per batch rather than one per finding: a scan that turns up
    twelve criticals should produce one notification a human can read, not
    twelve that push each other out of view.
    """
    count = len(findings)
    heading = (
        f"{count} new critical finding{'s' if count != 1 else ''} — {org_name}"
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔴 " + heading, "emoji": True},
        }
    ]

    # Slack hard-caps a message at 50 blocks and silently drops the rest, so
    # cap ourselves and say what was left out rather than losing it invisibly.
    shown = findings[:10]
    for finding in shown:
        cvss = finding.get("cvss_score")
        fields = [
            {"type": "mrkdwn", "text": f"*Asset*\n`{finding.get('hostname', 'unknown')}`"},
            {"type": "mrkdwn", "text": f"*CVE*\n`{finding.get('cve_id', 'n/a')}`"},
            {
                "type": "mrkdwn",
                "text": f"*CVSS*\n{cvss if cvss is not None else 'not scored'}",
            },
            {
                "type": "mrkdwn",
                "text": f"*Severity*\n{str(finding.get('severity', 'critical')).upper()}",
            },
        ]
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{finding.get('title', 'Untitled')}*"},
                "fields": fields,
            }
        )
        blocks.append({"type": "divider"})

    if count > len(shown):
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_…and {count - len(shown)} more. "
                        f"Open SurfaceWatch to see the full list._",
                    }
                ],
            }
        )

    if scan_id:
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Scan `{scan_id}`"}],
            }
        )

    return {
        # text is the notification/fallback string — what shows in the sidebar
        # and on a phone. Without it Slack pushes a blank notification.
        "text": heading,
        "blocks": blocks,
        "attachments": [
            {"color": _SEVERITY_COLOUR["critical"], "blocks": []}
        ],
    }


def post(url: str, payload: dict[str, Any], *, client: httpx.Client | None = None) -> bool:
    """POST to Slack. Returns True on success; never raises, never logs the URL."""
    try:
        validate_webhook_url(url)
    except InvalidWebhookURL as exc:
        logger.warning("Refusing to call stored webhook: %s", exc)
        return False

    owns = client is None
    client = client or httpx.Client(timeout=settings.slack_timeout_seconds)
    try:
        response = client.post(url, json=payload)
    except httpx.HTTPError as exc:
        # str(exc) on an httpx error includes the URL, which is the secret.
        logger.warning("Slack webhook request failed: %s", type(exc).__name__)
        return False
    finally:
        if owns:
            client.close()

    if response.status_code == 404:
        logger.warning("Slack webhook returned 404 — it was probably revoked in Slack")
        return False
    if response.status_code >= 400:
        # Slack puts the reason in the body ("invalid_payload", "channel_not_found")
        # and the body never contains the URL.
        logger.warning(
            "Slack webhook returned HTTP %s: %s",
            response.status_code,
            response.text[:200],
        )
        return False
    return True


@shared_task(
    name="workers.notifier.notify_critical",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    soft_time_limit=120,
)
def notify_critical(
    self,
    org_id: str,
    findings: list[dict[str, Any]],
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Alert an organisation's Slack channel about newly created critical findings."""
    if not settings.slack_notifications_enabled:
        return {"sent": False, "reason": "disabled"}

    eligible = [
        f for f in findings if _meets_threshold(str(f.get("severity", "")).lower())
    ]
    if not eligible:
        return {"sent": False, "reason": "below_threshold"}

    with session_scope() as session:
        org = session.get(Organisation, uuid.UUID(str(org_id)))
        if org is None:
            return {"sent": False, "reason": "org_missing"}
        webhook = org.slack_webhook_url
        org_name = org.name

    if not webhook:
        # Not an error. Most orgs will never configure this.
        return {"sent": False, "reason": "not_configured"}

    payload = build_blocks(findings=eligible, org_name=org_name, scan_id=scan_id)
    sent = post(webhook, payload)

    if not sent:
        # Retry covers a transient 5xx or timeout. A 404 (revoked webhook) will
        # burn the retries and then stop, which is correct — there is no
        # in-band way to distinguish it here, and three extra POSTs to a dead
        # URL costs nothing.
        try:
            raise self.retry(exc=RuntimeError("Slack webhook delivery failed"))
        except self.MaxRetriesExceededError:
            logger.error(
                "Giving up on Slack notification for org %s after %s attempts",
                org_id,
                self.max_retries,
            )
            return {"sent": False, "reason": "delivery_failed"}

    logger.info("Slack alert delivered for org %s (%s finding(s))", org_id, len(eligible))
    return {"sent": True, "count": len(eligible)}


__all__ = [
    "InvalidWebhookURL",
    "build_blocks",
    "notify_critical",
    "post",
    "redact",
    "validate_webhook_url",
]
