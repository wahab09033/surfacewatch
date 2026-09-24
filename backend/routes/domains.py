"""Domain ownership: claim a domain, prove it with DNS, revoke it.

This is the gate that stops SurfaceWatch being an open scanning relay. Scanning
authority comes only from ``Organisation.verified_domains``, and the only way in
is a claim here reaching VERIFIED by publishing a TXT record.

Registration is open to the public, so without this every account could scan any
domain it typed into the signup form. See ``models.Organisation.all_domains``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from config import settings
from core.deps import AdminDep, AnalystDep, DbDep
from core.dns_verify import check_domain_token
from core.ratelimit import DOMAIN_VERIFY_ORG, enforce
from models import DomainVerification, DomainVerificationStatus, Organisation
from models.base import utcnow
from models.domain_verification import TOKEN_TTL, new_token
from schemas.common import Message
from schemas.domain import (
    DomainAdd,
    DomainVerificationList,
    DomainVerificationOut,
    DomainVerifyResult,
)

router = APIRouter(prefix="/api/auth/organisation/domains", tags=["domains"])


async def _load_org(db: DbDep, org_id: uuid.UUID) -> Organisation:
    org = await db.scalar(select(Organisation).where(Organisation.id == org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return org


async def _load_claim(db: DbDep, claim_id: uuid.UUID, org_id: uuid.UUID) -> DomainVerification:
    """Fetch one claim, scoped to the caller's organisation.

    404 rather than 403 for another org's row: a 403 would confirm the id exists,
    which is the cross-tenant enumeration oracle every query in this codebase is
    filtered to avoid.
    """
    claim = await db.scalar(
        select(DomainVerification).where(
            DomainVerification.id == claim_id,
            DomainVerification.org_id == org_id,
        )
    )
    if claim is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    return claim


def _grant(org: Organisation, domain: str) -> None:
    """Add ``domain`` to the org's scanning authority.

    Reassigns the list rather than appending to it. ``verified_domains`` is a
    plain JSONB column, not a MutableList, so SQLAlchemy does not see in-place
    mutation — ``org.verified_domains.append(...)`` looks correct, changes the
    object in memory, and is silently dropped at commit. The result would be a
    claim marked VERIFIED whose domain is still unscannable.
    """
    current = [d for d in (org.verified_domains or []) if d]
    if domain not in current:
        org.verified_domains = [*current, domain]


def _revoke(org: Organisation, domain: str) -> None:
    """Remove ``domain`` from the org's scanning authority. See ``_grant``."""
    org.verified_domains = [d for d in (org.verified_domains or []) if d and d != domain]


@router.get(
    "",
    response_model=DomainVerificationList,
    summary="List this organisation's domain claims",
)
async def list_domains(current: AnalystDep, db: DbDep) -> DomainVerificationList:
    """Every claim, verified or not, with the DNS record still to be published.

    Analyst+ rather than any role: a pending claim carries its challenge token,
    and while the token grants nothing on its own — publishing it requires DNS
    control, which is the thing being proven — there is no reason a viewer needs
    it. The verified list itself is already visible to everyone via
    ``GET /api/auth/organisation``.
    """
    rows = (
        await db.scalars(
            select(DomainVerification)
            .where(DomainVerification.org_id == current.org_id)
            .order_by(DomainVerification.created_at)
        )
    ).all()
    return DomainVerificationList(
        items=[DomainVerificationOut.from_row(r) for r in rows],
        limit=settings.max_verified_domains_per_org,
    )


@router.post(
    "",
    response_model=DomainVerificationOut,
    summary="Claim a domain and get its DNS challenge",
)
async def add_domain(
    body: DomainAdd, current: AdminDep, db: DbDep
) -> DomainVerificationOut:
    """Register a claim on a domain. This grants nothing until it is verified.

    Admin+ because a verified domain is scanning authorisation, and because the
    per-org cap makes claim creation a resource an untrusted role should not be
    able to exhaust.

    Re-adding a domain returns the **existing** claim and its original token
    rather than erroring. That is deliberate: the common reason to re-add is
    having lost the token, and minting a fresh one would silently invalidate a
    TXT record the user may already have published.
    """
    org = await _load_org(db, current.org_id)

    existing = await db.scalar(
        select(DomainVerification).where(
            DomainVerification.org_id == current.org_id,
            DomainVerification.domain == body.domain,
        )
    )
    if existing is not None:
        return DomainVerificationOut.from_row(existing)

    held = await db.scalar(
        select(func.count())
        .select_from(DomainVerification)
        .where(DomainVerification.org_id == current.org_id)
    )
    if (held or 0) >= settings.max_verified_domains_per_org:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"This organisation already holds {held} domains, the maximum of "
                f"{settings.max_verified_domains_per_org}. Remove one first."
            ),
        )

    claim = DomainVerification(
        org_id=org.id,
        created_by=current.id,
        domain=body.domain,
    )
    db.add(claim)
    await db.commit()
    await db.refresh(claim)
    return DomainVerificationOut.from_row(claim)


@router.post(
    "/{claim_id}/verify",
    response_model=DomainVerifyResult,
    summary="Check DNS for the challenge record and verify the domain",
)
async def verify_domain(
    claim_id: uuid.UUID, current: AdminDep, db: DbDep
) -> DomainVerifyResult:
    """Look for the TXT record and, if it is there, grant scanning authority.

    On success the claim and ``Organisation.verified_domains`` are written in one
    transaction. They must not diverge: a VERIFIED claim whose domain never
    reached the list is an org that proved ownership and still cannot scan, and
    the reverse is a scannable domain with no proof behind it.
    """
    claim = await _load_claim(db, claim_id, current.org_id)

    # Short-circuited before the rate limiter so re-checking an already-verified
    # domain costs neither a DNS query nor budget.
    if claim.is_verified:
        return DomainVerifyResult(
            verified=True, verification=DomainVerificationOut.from_row(claim)
        )

    # Expired challenge tokens are rotated, not rejected: the user must publish
    # a fresh value, and only the current DNS owner can do that. Rotation
    # happens before any DNS query, so it spends no rate-limit budget.
    if claim.token_expires_at is None or utcnow() >= claim.token_expires_at:
        claim.token = new_token()
        claim.token_expires_at = utcnow() + TOKEN_TTL
        claim.status = DomainVerificationStatus.PENDING
        claim.last_checked_at = utcnow()
        claim.last_error = (
            "The verification token expired before the check ran. A new token "
            "has been issued — publish the new record value and verify again."
        )
        await db.commit()
        await db.refresh(claim)
        return DomainVerifyResult(
            verified=False,
            verification=DomainVerificationOut.from_row(claim),
            detail=(
                "The previous verification token expired. A new one has been "
                "issued — publish the new value shown above and verify again."
            ),
        )

    # Consumes budget per attempt, not per failure: the cost being limited is the
    # outbound DNS query, which is spent either way.
    await enforce(DOMAIN_VERIFY_ORG, str(current.org_id))

    result = await check_domain_token(claim.domain, claim.token)
    claim.last_checked_at = utcnow()

    if not result.ok:
        claim.status = DomainVerificationStatus.FAILED
        claim.last_error = result.error
        claim.consecutive_failures += 1
        await db.commit()
        await db.refresh(claim)
        return DomainVerifyResult(
            verified=False,
            verification=DomainVerificationOut.from_row(claim),
            detail=result.error,
        )

    org = await _load_org(db, current.org_id)
    claim.status = DomainVerificationStatus.VERIFIED
    claim.verified_at = claim.last_checked_at
    claim.last_error = None
    claim.consecutive_failures = 0
    _grant(org, claim.domain)
    await db.commit()
    await db.refresh(claim)

    return DomainVerifyResult(
        verified=True, verification=DomainVerificationOut.from_row(claim)
    )


@router.delete(
    "/{claim_id}",
    response_model=Message,
    summary="Remove a domain and revoke its scanning authority",
)
async def delete_domain(claim_id: uuid.UUID, current: AdminDep, db: DbDep) -> Message:
    """Drop the claim and take the domain out of scope.

    This revokes authorisation immediately: in-flight scans already past their
    scope check will finish, but no new scan of that domain can be started.
    """
    claim = await _load_claim(db, claim_id, current.org_id)
    org = await _load_org(db, current.org_id)
    domain = claim.domain

    _revoke(org, domain)
    await db.delete(claim)
    await db.commit()

    return Message(detail=f"{domain} removed. It can no longer be scanned.")
