"""Request/response models. These are the API contract — ORM objects never
cross the wire directly."""

from schemas.asset import AssetCreate, AssetOut, AssetSummary, AssetUpdate
from schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserInvite,
    UserOut,
)
from schemas.common import Message, PaginatedResponse
from schemas.domain import (
    DomainAdd,
    DomainVerificationList,
    DomainVerificationOut,
    DomainVerifyResult,
)
from schemas.finding import FindingOut, FindingStatsOut, FindingUpdate
from schemas.report import ReportOut, ReportRequest
from schemas.scan import ScanConfig, ScanCreate, ScanLogOut, ScanOut

__all__ = [
    "AssetCreate",
    "AssetOut",
    "AssetSummary",
    "AssetUpdate",
    "DomainAdd",
    "DomainVerificationList",
    "DomainVerificationOut",
    "DomainVerifyResult",
    "FindingOut",
    "FindingStatsOut",
    "FindingUpdate",
    "LoginRequest",
    "Message",
    "PaginatedResponse",
    "RefreshRequest",
    "RegisterRequest",
    "ReportOut",
    "ReportRequest",
    "ScanConfig",
    "ScanCreate",
    "ScanLogOut",
    "ScanOut",
    "TokenPair",
    "UserInvite",
    "UserOut",
]
