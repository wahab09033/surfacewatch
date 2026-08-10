"""ORM model package.

Importing this module registers every table on ``Base.metadata`` — Alembic's
autogenerate and ``create_all`` both depend on that side effect.
"""

from models.asset import Asset
from models.base import (
    AssetStatus,
    FindingStatus,
    LogLevel,
    ScanStatus,
    Severity,
    UserRole,
)
from models.finding import Finding
from models.organisation import Organisation
from models.report import Report
from models.scan import Scan, ScanLog
from models.user import User

__all__ = [
    "Asset",
    "AssetStatus",
    "Finding",
    "FindingStatus",
    "LogLevel",
    "Organisation",
    "Report",
    "Scan",
    "ScanLog",
    "ScanStatus",
    "Severity",
    "User",
    "UserRole",
]
