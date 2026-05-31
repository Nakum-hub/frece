"""FRECE: Forensic Recovery and Evidence Collection Engine."""

__version__ = "2.2.0"

from frece.errors import (
    AcquisitionError,
    CarveError,
    CustodyError,
    FreceError,
    RecoveryError,
    SandboxError,
    ValidationError,
)

__all__ = [
    "FreceError",
    "SandboxError",
    "AcquisitionError",
    "CarveError",
    "RecoveryError",
    "CustodyError",
    "ValidationError",
]
