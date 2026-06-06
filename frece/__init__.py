# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
"""FRECE: Forensic Recovery and Evidence Collection Engine."""

__version__ = "2.4.0"

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
