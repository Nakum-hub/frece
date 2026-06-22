# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""FRECE: Forensic Recovery and Evidence Collection Engine."""

__version__ = "1.0.0"

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
