# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""FRECE exception hierarchy with remediation hints."""


class FreceError(Exception):
    """Base exception for all FRECE errors."""

    def __init__(self, message: str, remediation: str = ""):
        self.message = message
        self.remediation = remediation
        super().__init__(f"{message}\nREMEDIATION: {remediation}" if remediation else message)


class CustodyError(FreceError):
    """Chain of custody violation or tampering detected."""

    pass


class ValidationError(FreceError):
    """File validation failed."""

    pass


class SandboxError(FreceError):
    """Sandbox validation or execution failed."""

    pass


class AcquisitionError(FreceError):
    """Evidence acquisition failed."""

    pass


class CarveError(FreceError):
    """File carving failed."""

    pass


class RecoveryError(FreceError):
    """Deleted file recovery failed."""

    pass
