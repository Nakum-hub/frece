# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Unit tests for the error hierarchy."""
import pytest
from frece.errors import (
    FreceError, SandboxError, RecoveryError, CarveError,
    AcquisitionError, CustodyError, ValidationError
)

def test_frece_error_is_exception():
    e = FreceError("test message", remediation="do this")
    assert "test message" in str(e)
    assert e.remediation == "do this"

def test_sandbox_error_is_frece_error():
    assert issubclass(SandboxError, FreceError)

def test_recovery_error_is_frece_error():
    assert issubclass(RecoveryError, FreceError)

def test_carve_error_is_frece_error():
    assert issubclass(CarveError, FreceError)

def test_acquisition_error_is_frece_error():
    assert issubclass(AcquisitionError, FreceError)

def test_custody_error_is_frece_error():
    assert issubclass(CustodyError, FreceError)

def test_validation_error_is_frece_error():
    assert issubclass(ValidationError, FreceError)

def test_error_raise_and_catch():
    with pytest.raises(FreceError) as exc_info:
        raise RecoveryError("disk read failed", remediation="check permissions")
    assert "disk read failed" in str(exc_info.value)
    assert exc_info.value.remediation == "check permissions"

def test_error_default_remediation():
    e = FreceError("oops")
    assert e.remediation == ""
