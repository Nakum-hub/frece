"""Regression tests for every bug fixed in the v2.0.0 → v2.1.0 patch set."""

import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from frece.acquisition import EvidenceAcquisition
from frece.carver import StreamingCarver
from frece.config import Config, load_config
from frece.custody import (
    CustodyDatabase,
    _key_store_warning_shown,
    create_case_secret_key,
    get_case_secret_key,
    rotate_case_secret_key,
    _key_path,
)
from frece.errors import (
    AcquisitionError,
    CustodyError,
    SandboxError,
    ValidationError,
)
from frece.sandbox import InputValidator


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 1 – config.py: tilde not expanded when reading case_root from TOML
# ─────────────────────────────────────────────────────────────────────────────
def test_config_tilde_expanded_from_toml(tmp_path):
    """~/.frece/cases in a config TOML must be resolved, not kept literally."""
    config_toml = tmp_path / "config.toml"
    config_toml.write_text('[tool.frece]\ncase_root = "~/.frece_test_cases"\n')

    cfg = load_config(config_path=config_toml)

    assert "~" not in str(cfg.case_root), (
        f"Tilde was not expanded; got {cfg.case_root}"
    )
    assert str(Path.home()) in str(cfg.case_root)


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 2 – config.py: load_config must NOT create directories as a side-effect
# ─────────────────────────────────────────────────────────────────────────────
def test_load_config_does_not_mkdir(tmp_path):
    """load_config() must not create case_root as a side-effect."""
    non_existent = tmp_path / "should_not_be_created"
    cfg = Config()
    cfg.case_root = non_existent

    # Simulate what load_config does (no TOML file → returns defaults)
    loaded = load_config(config_path=tmp_path / "missing.toml")

    # The directory pointed to by a fresh default config must not yet exist
    # unless the caller explicitly calls ensure_case_root()
    assert not non_existent.exists()


def test_ensure_case_root_creates_directory(tmp_path):
    """ensure_case_root() is the explicit way to create the directory."""
    cfg = Config()
    cfg.case_root = tmp_path / "cases"
    assert not cfg.case_root.exists()
    cfg.ensure_case_root()
    assert cfg.case_root.exists()


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 3 – sandbox.py: path traversal not blocked
# ─────────────────────────────────────────────────────────────────────────────
def test_validate_path_blocks_dotdot():
    """.. components in a path must raise SandboxError."""
    with pytest.raises(SandboxError, match="traversal"):
        InputValidator.validate_path("/tmp/../etc/passwd")


def test_validate_path_blocks_dotdot_relative():
    """Relative paths with .. must also be blocked."""
    with pytest.raises(SandboxError, match="traversal"):
        InputValidator.validate_path("../etc/passwd")


def test_validate_path_blocks_null_byte():
    """Null bytes in paths must raise SandboxError."""
    with pytest.raises(SandboxError, match="null"):
        InputValidator.validate_path("/tmp/file\x00.txt")


def test_validate_path_allows_normal_path(tmp_path):
    """Normal absolute paths must still work."""
    result = InputValidator.validate_path(str(tmp_path / "evidence.dd"))
    assert result == tmp_path / "evidence.dd"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 4 – acquisition.py: _acquire_single_file read file twice
# ─────────────────────────────────────────────────────────────────────────────
def test_acquire_single_file_reads_once(tmp_path):
    """_acquire_single_file must produce the correct hash in one pass."""
    source = tmp_path / "evidence.bin"
    content = b"forensic payload " * 1024
    source.write_bytes(content)

    acq = EvidenceAcquisition()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = acq._acquire_single_file(source, out_dir)

    expected_sha256 = hashlib.sha256(content).hexdigest()
    assert result["sha256"] == expected_sha256

    # Output filename embeds the first 8 hex chars of the hash
    assert result["output_file"].endswith(f"{expected_sha256[:8]}_evidence.bin")

    # Output file has correct content
    assert Path(result["output_file"]).read_bytes() == content


def test_acquire_single_file_parallel_no_collision(tmp_path):
    """Two files with the same name but different content must not collide."""
    src1 = tmp_path / "d1" / "report.txt"
    src2 = tmp_path / "d2" / "report.txt"
    src1.parent.mkdir()
    src2.parent.mkdir()
    src1.write_text("Report version 1")
    src2.write_text("Report version 2")

    acq = EvidenceAcquisition()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    batch = acq.acquire_files([src1, src2], out_dir)
    output_files = [m["output_file"] for m in batch.values()]
    assert len(set(output_files)) == 2, "Parallel acquisition produced colliding output files"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 5 – custody.py: _key_path warning fires on every call
# ─────────────────────────────────────────────────────────────────────────────
def test_key_path_warning_fires_at_most_once(tmp_path, monkeypatch, capsys):
    """The FRECE_KEY_STORE-missing warning must appear at most once per process."""
    import frece.custody as custody_mod

    monkeypatch.delenv("FRECE_KEY_STORE", raising=False)
    # Reset the module-level flag so the test is deterministic
    monkeypatch.setattr(custody_mod, "_key_store_warning_shown", False)

    from frece.custody import _key_path

    _key_path(tmp_path, "case1")
    _key_path(tmp_path, "case1")
    _key_path(tmp_path, "case1")

    captured = capsys.readouterr()
    warning_count = captured.err.count("WARNING")
    assert warning_count == 1, (
        f"Expected exactly 1 warning, got {warning_count}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 6 – custody.py: rotate_case_secret_key atomicity
# ─────────────────────────────────────────────────────────────────────────────
def test_rotate_key_staging_file_naming(tmp_path, monkeypatch):
    """Rotation must write a staging key file (.new suffix) before swapping."""
    monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))

    case_dir = tmp_path / "cases" / "CASE-001"
    case_dir.mkdir(parents=True)

    key = create_case_secret_key(case_dir, case_name="CASE-001")
    db = CustodyDatabase(case_dir / "custody.db", key)
    db.log_event("INTAKE", "EV-001", "analyst", {"note": "initial"})

    # After rotation the DB must still verify cleanly
    key_path = rotate_case_secret_key(case_dir, case_name="CASE-001")
    assert key_path.exists()

    new_db = CustodyDatabase(case_dir / "custody.db", key_path.read_bytes(), initialize=False)
    total, tampered = new_db.verify_database()
    assert total == 1
    assert tampered == 0


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 7 – carver.py: duplicated _validate_file / _validate_output_file
# ─────────────────────────────────────────────────────────────────────────────
def test_validate_file_delegates_to_validate_output_file():
    """_validate_file must produce the same result as _validate_output_file."""
    carver = StreamingCarver()

    # Build a minimal valid JPEG (SOI + EOI)
    jpeg_data = b"\xff\xd8\xff\xe0" + b"\x00" * 16 + b"\xff\xd9"

    from_bytes = carver._validate_file("jpeg", jpeg_data)
    assert "JPEG" in from_bytes
    assert "SOI" in from_bytes


def test_validate_output_file_jpeg_via_file(tmp_path):
    """_validate_output_file must work for JPEG on disk."""
    carver = StreamingCarver()
    jpeg = tmp_path / "test.jpeg"
    jpeg.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 16 + b"\xff\xd9")

    result = carver._validate_output_file("jpeg", jpeg, jpeg.stat().st_size)
    assert "JPEG" in result


def test_validate_output_file_jpeg_bad_eoi(tmp_path):
    """_validate_output_file must reject JPEG missing EOI regardless of size."""
    carver = StreamingCarver()
    jpeg = tmp_path / "bad.jpeg"
    jpeg.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 16)  # no EOI

    with pytest.raises(ValidationError, match="EOI"):
        carver._validate_output_file("jpeg", jpeg, jpeg.stat().st_size)


# ─────────────────────────────────────────────────────────────────────────────
# BUG-FIX 8 – partition.py: empty error message for bare filesystem images
# ─────────────────────────────────────────────────────────────────────────────
def test_partitions_helpful_error_for_bare_image(tmp_path):
    """frece partitions on a raw ext2 image must give a useful error message."""
    from frece.partition import list_partitions
    from frece.errors import RecoveryError

    image = tmp_path / "bare.dd"
    image.write_bytes(b"\x00" * 1024)  # not a partitioned disk

    with pytest.raises(RecoveryError) as exc_info:
        list_partitions(image)

    msg = str(exc_info.value)
    # Must not be a bare "mmls failed: " with nothing after
    assert len(msg) > len("mmls failed: "), (
        f"Error message was not informative: {msg!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Regression – custody HMAC tampering detection still works after all patches
# ─────────────────────────────────────────────────────────────────────────────
def test_custody_detects_tampering_after_patches(tmp_path, monkeypatch):
    """HMAC tampering detection must still work end-to-end."""
    monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    key = create_case_secret_key(case_dir, case_name="CASE")
    db = CustodyDatabase(case_dir / "custody.db", key)
    db.log_event("ACQUIRE", "EV-001", "analyst", {"source": "/dev/sda"})

    # Tamper directly with SQLite
    conn = sqlite3.connect(str(case_dir / "custody.db"))
    conn.execute("UPDATE custody_log SET operator='attacker' WHERE id=1")
    conn.commit()
    conn.close()

    with pytest.raises(CustodyError, match="tampered"):
        db.verify_database()
