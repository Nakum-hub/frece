"""Tests for chain of custody HMAC protection."""

import hashlib
import os
import sqlite3

import pytest

from frece.custody import (
    CustodyDatabase,
    create_case_secret_key,
    get_case_secret_key,
    rotate_case_secret_key,
)
from frece.errors import CustodyError


class TestCustodyDatabase:
    """Test custody database HMAC protection."""

    @pytest.fixture
    def secret_key(self):
        """Create a test secret key."""
        return hashlib.sha256(b"test_secret").digest()

    @pytest.fixture
    def custody_db(self, temp_dir, secret_key):
        """Create a custody database."""
        db_path = temp_dir / "custody.db"
        return CustodyDatabase(db_path, secret_key)

    def test_init_creates_database(self, temp_dir, secret_key):
        """Test database initialization."""
        db_path = temp_dir / "custody.db"
        CustodyDatabase(db_path, secret_key)

        assert db_path.exists()

    def test_log_event_creates_entry(self, custody_db):
        """Test logging a custody event."""
        entry = custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source": "/dev/sda", "size": 1000},
        )

        assert entry.event_type == "ACQUIRE"
        assert entry.evidence_id == "EV001"
        assert entry.operator == "analyst1"
        assert len(entry.hash_sha256) == 64

    def test_hmac_protection(self, custody_db, secret_key):
        """Test that HMAC prevents tampering detection."""
        custody_db.log_event(
            event_type="HASH",
            evidence_id="EV001",
            operator="analyst1",
            details={"hash": "abc123"},
        )

        conn = sqlite3.connect(custody_db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, entry_hash FROM custody_log WHERE evidence_id = 'EV001'")
        row_id, stored_hash = cursor.fetchone()

        cursor.execute(
            "UPDATE custody_log SET details = ? WHERE id = ?",
            ('{"hash": "tampered"}', row_id),
        )
        conn.commit()
        conn.close()

        with pytest.raises(CustodyError):
            custody_db.verify_database()

    def test_verify_database_detects_tampering(self, custody_db):
        """Test tampering detection."""
        custody_db.log_event(
            event_type="CARVE",
            evidence_id="EV001",
            operator="analyst1",
            details={"count": 5},
        )

        conn = sqlite3.connect(custody_db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM custody_log WHERE evidence_id = 'EV001'")
        row_id = cursor.fetchone()[0]

        cursor.execute(
            "UPDATE custody_log SET details = ? WHERE id = ?",
            ('{"count": 999}', row_id),
        )
        conn.commit()
        conn.close()

        with pytest.raises(CustodyError):
            custody_db.verify_database()

    def test_verify_database_clean(self, custody_db):
        """Test clean database verification."""
        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source": "/dev/sda"},
        )

        custody_db.log_event(
            event_type="HASH",
            evidence_id="EV001",
            operator="analyst1",
            details={"hash": "abc123"},
        )

        total, tampered = custody_db.verify_database()

        assert total == 2
        assert tampered == 0

    def test_verify_evidence_source_match(self, custody_db):
        """Test source hash verification on match."""
        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source_hash": "abc123def456"},
        )

        result = custody_db.verify_evidence_source("EV001", "abc123def456")
        assert result is True

    def test_verify_evidence_source_mismatch(self, custody_db):
        """Test source hash verification on mismatch."""
        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source_hash": "abc123def456"},
        )

        with pytest.raises(CustodyError):
            custody_db.verify_evidence_source("EV001", "different_hash")

    def test_get_evidence_log(self, custody_db):
        """Test retrieving evidence log."""
        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source": "/dev/sda"},
        )

        custody_db.log_event(
            event_type="HASH",
            evidence_id="EV001",
            operator="analyst1",
            details={"hash": "abc123"},
        )

        log = custody_db.get_evidence_log("EV001")

        assert len(log) == 2
        assert log[0].event_type == "ACQUIRE"
        assert log[1].event_type == "HASH"

    def test_multiple_evidence_items(self, custody_db):
        """Test logging multiple evidence items."""
        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source": "/dev/sda"},
        )

        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV002",
            operator="analyst1",
            details={"source": "/dev/sdb"},
        )

        log1 = custody_db.get_evidence_log("EV001")
        log2 = custody_db.get_evidence_log("EV002")

        assert len(log1) == 1
        assert len(log2) == 1
        assert log1[0].evidence_id == "EV001"
        assert log2[0].evidence_id == "EV002"

    def test_create_case_secret_key(self, temp_dir):
        """Test case secret key creation."""
        case_dir = temp_dir / "case1"
        key = create_case_secret_key(case_dir)

        assert len(key) == 32
        assert (case_dir / ".case_secret").exists()

    @pytest.mark.skipif(os.name != "posix", reason="POSIX chmod semantics only")
    def test_case_secret_key_protected(self, temp_dir):
        """Test that case secret key is chmod 600."""
        case_dir = temp_dir / "case1"
        create_case_secret_key(case_dir)

        key_file = case_dir / ".case_secret"
        stat_info = key_file.stat()
        mode = stat_info.st_mode & 0o777

        assert mode == 0o600

    def test_case_secret_key_persists(self, temp_dir):
        """Test that case secret key is reused."""
        case_dir = temp_dir / "case1"
        key1 = create_case_secret_key(case_dir)
        key2 = create_case_secret_key(case_dir)

        assert key1 == key2

    def test_case_secret_key_uses_external_store(self, temp_dir, monkeypatch):
        """FRECE_KEY_STORE must move the HMAC key outside the case directory."""
        key_store = temp_dir / "keys"
        case_dir = temp_dir / "case1"
        monkeypatch.setenv("FRECE_KEY_STORE", str(key_store))

        key = create_case_secret_key(case_dir, case_name="case1")

        assert key == get_case_secret_key(case_dir, case_name="case1", create=False)
        assert (key_store / "case1.key").exists()
        assert not (case_dir / ".case_secret").exists()

    def test_rotate_case_secret_key_rehashes_database(self, temp_dir):
        """Key rotation must keep the custody DB verifiable under the new key."""
        case_dir = temp_dir / "case1"
        original_key = create_case_secret_key(case_dir, case_name="case1")
        custody_db = CustodyDatabase(case_dir / "custody.db", original_key)
        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source": "/dev/sda"},
        )

        rotate_case_secret_key(case_dir, case_name="case1")
        rotated_key = get_case_secret_key(case_dir, case_name="case1", create=False)
        rotated_db = CustodyDatabase(case_dir / "custody.db", rotated_key, initialize=False)

        assert rotated_key != original_key
        assert rotated_db.verify_database() == (1, 0)

    def test_event_timestamp_format(self, custody_db):
        """Test that timestamps are ISO 8601 with Z suffix."""
        entry = custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"source": "/dev/sda"},
        )

        assert entry.timestamp.endswith("Z")
        assert "T" in entry.timestamp

    def test_no_silent_failures_on_log(self, temp_dir, secret_key):
        """CustodyDatabase propagates sqlite3 errors — never silences them."""
        from unittest.mock import patch

        db_path = temp_dir / "custody.db"
        custody_db = CustodyDatabase(db_path, secret_key)

        with patch.object(
            custody_db,
            "_connect",
            side_effect=sqlite3.OperationalError("disk I/O error"),
        ):
            with pytest.raises(Exception):
                custody_db.log_event(
                    event_type="ACQUIRE",
                    evidence_id="EV001",
                    operator="analyst1",
                    details={},
                )
