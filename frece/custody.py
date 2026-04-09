"""Chain of custody tracking with HMAC-SHA256 protection."""

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from frece.errors import CustodyError


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class CustodyEntry:
    """Chain of custody log entry."""

    event_type: str
    evidence_id: str
    operator: str
    timestamp: str
    details: dict
    hash_sha256: str


class CustodyDatabase:
    """SQLite-based chain of custody tracking with HMAC protection."""

    def __init__(self, db_path: Path, secret_key: bytes, initialize: bool = True):
        """Initialize custody database."""
        self.db_path = db_path
        self.secret_key = secret_key

        db_path.parent.mkdir(parents=True, exist_ok=True)
        if initialize:
            self._init_db()

    def _connect(self, read_only: bool = False) -> sqlite3.Connection:
        """Open the custody database with the appropriate access mode."""
        if read_only:
            return sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        """Create custody table if not exists."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS custody_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                operator TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                verified INTEGER DEFAULT 0
            )
        """
        )

        conn.commit()
        conn.close()

    def log_event(
        self,
        event_type: str,
        evidence_id: str,
        operator: str,
        details: dict,
    ) -> CustodyEntry:
        """Log a custody event with HMAC signature."""
        timestamp = _utc_now_iso()

        entry_dict = {
            "event_type": event_type,
            "evidence_id": evidence_id,
            "operator": operator,
            "timestamp": timestamp,
            "details": details,
        }

        entry_hash = self._compute_hmac(entry_dict)

        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO custody_log
            (event_type, evidence_id, operator, timestamp, details, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                event_type,
                evidence_id,
                operator,
                timestamp,
                json.dumps(details),
                entry_hash,
            ),
        )

        conn.commit()
        conn.close()

        return CustodyEntry(
            event_type=event_type,
            evidence_id=evidence_id,
            operator=operator,
            timestamp=timestamp,
            details=details,
            hash_sha256=entry_hash,
        )

    def _compute_hmac(self, entry_dict: dict) -> str:
        """Compute HMAC-SHA256 of entry fields."""
        entry_json = json.dumps(entry_dict, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            self.secret_key, entry_json.encode(), hashlib.sha256
        ).hexdigest()
        return signature

    def verify_database(self) -> tuple[int, int]:
        """Verify all entries in database for tampering."""
        conn = self._connect(read_only=True)
        cursor = conn.cursor()

        cursor.execute("SELECT id, event_type, evidence_id, operator, timestamp, details, entry_hash FROM custody_log")
        rows = cursor.fetchall()
        conn.close()

        total = len(rows)
        tampered = 0

        for row_id, event_type, evidence_id, operator, timestamp, details_json, stored_hash in rows:
            details = json.loads(details_json)

            entry_dict = {
                "event_type": event_type,
                "evidence_id": evidence_id,
                "operator": operator,
                "timestamp": timestamp,
                "details": details,
            }

            computed_hash = self._compute_hmac(entry_dict)

            if computed_hash != stored_hash:
                tampered += 1

        if tampered > 0:
            raise CustodyError(
                f"Database integrity check failed: {tampered}/{total} entries tampered",
                remediation="Do not use this evidence. Report to legal.",
            )

        return (total, tampered)

    def verify_evidence_source(
        self, evidence_id: str, source_hash: str
    ) -> bool:
        """Verify evidence hash matches source device hash."""
        conn = self._connect(read_only=True)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT details FROM custody_log WHERE evidence_id = ? AND event_type = 'ACQUIRE'",
            (evidence_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise CustodyError(
                f"No ACQUIRE event found for {evidence_id}",
                remediation="Cannot verify source.",
            )

        details = json.loads(row[0])
        stored_source_hash = details.get("source_hash")

        if stored_source_hash != source_hash:
            raise CustodyError(
                f"Evidence {evidence_id} source mismatch",
                remediation="Evidence tampering detected.",
            )

        return True

    def get_evidence_log(self, evidence_id: str) -> list[CustodyEntry]:
        """Get all custody events for an evidence item."""
        conn = self._connect(read_only=True)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT event_type, evidence_id, operator, timestamp, details FROM custody_log WHERE evidence_id = ? ORDER BY timestamp",
            (evidence_id,),
        )
        rows = cursor.fetchall()
        conn.close()

        entries = []
        for event_type, eid, operator, timestamp, details_json in rows:
            details = json.loads(details_json)
            entry = CustodyEntry(
                event_type=event_type,
                evidence_id=eid,
                operator=operator,
                timestamp=timestamp,
                details=details,
                hash_sha256="",
            )
            entries.append(entry)

        return entries


def create_case_secret_key(case_dir: Path) -> bytes:
    """Create and securely store a case-level HMAC key."""
    return get_case_secret_key(case_dir, create=True)


def get_case_secret_key(case_dir: Path, create: bool = True) -> bytes:
    """Load a case-level HMAC key, optionally creating it."""
    case_dir.mkdir(parents=True, exist_ok=True)
    key_path = case_dir / ".case_secret"

    if key_path.exists():
        key = key_path.read_bytes()
        return key

    if not create:
        raise CustodyError(
            f"Case secret key missing: {key_path}",
            remediation="Restore the original .case_secret file before verification.",
        )

    key = os.urandom(32)

    try:
        key_path.write_bytes(key)
        key_path.chmod(0o600)
    except OSError as e:
        raise CustodyError(
            f"Cannot create case key: {key_path}",
            remediation="Check directory permissions.",
        ) from e

    return key
