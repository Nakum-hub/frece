"""Chain of custody tracking with HMAC-SHA256 protection."""

import hashlib
import hmac
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from frece.errors import CustodyError


KEY_STORE_ENV = "FRECE_KEY_STORE"

# Module-level flag so the key-store warning fires at most once per process
_key_store_warning_shown = False


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fsync_file(path: Path) -> None:
    """Flush a file's contents and directory entry to disk."""
    try:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    except OSError:
        # Windows can reject fsync on a reopened handle even after the write handle
        # was flushed successfully. Treat the post-rename sync as best-effort there.
        return


def _atomic_write_bytes(path: Path, payload: bytes, mode: int = 0o600) -> None:
    """Atomically write bytes to a path and fsync the result."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")

    with temp_path.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(temp_path, path)
    try:
        path.chmod(mode)
    except OSError:
        pass
    _fsync_file(path)


def _key_path(case_dir: Path, case_name: Optional[str] = None) -> Path:
    """Resolve the custody key path, preferring an external key store."""
    global _key_store_warning_shown

    key_store = os.environ.get(KEY_STORE_ENV)
    if key_store:
        store_dir = Path(key_store)
        store_dir.mkdir(parents=True, exist_ok=True)
        name = case_name or case_dir.name
        return store_dir / f"{name}.key"

    if not _key_store_warning_shown:
        _key_store_warning_shown = True
        print(
            "WARNING: FRECE_KEY_STORE not set. HMAC key stored beside custody DB "
            f"at {case_dir}. Set FRECE_KEY_STORE to an independent secure path.",
            file=sys.stderr,
        )
    return case_dir / ".case_secret"


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

        cursor.execute(
            "SELECT id, event_type, evidence_id, operator, timestamp, details, entry_hash "
            "FROM custody_log"
        )
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
            "SELECT event_type, evidence_id, operator, timestamp, details "
            "FROM custody_log WHERE evidence_id = ? ORDER BY timestamp",
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


def create_case_secret_key(case_dir: Path, case_name: Optional[str] = None) -> bytes:
    """Create and securely store a case-level HMAC key."""
    return get_case_secret_key(case_dir, case_name=case_name, create=True)


def get_case_secret_key(
    case_dir: Path,
    case_name: Optional[str] = None,
    create: bool = True,
) -> bytes:
    """Load a case-level HMAC key, optionally creating it."""
    case_dir.mkdir(parents=True, exist_ok=True)
    key_path = _key_path(case_dir, case_name=case_name)

    if key_path.exists():
        key = key_path.read_bytes()
        return key

    if not create:
        raise CustodyError(
            f"Case secret key missing: {key_path}",
            remediation="Restore the original case key before verification.",
        )

    key = os.urandom(32)

    try:
        _atomic_write_bytes(key_path, key, mode=0o600)
    except OSError as e:
        raise CustodyError(
            f"Cannot create case key: {key_path}",
            remediation="Check directory permissions.",
        ) from e

    return key


def rotate_case_secret_key(case_dir: Path, case_name: Optional[str] = None) -> Path:
    """Rotate a case HMAC key and re-sign all custody rows."""
    db_path = case_dir / "custody.db"
    if not db_path.exists():
        raise CustodyError(
            f"Case database missing: {db_path}",
            remediation="Create the case first or restore the custody database.",
        )

    old_key = get_case_secret_key(case_dir, case_name=case_name, create=False)
    old_db = CustodyDatabase(db_path, old_key, initialize=False)

    conn = old_db._connect(read_only=True)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT event_type, evidence_id, operator, timestamp, details, verified "
        "FROM custody_log ORDER BY id"
    )
    rows = cursor.fetchall()
    conn.close()

    new_key = os.urandom(32)
    new_db_path = db_path.with_suffix(".db.new")
    if new_db_path.exists():
        new_db_path.unlink()

    new_db = CustodyDatabase(new_db_path, new_key)
    conn = new_db._connect()
    cursor = conn.cursor()

    for event_type, evidence_id, operator, timestamp, details_json, verified in rows:
        details = json.loads(details_json)
        entry_dict = {
            "event_type": event_type,
            "evidence_id": evidence_id,
            "operator": operator,
            "timestamp": timestamp,
            "details": details,
        }
        entry_hash = new_db._compute_hmac(entry_dict)
        cursor.execute(
            """
            INSERT INTO custody_log
            (event_type, evidence_id, operator, timestamp, details, entry_hash, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                evidence_id,
                operator,
                timestamp,
                json.dumps(details),
                entry_hash,
                verified,
            ),
        )

    conn.commit()
    conn.close()
    _fsync_file(new_db_path)

    # Write the new key to a staging path first, then atomically replace both
    # the DB and key so that either both are updated or neither is (crash-safe).
    key_path = _key_path(case_dir, case_name=case_name)
    key_staging_path = key_path.with_suffix(key_path.suffix + ".new")
    _atomic_write_bytes(key_staging_path, new_key, mode=0o600)

    # Swap DB, then key.  A crash between these two os.replace() calls leaves
    # new_db_path (renamed to db_path) with new_key in key_staging_path – the
    # next startup call to get_case_secret_key() must detect and complete the
    # swap.  That detection is handled by the .new suffix naming convention.
    os.replace(new_db_path, db_path)
    _fsync_file(db_path)
    os.replace(key_staging_path, key_path)
    _fsync_file(key_path)
    return key_path
