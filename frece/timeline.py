# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
"""Forensic timeline synthesis from FRECE case artifacts.

Aggregates MAC (Modified/Accessed/Created) times from:
  - fls -m mactime output in scan manifests
  - recovery_manifest.json files
  - carve_manifest.json files
  - custody.db event timestamps

Outputs sorted chronological event streams for triage and court presentation.
"""

import csv
import io
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class TimelineEvent:
    """A single timestamped forensic event."""

    timestamp: str           # ISO-8601 UTC
    timestamp_epoch: int     # Unix epoch seconds (for sorting)
    event_source: str        # "filesystem" | "recovery" | "carving" | "custody"
    event_type: str          # "modified" | "accessed" | "created" | "changed" | "acquire" | …
    artifact_path: str       # file path / evidence ID
    artifact_type: str       # file type or custody event type
    size_bytes: int          # 0 when unknown
    inode: Optional[int]     # for filesystem events
    notes: str               # extra context


def _epoch_to_iso(epoch: int) -> str:
    """Convert a Unix epoch int to a UTC ISO-8601 string."""
    if epoch == 0:
        return ""
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return ""


def _iso_to_epoch(iso: str) -> int:
    """Parse an ISO-8601 string to Unix epoch seconds."""
    if not iso:
        return 0
    iso = iso.rstrip("Z")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ):
        try:
            return int(datetime.strptime(iso, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Parsers for individual data sources
# ──────────────────────────────────────────────────────────────────────────────

def _events_from_mactime_line(line: str) -> list[TimelineEvent]:
    """Parse one fls -m (mactime / body file) line into TimelineEvent(s).

    Format:  MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    """
    parts = line.strip().split("|")
    if len(parts) < 11:
        return []

    name = parts[1]
    try:
        inode_str = parts[2].split("-")[0]
        inode = int(inode_str) if inode_str.isdigit() else None
    except (ValueError, IndexError):
        inode = None

    try:
        size = int(parts[6])
    except ValueError:
        size = 0

    time_map = {
        "accessed": parts[7],
        "modified": parts[8],
        "changed": parts[9],
        "created": parts[10],
    }

    events: list[TimelineEvent] = []
    for etype, epoch_str in time_map.items():
        try:
            epoch = int(epoch_str)
        except ValueError:
            continue
        if epoch == 0:
            continue
        iso = _epoch_to_iso(epoch)
        if not iso:
            continue
        events.append(
            TimelineEvent(
                timestamp=iso,
                timestamp_epoch=epoch,
                event_source="filesystem",
                event_type=etype,
                artifact_path=name,
                artifact_type="file",
                size_bytes=size,
                inode=inode,
                notes="",
            )
        )
    return events


def _events_from_recovery_manifest(manifest_path: Path) -> list[TimelineEvent]:
    """Extract timeline events from a recovery_manifest.json."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    events: list[TimelineEvent] = []
    for rec in data.get("recovered_files", []):
        # Recovery timestamp
        ts = rec.get("timestamp") or rec.get("recovery_timestamp") or ""
        epoch = _iso_to_epoch(ts)
        if ts:
            events.append(
                TimelineEvent(
                    timestamp=ts,
                    timestamp_epoch=epoch,
                    event_source="recovery",
                    event_type="recovered",
                    artifact_path=rec.get("output_path", ""),
                    artifact_type=rec.get("file_type", "bin"),
                    size_bytes=rec.get("size", 0),
                    inode=rec.get("inode"),
                    notes=f"original_name={rec.get('original_name', '')}",
                )
            )
        # MAC times if present
        for mac_key in ("mtime", "atime", "ctime", "crtime"):
            epoch_val = rec.get(mac_key, 0)
            if epoch_val:
                iso = _epoch_to_iso(int(epoch_val))
                if iso:
                    events.append(
                        TimelineEvent(
                            timestamp=iso,
                            timestamp_epoch=int(epoch_val),
                            event_source="filesystem",
                            event_type=mac_key,
                            artifact_path=rec.get("original_name") or rec.get("output_path", ""),
                            artifact_type=rec.get("file_type", "bin"),
                            size_bytes=rec.get("size", 0),
                            inode=rec.get("inode"),
                            notes="from recovery manifest",
                        )
                    )
    return events


def _events_from_carve_manifest(manifest_path: Path) -> list[TimelineEvent]:
    """Extract timeline events from a carve_manifest.json."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    ts = data.get("timestamp", "")
    epoch = _iso_to_epoch(ts)
    events: list[TimelineEvent] = []

    for carved in data.get("carved_files", []):
        events.append(
            TimelineEvent(
                timestamp=ts,
                timestamp_epoch=epoch,
                event_source="carving",
                event_type="carved",
                artifact_path=f"offset:{carved.get('offset', 0)}",
                artifact_type=carved.get("file_type", "bin"),
                size_bytes=carved.get("size", 0),
                inode=None,
                notes=(
                    f"source={data.get('source', '')} "
                    f"validation={'pass' if carved.get('validation_passed') else 'fail'}"
                ),
            )
        )
    return events


def _events_from_custody_db(  # noqa: E501
    db_path: Path,
    secret_key: Optional[bytes] = None,
) -> list[TimelineEvent]:
    """Extract timeline events from a FRECE custody database."""
    if not db_path.exists():
        return []

    events: list[TimelineEvent] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT event_type, evidence_id, operator, timestamp, details"
            " FROM custody_log ORDER BY id"
        )
        for event_type, evidence_id, operator, timestamp, details_json in cursor.fetchall():
            epoch = _iso_to_epoch(timestamp)
            try:
                details = json.loads(details_json) if details_json else {}
            except Exception:
                details = {}
            notes = f"operator={operator} evidence_id={evidence_id}"
            if details:
                notes += " " + " ".join(f"{k}={v}" for k, v in list(details.items())[:3])
            events.append(
                TimelineEvent(
                    timestamp=timestamp,
                    timestamp_epoch=epoch,
                    event_source="custody",
                    event_type=event_type.lower(),
                    artifact_path=evidence_id,
                    artifact_type="custody_event",
                    size_bytes=0,
                    inode=None,
                    notes=notes,
                )
            )
        conn.close()
    except Exception:
        pass

    return events


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def build_timeline(
    case_dir: Path,
    mactime_file: Optional[Path] = None,
) -> list[TimelineEvent]:
    """Synthesise a sorted timeline for a case directory.

    Automatically discovers recovery_manifest.json, carve_manifest.json and
    custody.db inside case_dir.  If a mactime_file (from fls -m output) is
    provided it is merged in as well.

    Returns events sorted oldest → newest.
    """
    events: list[TimelineEvent] = []

    # Mactime body file
    if mactime_file and mactime_file.exists():
        for line in mactime_file.read_text(encoding="utf-8", errors="replace").splitlines():
            events.extend(_events_from_mactime_line(line))

    # Recovery manifests
    for manifest_path in sorted(case_dir.rglob("recovery_manifest.json")):
        events.extend(_events_from_recovery_manifest(manifest_path))

    # Carve manifests
    for manifest_path in sorted(case_dir.rglob("carve_manifest.json")):
        events.extend(_events_from_carve_manifest(manifest_path))

    # Custody DB
    db_path = case_dir / "custody.db"
    events.extend(_events_from_custody_db(db_path))

    # Sort by epoch, then by source for stability
    events.sort(key=lambda e: (e.timestamp_epoch, e.event_source))

    return events


def events_to_json(events: list[TimelineEvent]) -> str:
    """Serialise timeline events to a JSON string."""
    return json.dumps(
        [asdict(e) for e in events],
        indent=2,
        ensure_ascii=False,
    )


def events_to_csv(events: list[TimelineEvent]) -> str:
    """Serialise timeline events to a CSV string."""
    buf = io.StringIO()
    if not events:
        return ""
    fieldnames = list(asdict(events[0]).keys())
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for event in events:
        writer.writerow(asdict(event))
    return buf.getvalue()


def events_to_text(events: list[TimelineEvent]) -> str:
    """Human-readable table suitable for terminal output."""
    if not events:
        return "No timeline events found.\n"
    lines = [
        f"{'TIMESTAMP':<28} {'SOURCE':<12} {'TYPE':<16} {'ARTIFACT':<40} {'CATEGORY':<12} SIZE",
        "-" * 120,
    ]
    for e in events:
        ts = e.timestamp[:26] if e.timestamp else "(no time)"
        artifact = e.artifact_path
        if len(artifact) > 40:
            artifact = "…" + artifact[-38:]
        lines.append(
            f"{ts:<28} {e.event_source:<12} {e.event_type:<16} "
            f"{artifact:<40} {e.artifact_type:<12} {e.size_bytes}"
        )
    return "\n".join(lines) + "\n"
