# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Freedesktop.org Trash recovery.

On Linux, deleting a file in a file manager does *not* erase it — the file is
moved into a Trash directory (per the freedesktop.org Trash specification)
together with a ``.trashinfo`` record describing its original path and the
moment it was deleted. This module discovers those trash locations, lists their
contents with full forensic context, and restores them.

For files that were *emptied* from the trash (unlinked at the filesystem
layer), use ``frece recover`` / ``frece scan`` against the device or image — the
data is then recovered with The Sleuth Kit, not from here.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from .errors import RecoveryError

try:  # python-magic is a declared dependency, but degrade gracefully.
    import magic as _magic
except Exception:  # pragma: no cover - defensive
    _magic = None  # type: ignore[assignment]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class TrashedFile:
    """A single entry recovered from a Trash directory."""

    trash_name: str  # basename inside <trash>/files
    original_path: Optional[str]  # decoded Path= from .trashinfo
    deletion_date: Optional[str]  # DeletionDate= from .trashinfo
    size: int
    sha256: str
    file_type: str
    is_dir: bool
    trash_dir: str
    files_path: str
    info_path: Optional[str]
    has_info: bool
    recovered_to: str = ""
    artifact_metadata: dict = field(default_factory=dict)


def parse_trashinfo(info_path: Path) -> tuple[Optional[str], Optional[str]]:
    """Parse a ``.trashinfo`` file → (original_path, deletion_date).

    The ``Path`` value is URL-encoded per the spec; it is decoded here.
    """
    original_path: Optional[str] = None
    deletion_date: Optional[str] = None
    try:
        text = info_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None

    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped.lower() == "[trash info]"
            continue
        if not in_section:
            continue
        lowered = stripped.lower()
        if lowered.startswith("path="):
            original_path = unquote(stripped[len("path="):])
        elif lowered.startswith("deletiondate="):
            deletion_date = stripped[len("deletiondate="):]
    return original_path, deletion_date


class TrashRecovery:
    """Discover, list, and restore files from freedesktop Trash directories."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger("frece.trash")

    # ── discovery ────────────────────────────────────────────────────
    @staticmethod
    def _is_trash_dir(path: Path) -> bool:
        return (path / "files").is_dir() or (path / "info").is_dir()

    @staticmethod
    def _mount_points() -> list[Path]:
        mounts: list[Path] = []
        try:
            with open("/proc/mounts", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2:
                        mount = parts[1].replace("\\040", " ")
                        mounts.append(Path(mount))
        except OSError:
            pass
        return mounts

    def discover_trash_dirs(
        self, explicit: Optional[Path] = None, uid: Optional[int] = None
    ) -> list[Path]:
        """Return every Trash directory we should inspect.

        With *explicit* set, treat it as a Trash dir (or a directory that
        contains one) and do not auto-discover. Otherwise locate the home trash
        and per-volume trashes (``.Trash-<uid>`` / ``.Trash/<uid>``).
        """
        if explicit is not None:
            explicit = Path(explicit)
            if self._is_trash_dir(explicit):
                return [explicit]
            # A path that *contains* trash dirs (e.g. a mounted image root).
            found: list[Path] = []
            for candidate in (
                explicit / ".local/share/Trash",
                explicit / "Trash",
            ):
                if self._is_trash_dir(candidate):
                    found.append(candidate)
            for child in explicit.glob(".Trash*"):
                if self._is_trash_dir(child):
                    found.append(child)
                elif child.is_dir():  # .Trash/<uid>
                    found.extend(d for d in child.iterdir() if self._is_trash_dir(d))
            return found

        uid = os.getuid() if uid is None else uid
        dirs: list[Path] = []

        xdg = os.environ.get("XDG_DATA_HOME")
        home_trash = Path(xdg) / "Trash" if xdg else Path.home() / ".local/share/Trash"
        if self._is_trash_dir(home_trash):
            dirs.append(home_trash)

        for mount in self._mount_points():
            for candidate in (mount / f".Trash-{uid}", mount / ".Trash" / str(uid)):
                if self._is_trash_dir(candidate) and candidate not in dirs:
                    dirs.append(candidate)
        return dirs

    # ── helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _hash_and_size(path: Path) -> tuple[str, int]:
        """Return (sha256, size) for a file, or ("", recursive_size) for a dir."""
        if path.is_dir():
            total = 0
            for root, _dirs, names in os.walk(path):
                for name in names:
                    try:
                        total += (Path(root) / name).stat().st_size
                    except OSError:
                        pass
            return "", total
        sha = hashlib.sha256()
        size = 0
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    sha.update(chunk)
                    size += len(chunk)
        except OSError:
            return "", 0
        return sha.hexdigest(), size

    @staticmethod
    def _detect_type(path: Path) -> str:
        if path.is_dir():
            return "directory"
        if _magic is not None:
            try:
                return _magic.from_file(str(path), mime=True) or "application/octet-stream"
            except Exception:
                pass
        suffix = path.suffix.lstrip(".").lower()
        return suffix or "unknown"

    # ── listing ──────────────────────────────────────────────────────
    def list_trashed(self, trash_dirs: list[Path]) -> list[TrashedFile]:
        """Enumerate every entry across the given trash directories."""
        results: list[TrashedFile] = []
        for trash_dir in trash_dirs:
            files_dir = trash_dir / "files"
            info_dir = trash_dir / "info"
            if not files_dir.is_dir():
                continue
            for entry in sorted(files_dir.iterdir()):
                info_path = info_dir / f"{entry.name}.trashinfo"
                has_info = info_path.is_file()
                original_path, deletion_date = (
                    parse_trashinfo(info_path) if has_info else (None, None)
                )
                sha256, size = self._hash_and_size(entry)
                results.append(
                    TrashedFile(
                        trash_name=entry.name,
                        original_path=original_path,
                        deletion_date=deletion_date,
                        size=size,
                        sha256=sha256,
                        file_type=self._detect_type(entry),
                        is_dir=entry.is_dir(),
                        trash_dir=str(trash_dir),
                        files_path=str(entry),
                        info_path=str(info_path) if has_info else None,
                        has_info=has_info,
                    )
                )
        return results

    # ── recovery ─────────────────────────────────────────────────────
    @staticmethod
    def _unique_destination(dest: Path) -> Path:
        """Avoid clobbering an existing destination by suffixing ``_N``."""
        if not dest.exists():
            return dest
        stem, suffix = dest.stem, dest.suffix
        counter = 1
        while True:
            candidate = dest.with_name(f"{stem}_{counter}{suffix}")
            if not candidate.exists():
                return candidate
            counter += 1

    def recover(
        self,
        entries: list[TrashedFile],
        output_dir: Optional[Path] = None,
        to_original: bool = False,
    ) -> list[TrashedFile]:
        """Recover trashed *entries*.

        Default (forensic): COPY each item into *output_dir*, leaving the trash
        intact as evidence. With *to_original* the item is moved back to its
        recorded original location (a true "restore from trash").
        """
        if not to_original and output_dir is None:
            raise RecoveryError(
                "No recovery destination given",
                remediation="Pass --output <dir> or use --to-original",
            )
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)

        recovered: list[TrashedFile] = []
        for entry in entries:
            source = Path(entry.files_path)
            if not source.exists():
                self.logger.warning("Trash entry missing on disk: %s", source)
                continue

            if to_original and entry.original_path:
                dest = self._unique_destination(Path(entry.original_path))
                dest.parent.mkdir(parents=True, exist_ok=True)
            else:
                base = Path(entry.original_path).name if entry.original_path else entry.trash_name
                dest = self._unique_destination((output_dir or Path(".")) / base)

            try:
                if to_original:
                    shutil.move(str(source), str(dest))
                    if entry.info_path and Path(entry.info_path).exists():
                        Path(entry.info_path).unlink()
                elif source.is_dir():
                    shutil.copytree(source, dest)
                else:
                    shutil.copy2(source, dest)
            except (OSError, shutil.Error) as exc:
                self.logger.error("Failed to recover %s: %s", source, exc)
                continue

            entry.recovered_to = str(dest)
            recovered.append(entry)
        return recovered

    # ── manifest ─────────────────────────────────────────────────────
    def build_report(
        self, entries: list[TrashedFile], trash_dirs: list[Path], mode: str
    ) -> dict:
        return {
            "tool": "frece trash",
            "mode": mode,
            "timestamp": _utc_now_iso(),
            "trash_dirs": [str(directory) for directory in trash_dirs],
            "total": len(entries),
            "entries": [asdict(entry) for entry in entries],
        }
