# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Cross-platform Trash / Recycle-Bin recovery.

Deleting a file in a desktop file manager does not erase it — it is moved into a
per-platform trash store. FRECE understands all three of the common layouts and
exposes them through one command (``frece trash``):

* **Linux (freedesktop.org):** ``~/.local/share/Trash`` (and per-volume
  ``.Trash-<uid>`` / ``.Trash/<uid>``) with ``files/`` payloads and
  ``info/*.trashinfo`` records (original path + deletion time).
* **Windows ($Recycle.Bin):** ``<vol>:\\$Recycle.Bin\\<SID>\\`` with paired
  ``$I######.ext`` (metadata: version, size, FILETIME, original path) and
  ``$R######.ext`` (the file content).
* **macOS:** ``~/.Trash`` and volume ``.Trashes/<uid>`` hold the files directly
  (no sidecar; the deletion time is taken from the file's mtime).

For files *emptied* from the trash (unlinked at the filesystem layer), use
``frece recover`` / ``frece scan`` against the device or image instead.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import struct
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from .errors import RecoveryError

try:  # python-magic is a declared dependency, but degrade gracefully.
    import magic as _magic
except Exception:  # pragma: no cover - defensive
    _magic = None  # type: ignore[assignment]

_WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _basename(path_str: str) -> str:
    """Final component of a path that may use POSIX '/' or Windows '\\' separators."""
    return re.split(r"[\\/]", path_str)[-1] or path_str


_UNSAFE_NAMES = {"", ".", ".."}


def _safe_output_name(raw: str, fallback: str) -> str:
    """Return a safe single-component filename (no separators, no traversal).

    Trash records come from *untrusted evidence*; a crafted original path such as
    ``../../etc/cron.d/x`` or an absolute path must never let a recovered file
    escape the chosen output directory.
    """
    name = _basename(raw).replace("\x00", "").strip()
    name = "".join(ch for ch in name if ch.isprintable())
    if name in _UNSAFE_NAMES or name.startswith(".."):
        return fallback
    return name


def _has_traversal(path_str: str) -> bool:
    """True if a path contains a null byte or a ``..`` component (either separator)."""
    if "\x00" in path_str:
        return True
    return ".." in re.split(r"[\\/]", path_str)


def _trash_root_of(rel_path: str) -> Optional[str]:
    """Given a file path inside an image, return its enclosing trash-store root."""
    parts = rel_path.split("/")
    low = [p.lower() for p in parts]
    for i, part in enumerate(low):
        if part == "$recycle.bin" and i + 1 < len(parts):
            return "/".join(parts[: i + 2])  # $Recycle.Bin/<SID>
    for i, part in enumerate(low):
        if part == "trash" and i >= 1 and low[i - 1] == "share":
            return "/".join(parts[: i + 1])  # .local/share/Trash
        if part.startswith(".trash-"):
            return "/".join(parts[: i + 1])  # .Trash-<uid>
        if part == ".trashes" and i + 1 < len(parts):
            return "/".join(parts[: i + 2])  # .Trashes/<uid>
        if part == ".trash":
            return "/".join(parts[: i + 1])  # macOS ~/.Trash
    return None


def _filetime_to_iso(filetime: int) -> Optional[str]:
    """Convert a Windows FILETIME (100 ns ticks since 1601) to an ISO string."""
    if not filetime:
        return None
    try:
        moment = _WINDOWS_EPOCH + timedelta(microseconds=filetime / 10)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _mtime_to_iso(path: Path) -> Optional[str]:
    try:
        return (
            datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except OSError:
        return None


@dataclass
class TrashedFile:
    """A single entry recovered from any kind of trash store."""

    trash_name: str
    original_path: Optional[str]
    deletion_date: Optional[str]
    size: int
    sha256: str
    file_type: str
    is_dir: bool
    trash_dir: str
    files_path: str
    info_path: Optional[str]
    has_info: bool
    source_type: str = "freedesktop"  # freedesktop | windows | macos
    recovered_to: str = ""
    artifact_metadata: dict = field(default_factory=dict)


def parse_trashinfo(info_path: Path) -> tuple[Optional[str], Optional[str]]:
    """Parse a freedesktop ``.trashinfo`` → (original_path, deletion_date)."""
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


def parse_windows_index(data: bytes) -> Optional[dict]:
    """Parse a Windows ``$I`` metadata record (v1 and v2/Win10 layouts)."""
    if len(data) < 24:
        return None
    version, size, filetime = struct.unpack_from("<QQQ", data, 0)
    if version == 2 and len(data) >= 28:
        (nchars,) = struct.unpack_from("<I", data, 24)
        raw = data[28 : 28 + max(0, nchars) * 2]
    else:  # version 1: fixed 260-wchar (520-byte) path field
        raw = data[24 : 24 + 520]
    original_path = raw.decode("utf-16-le", errors="replace").split("\x00")[0] or None
    return {
        "original_path": original_path,
        "size": size,
        "deletion_date": _filetime_to_iso(filetime),
    }


class TrashRecovery:
    """Discover, list, and restore files from any supported trash store."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger("frece.trash")

    # ── classification ───────────────────────────────────────────────
    @staticmethod
    def _trash_kind(path: Path) -> Optional[str]:
        """Return 'freedesktop' | 'windows' | 'macos' | None for *path*."""
        if not path.is_dir():
            return None
        if (path / "files").is_dir() or (path / "info").is_dir():
            return "freedesktop"
        try:
            entries = list(path.iterdir())
        except OSError:
            return None
        if any(entry.is_file() and entry.name.startswith("$I") for entry in entries):
            return "windows"
        if path.name == ".Trash" or path.parent.name == ".Trashes":
            return "macos"
        return None

    @staticmethod
    def _mount_points() -> list[Path]:
        mounts: list[Path] = []
        try:
            with open("/proc/mounts", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2:
                        mounts.append(Path(parts[1].replace("\\040", " ")))
        except OSError:
            pass
        return mounts

    def _collect_under(self, root: Path, uid: int) -> list[Path]:
        """Find per-volume trash dirs (all three layouts) directly under *root*."""
        found: list[Path] = []
        for candidate in (root / f".Trash-{uid}", root / ".Trash" / str(uid)):
            if self._trash_kind(candidate) == "freedesktop":
                found.append(candidate)
        trashes = root / ".Trashes"
        if trashes.is_dir():
            try:
                found.extend(d for d in trashes.iterdir() if d.is_dir())
            except OSError:
                pass
        recycle_bin = root / "$Recycle.Bin"
        if recycle_bin.is_dir():
            try:
                found.extend(d for d in recycle_bin.iterdir() if d.is_dir())
            except OSError:
                pass
        return found

    def discover_trash_dirs(
        self, explicit: Optional[Path] = None, uid: Optional[int] = None
    ) -> list[Path]:
        """Locate every trash directory we should inspect."""
        uid = os.getuid() if uid is None else uid

        if explicit is not None:
            explicit = Path(explicit)
            if self._trash_kind(explicit):
                return [explicit]
            found: list[Path] = []
            # treat *explicit* as a user home …
            fd_home = explicit / ".local/share/Trash"
            if self._trash_kind(fd_home):
                found.append(fd_home)
            mac_home = explicit / ".Trash"
            if self._trash_kind(mac_home) == "macos":
                found.append(mac_home)
            # … or a volume root …
            found.extend(self._collect_under(explicit, uid))
            # … or a mounted-image root containing user homes.
            for base in (explicit / "home", explicit / "Users"):
                if base.is_dir():
                    try:
                        user_dirs = [d for d in base.iterdir() if d.is_dir()]
                    except OSError:
                        user_dirs = []
                    for user_dir in user_dirs:
                        for candidate in (user_dir / ".local/share/Trash", user_dir / ".Trash"):
                            if self._trash_kind(candidate):
                                found.append(candidate)
            return list(dict.fromkeys(found))

        dirs: list[Path] = []
        xdg = os.environ.get("XDG_DATA_HOME")
        fd_home = Path(xdg) / "Trash" if xdg else Path.home() / ".local/share/Trash"
        if self._trash_kind(fd_home):
            dirs.append(fd_home)
        mac_home = Path.home() / ".Trash"
        if self._trash_kind(mac_home) == "macos":
            dirs.append(mac_home)
        for mount in self._mount_points():
            dirs.extend(self._collect_under(mount, uid))
        return list(dict.fromkeys(dirs))

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
        return path.suffix.lstrip(".").lower() or "unknown"

    def _entry(self, content: Path, **kwargs) -> TrashedFile:
        sha256, size = self._hash_and_size(content)
        declared_size = kwargs.pop("declared_size", None)
        params = dict(
            trash_name=content.name,
            original_path=None,
            deletion_date=None,
            size=size,
            sha256=sha256,
            file_type=self._detect_type(content),
            is_dir=content.is_dir(),
            trash_dir=str(content.parent),
            files_path=str(content),
            info_path=None,
            has_info=False,
            source_type="freedesktop",
        )
        params.update(kwargs)
        entry = TrashedFile(**params)  # type: ignore[arg-type]
        if declared_size is not None and declared_size != size:
            entry.artifact_metadata["declared_size"] = declared_size
        return entry

    # ── per-format listing ───────────────────────────────────────────
    def _list_freedesktop(self, trash_dir: Path) -> list[TrashedFile]:
        results: list[TrashedFile] = []
        files_dir = trash_dir / "files"
        info_dir = trash_dir / "info"
        if not files_dir.is_dir():
            return results
        for entry in sorted(files_dir.iterdir()):
            info_path = info_dir / f"{entry.name}.trashinfo"
            has_info = info_path.is_file()
            original_path, deletion_date = parse_trashinfo(info_path) if has_info else (None, None)
            results.append(
                self._entry(
                    entry,
                    trash_dir=str(trash_dir),
                    original_path=original_path,
                    deletion_date=deletion_date,
                    info_path=str(info_path) if has_info else None,
                    has_info=has_info,
                    source_type="freedesktop",
                )
            )
        return results

    def _list_windows(self, trash_dir: Path) -> list[TrashedFile]:
        results: list[TrashedFile] = []
        try:
            entries = sorted(trash_dir.iterdir())
        except OSError:
            return results
        for index_file in entries:
            if not (index_file.is_file() and index_file.name.startswith("$I")):
                continue
            content = trash_dir / ("$R" + index_file.name[2:])
            meta = parse_windows_index(index_file.read_bytes()) or {}
            if not content.exists():
                self.logger.warning("Windows $R content missing for %s", index_file.name)
                continue
            results.append(
                self._entry(
                    content,
                    trash_dir=str(trash_dir),
                    original_path=meta.get("original_path"),
                    deletion_date=meta.get("deletion_date"),
                    info_path=str(index_file),
                    has_info=True,
                    source_type="windows",
                    declared_size=meta.get("size"),
                )
            )
        return results

    def _list_macos(self, trash_dir: Path) -> list[TrashedFile]:
        results: list[TrashedFile] = []
        try:
            entries = sorted(trash_dir.iterdir())
        except OSError:
            return results
        for entry in entries:
            if entry.name == ".DS_Store":
                continue
            results.append(
                self._entry(
                    entry,
                    trash_dir=str(trash_dir),
                    deletion_date=_mtime_to_iso(entry),
                    has_info=False,
                    source_type="macos",
                )
            )
        return results

    def list_trashed(self, trash_dirs: list[Path]) -> list[TrashedFile]:
        """Enumerate every entry across the given trash directories."""
        results: list[TrashedFile] = []
        for trash_dir in trash_dirs:
            kind = self._trash_kind(trash_dir)
            if kind == "freedesktop":
                results.extend(self._list_freedesktop(trash_dir))
            elif kind == "windows":
                results.extend(self._list_windows(trash_dir))
            elif kind == "macos":
                results.extend(self._list_macos(trash_dir))
        return results

    # ── recovery ─────────────────────────────────────────────────────
    @staticmethod
    def _unique_destination(dest: Path) -> Path:
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
        """Recover trashed *entries* (forensic copy by default)."""
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
                if _has_traversal(entry.original_path):
                    self.logger.warning(
                        "Refusing unsafe original path (traversal): %s", entry.original_path
                    )
                    continue
                dest = self._unique_destination(Path(entry.original_path))
                dest.parent.mkdir(parents=True, exist_ok=True)
            else:
                fallback = entry.trash_name or "recovered.bin"
                base = _safe_output_name(entry.original_path or entry.trash_name, fallback)
                target_dir = output_dir or Path(".")
                dest = self._unique_destination(target_dir / base)
                # defence in depth: never let a destination escape the output dir
                try:
                    out_real = os.path.realpath(target_dir)
                    if os.path.commonpath([out_real, os.path.realpath(dest)]) != out_real:
                        self.logger.warning(
                            "Refusing out-of-bounds destination for %s", entry.trash_name
                        )
                        continue
                except (OSError, ValueError):
                    continue

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

    # ── image extraction (Sleuth Kit) ────────────────────────────────
    @staticmethod
    def _require_sleuthkit() -> None:
        missing = [tool for tool in ("fls", "icat") if shutil.which(tool) is None]
        if missing:
            raise RecoveryError(
                f"The Sleuth Kit tools not found: {missing}",
                remediation="Install The Sleuth Kit: apt-get install sleuthkit",
            )

    def _fls_walk(self, image: Path, offset: int, timeout: int):
        """Yield (inode_token, path) for every file in *image* via ``fls -F -r -p``."""
        command = ["fls", "-F", "-r", "-p"]
        if offset:
            command += ["-o", str(offset)]
        command += [str(image)]
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=(timeout or None), check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise RecoveryError(
                "fls timed out walking the image",
                remediation="Increase --timeout or verify the image is readable",
            ) from exc
        for line in proc.stdout.splitlines():
            if "\t" not in line:
                continue
            meta, path = line.split("\t", 1)
            fields = meta.split()
            if not fields:
                continue
            idx = 1
            if idx < len(fields) and fields[idx] == "*":  # '*' marks a deleted entry
                idx += 1
            if idx >= len(fields):
                continue
            yield fields[idx].rstrip(":"), path

    def _icat_to_file(
        self, image: Path, offset: int, token: str, dest: Path, timeout: int
    ) -> bool:
        command = ["icat"]
        if offset:
            command += ["-o", str(offset)]
        command += [str(image), token]
        try:
            with open(dest, "wb") as handle:
                proc = subprocess.run(
                    command, stdout=handle, stderr=subprocess.PIPE,
                    timeout=(timeout or None), check=False,
                )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError) as exc:
            self.logger.warning("icat failed for %s: %s", token, exc)
            return False

    def extract_trash_from_image(
        self, image: Path, staging_dir: Path, offset: int = 0, timeout: int = 0
    ) -> list[Path]:
        """Extract every trash store from a raw/NTFS/ext image to *staging_dir*.

        Uses The Sleuth Kit (no mount) so a `.dd`/raw image of a Windows, Linux,
        or macOS-ish volume can be triaged directly. Returns the staged trash
        directories, ready for :meth:`list_trashed`.
        """
        self._require_sleuthkit()
        image = Path(image)
        staging_dir = Path(staging_dir)
        staging_real = os.path.realpath(staging_dir)
        roots: list[Path] = []
        seen: set[str] = set()

        for token, rel in self._fls_walk(image, offset, timeout):
            root_rel = _trash_root_of(rel)
            if root_rel is None or _has_traversal(rel):
                continue
            dest = staging_dir / rel
            try:  # confine extraction strictly within the staging dir
                if os.path.commonpath(
                    [staging_real, os.path.realpath(dest.parent)]
                ) != staging_real and dest.parent.exists():
                    continue
            except (OSError, ValueError):
                pass
            dest.parent.mkdir(parents=True, exist_ok=True)
            if self._icat_to_file(image, offset, token, dest, timeout):
                staged_root = staging_dir / root_rel
                if str(staged_root) not in seen:
                    seen.add(str(staged_root))
                    roots.append(staged_root)
        return roots

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
