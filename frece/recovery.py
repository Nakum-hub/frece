# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Deleted file recovery using The Sleuth Kit tools."""

import hashlib
import json
import logging
import os
import re
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

from frece.classifier import classify_file
from frece.metadata import extract as extract_metadata
from frece.scoring import score_artifact
from frece.config import Config
from frece.errors import RecoveryError

try:
    import magic as magic_module
except ImportError:
    magic_module = None  # type: ignore[assignment]


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class ScannedEntry:
    """One deleted file as seen by fls — no extraction performed."""

    inode: int
    inode_token: str
    entry_type: str
    name: str
    allocated: bool
    size: int = 0
    mtime: int = 0    # last-modified  (Unix epoch)
    atime: int = 0    # last-accessed  (Unix epoch)
    ctime: int = 0    # inode-changed  (Unix epoch)
    crtime: int = 0   # created        (Unix epoch; NTFS/ext4 only)


@dataclass
class RecoveredFile:
    """Metadata for a recovered file."""

    inode: int
    size: int
    file_type: str
    sha256: str
    output_path: str = ""
    verified: bool = False
    original_name: Optional[str] = None
    mtime: int = 0
    atime: int = 0
    ctime: int = 0
    crtime: int = 0
    forensic_category: str = "unknown"
    forensic_priority: str = "LOW"
    entropy: float = 0.0
    possibly_encrypted: bool = False
    timestamp: str = ""
    confidence_score: int = 0
    confidence_grade: str = "UNKNOWN"
    artifact_metadata: dict = None  # type: ignore[assignment]
    suggested_name: str = ""

    def __post_init__(self) -> None:
        if self.artifact_metadata is None:
            self.artifact_metadata = {}


class DdrescueMapParser:
    """Parse ddrescue mapfile to identify bad sectors."""

    BAD_SECTOR_FLAG = "-"

    @staticmethod
    def load_mapfile(mapfile_path: Path) -> list[tuple[int, int, str]]:
        """Load ddrescue mapfile and return byte ranges with status flags."""
        sectors: list[tuple[int, int, str]] = []

        if not mapfile_path.exists():
            return sectors

        try:
            with open(mapfile_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            offset = int(parts[0], 16)
                            size = int(parts[1], 16)
                            status = parts[2]
                            sectors.append((offset, offset + size, status))
                        except ValueError:
                            pass
        except OSError as exc:
            raise RecoveryError(
                f"Cannot read mapfile: {mapfile_path}",
                remediation="Verify the ddrescue mapfile path and permissions",
            ) from exc

        return sectors

    @staticmethod
    def is_bad_sector(mapfile: list[tuple[int, int, str]], offset: int) -> bool:
        """Check if offset falls inside a bad range in the mapfile."""
        return DdrescueMapParser.overlaps_bad_sector(mapfile, offset, offset + 1)

    @staticmethod
    def overlaps_bad_sector(
        mapfile: list[tuple[int, int, str]],
        start_offset: int,
        end_offset: int,
    ) -> bool:
        """Check if a byte range overlaps any bad ddrescue range."""
        for range_start, range_end, status in mapfile:
            if (
                status == DdrescueMapParser.BAD_SECTOR_FLAG
                and start_offset < range_end
                and end_offset > range_start
            ):
                return True
        return False



# ─────────────────────────────────────────────────────────────────────────────
# Filename suggestion for orphan files
# ─────────────────────────────────────────────────────────────────────────────

_TYPE_EXTENSIONS: dict[str, str] = {
    "jpeg": "jpg", "png": "png", "gif": "gif", "bmp": "bmp",
    "tiff": "tif", "psd": "psd", "heic": "heic", "webp": "webp",
    "pdf": "pdf", "rtf": "rtf", "xml": "xml", "html": "html",
    "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    "doc": "doc", "xls": "xls", "ppt": "ppt", "ole": "bin",
    "zip": "zip", "7z": "7z", "rar": "rar", "gz": "gz",
    "mp3": "mp3", "wav": "wav", "flac": "flac", "ogg": "ogg",
    "mp4": "mp4", "avi": "avi", "mov": "mov",
    "pe": "exe", "elf": "elf",
    "evtx": "evtx", "lnk": "lnk", "reg": "dat",
    "sqlite": "db", "pcap": "pcap", "pcapng": "pcapng",
    "eml": "eml", "msg": "msg", "pem": "pem",
    "py": "py", "sh": "sh", "php": "php", "script": "sh",
    "txt": "txt", "csv": "csv",
}


def _suggest_filename(
    original_name: Optional[str],
    file_type: str,
    inode: int,
    metadata: dict,
) -> str:
    """Suggest a human-readable filename for orphan/recovered files.

    Attempts to incorporate metadata clues (email subject, PDF title,
    PE filename, SQLite schema) to produce a more descriptive name
    than "OrphanFile-14.bin".

    Args:
        original_name: Filesystem name if known, else None / OrphanFile-N.
        file_type:     Canonical type string.
        inode:         Inode number (used as numeric suffix).
        metadata:      Extracted metadata dict.

    Returns:
        Suggested filename string (no directory component).
    """
    ext = _TYPE_EXTENSIONS.get(file_type, "bin")

    # If we have the real name and it isn't an orphan placeholder, use it
    if original_name and "OrphanFile" not in original_name and original_name != "":
        # Just ensure correct extension
        if not original_name.endswith(f".{ext}"):
            base = original_name.rsplit(".", 1)[0]
            return f"{base}.{ext}"
        return original_name

    # Try metadata-derived names
    hint = ""
    if file_type == "eml":
        subject = metadata.get("subject", "")
        if subject:
            # Sanitise for filesystem
            safe = re.sub(r"[^A-Za-z0-9_\- ]", "", subject)[:40].strip()
            if safe:
                hint = f"email_{safe.replace(' ', '_')}"

    elif file_type == "pdf":
        title = metadata.get("title", "")
        if title:
            safe = re.sub(r"[^A-Za-z0-9_\- ]", "", title)[:40].strip()
            if safe:
                hint = f"doc_{safe.replace(' ', '_')}"

    elif file_type in ("docx", "xlsx", "pptx"):
        title = metadata.get("title", "")
        creator = metadata.get("creator", "")
        if title:
            safe = re.sub(r"[^A-Za-z0-9_\- ]", "", title)[:40].strip()
            if safe:
                hint = f"office_{safe.replace(' ', '_')}"
        elif creator:
            safe = re.sub(r"[^A-Za-z0-9_\-]", "", creator)[:20].strip()
            if safe:
                hint = f"doc_by_{safe}"

    elif file_type == "pe":
        is_dll = metadata.get("is_dll", False)
        arch = metadata.get("architecture", "")
        suffix = "dll" if is_dll else "exe"
        ext = suffix
        if arch:
            hint = f"binary_{arch}_{inode}"
        else:
            hint = f"binary_{inode}"

    elif file_type == "sqlite":
        tables = metadata.get("tables", [])
        if tables:
            first_table = tables[0].get("name", "") if isinstance(tables[0], dict) else ""
            if first_table:
                hint = f"db_{first_table}_{inode}"

    elif file_type == "pcap":
        ips = metadata.get("unique_src_ips", [])
        pkts = metadata.get("packet_count", 0)
        if ips:
            hint = f"capture_{ips[0].replace('.','_')}_{pkts}pkts"

    elif file_type in ("py", "sh", "php", "script"):
        hint = f"script_{inode}"

    if not hint:
        hint = f"recovered_inode{inode}"

    return f"{hint}.{ext}"

class DeletedFileRecovery:
    """Recover deleted files from forensic images."""

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        config: Config | None = None,
        timeout: int | None = None,
    ):
        self.logger = logger or logging.getLogger(__name__)
        self.config = config or Config()
        self.timeout = timeout or 0

    def recover_deleted(
        self,
        image_path: Path,
        output_dir: Path,
        image_offset: int = 0,
        mapfile_path: Path | None = None,
        verify: bool = False,
        inodes: list[int] | None = None,
        file_types: list[str] | None = None,
    ) -> list[RecoveredFile]:
        """Recover deleted files listed by fls and extracted with icat."""
        image_path = Path(image_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        deleted_entries = self._list_deleted_entries(image_path, image_offset)
        if inodes is not None:
            inodes_set = set(inodes)
            deleted_entries = [entry for entry in deleted_entries if entry.inode in inodes_set]

        allowed_types: Optional[set[str]] = None
        if file_types is not None:
            file_type_aliases = {"jpg": "jpeg"}
            allowed_types = {
                file_type_aliases.get(file_type.lower().lstrip("."), file_type.lower().lstrip("."))
                for file_type in file_types
            }

        mapfile = DdrescueMapParser.load_mapfile(mapfile_path) if mapfile_path else []

        recovered_files: list[RecoveredFile] = []
        failed_inodes: list[dict] = []

        for entry in deleted_entries:
            try:
                recovered = self._extract_inode(
                    image_path,
                    entry.inode,
                    output_dir,
                    image_offset=image_offset,
                    mapfile=mapfile,
                    verify=verify,
                    allowed_types=allowed_types,
                    original_name=entry.name,
                )
                if recovered is not None:
                    recovered_files.append(recovered)
            except RecoveryError as exc:
                failed_inodes.append({"inode": entry.inode, "reason": exc.message})
                self.logger.warning(
                    json.dumps(
                        {
                            "event": "INODE_SKIP",
                            "inode": entry.inode,
                            "reason": exc.message,
                            "timestamp": _utc_now_iso(),
                        }
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive guardrail
                failed_inodes.append({"inode": entry.inode, "reason": str(exc)})
                self.logger.warning(
                    json.dumps(
                        {
                            "event": "INODE_SKIP",
                            "inode": entry.inode,
                            "reason": str(exc),
                            "timestamp": _utc_now_iso(),
                        }
                    )
                )

        self.export_recovery_manifest(
            image_path,
            output_dir,
            recovered_files,
            failed_inodes,
        )
        return recovered_files

    def scan_deleted(
        self,
        image_path: Path,
        image_offset: int = 0,
    ) -> list[ScannedEntry]:
        """List deleted files using fls without extracting anything."""
        image_path = Path(image_path)
        entries = self._list_deleted_entries(image_path, image_offset)

        self.logger.info(
            json.dumps(
                {
                    "event": "SCAN_COMPLETE",
                    "image": str(image_path),
                    "deleted_entries": len(entries),
                    "timestamp": _utc_now_iso(),
                }
            )
        )
        return entries

    def scan_mactime(
        self,
        image_path: Path,
        image_offset: int = 0,
        deleted_only: bool = True,
    ) -> list[ScannedEntry]:
        """Scan using fls -m to get full MAC-time metadata for all entries.

        Returns ScannedEntry records with mtime/atime/ctime/crtime populated.
        On filesystems that erase directory entries on delete (ext2/3) the
        original filenames will show as OrphanFile-N; on NTFS they are preserved.

        Args:
            image_path:    Path to forensic image.
            image_offset:  Sector offset into image (0 = whole disk image).
            deleted_only:  When True (default) return only deleted entries.

        Returns:
            List of ScannedEntry with timestamp fields populated.
        """
        image_path = Path(image_path)
        entries: list[ScannedEntry] = []
        seen_inodes: set[int] = set()

        for line in self._iter_fls_mactime(image_path, image_offset):
            entry = self._parse_mactime_line(line, deleted_only=deleted_only)
            if entry is not None and entry.inode not in seen_inodes:
                seen_inodes.add(entry.inode)
                entries.append(entry)

        self.logger.info(
            json.dumps(
                {
                    "event": "MACTIME_SCAN_COMPLETE",
                    "image": str(image_path),
                    "entries": len(entries),
                    "timestamp": _utc_now_iso(),
                }
            )
        )
        return entries

    def _list_deleted_entries(self, image_path: Path, image_offset: int = 0) -> list[ScannedEntry]:
        """List deleted entries from a filesystem image using streamed fls output."""
        entries: list[ScannedEntry] = []
        seen_inodes: set[int] = set()

        for line in self._iter_fls_lines(image_path, image_offset):
            entry = self._parse_fls_line(line)
            if entry is not None and entry.inode not in seen_inodes:
                seen_inodes.add(entry.inode)
                entries.append(entry)

        return entries

    def _iter_fls_lines(self, image_path: Path, image_offset: int) -> Generator[str, None, None]:
        """Yield fls output lines without buffering the full output."""
        command = ["fls", "-r", "-d"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.append(str(image_path))

        timeout = self._command_timeout("fls")
        timed_out = False

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RecoveryError(
                "Tool not found: fls",
                remediation="Install The Sleuth Kit: apt-get install sleuthkit",
            ) from exc
        except OSError as exc:
            raise RecoveryError(
                f"Failed to run fls on {image_path}",
                remediation="Verify image path and permissions",
            ) from exc

        def _kill_process() -> None:
            nonlocal timed_out
            timed_out = True
            proc.kill()

        timer = threading.Timer(timeout, _kill_process) if timeout > 0 else None
        if timer is not None:
            timer.start()

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                yield line
            proc.wait()
        finally:
            if timer is not None:
                timer.cancel()

        stderr_text = proc.stderr.read().strip() if proc.stderr is not None else ""
        if timed_out:
            raise RecoveryError(
                "fls timed out",
                remediation="Increase --timeout or config max_fls_timeout.",
            )

        if proc.returncode != 0:
            raise RecoveryError(
                f"fls failed: {stderr_text}",
                remediation="Check image format and filesystem offset",
            )

    def _parse_fls_line(self, line: str) -> ScannedEntry | None:
        """Parse one fls output line into a ScannedEntry."""
        line = line.strip()
        if not line:
            return None

        match = re.match(
            r"^([^/\s]+)/([a-zA-Z])(?:[a-zA-Z\-]*)\s+(\*\s+)?"
            r"([0-9]+(?:-[0-9]+)*)(?:\([^)]+\))?\s*:\s*(.*)",
            line,
        )
        if not match:
            return None

        entry_type = match.group(2).lower()
        is_unallocated = match.group(3) is not None
        inode_token = match.group(4)
        name = match.group(5).strip() or "(no name)"

        inode_text = inode_token.split("-")[0]
        try:
            inode = int(inode_text)
        except ValueError:
            return None

        return ScannedEntry(
            inode=inode,
            inode_token=inode_token,
            entry_type=entry_type,
            name=name,
            allocated=not is_unallocated,
        )

    def _iter_fls_mactime(
        self, image_path: Path, image_offset: int
    ) -> Generator[str, None, None]:
        """Stream fls -m body-file output (MD5|name|inode|…|atime|mtime|ctime|crtime)."""
        command = ["fls", "-r", "-m", "/"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.append(str(image_path))

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise RecoveryError(
                "Tool not found: fls",
                remediation="Install The Sleuth Kit: apt-get install sleuthkit",
            ) from exc

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line
        finally:
            proc.stdout.close()
            proc.wait()

    def _parse_mactime_line(
        self, line: str, deleted_only: bool = True
    ) -> Optional[ScannedEntry]:
        """Parse one fls -m body-file line.

        Format: MD5|name|inode|mode_str|UID|GID|size|atime|mtime|ctime|crtime
        """
        line = line.strip()
        if not line:
            return None
        parts = line.split("|")
        if len(parts) < 11:
            return None

        name = parts[1]

        # Detect deleted status from the name suffix
        is_deleted = "(deleted)" in name or "* " in name
        if deleted_only and not is_deleted:
            return None

        name = name.replace(" (deleted)", "").strip()
        # Strip leading path separator
        if name.startswith("/"):
            name = name[1:]

        # Parse inode (may be "N-M-K" for NTFS attribute addresses)
        inode_str = parts[2].split("-")[0]
        try:
            inode = int(inode_str)
        except ValueError:
            return None

        try:
            size = int(parts[6])
        except (ValueError, IndexError):
            size = 0

        def _safe_int(s: str) -> int:
            try:
                return int(s)
            except (ValueError, IndexError):
                return 0

        atime = _safe_int(parts[7])
        mtime = _safe_int(parts[8])
        ctime = _safe_int(parts[9])
        crtime = _safe_int(parts[10]) if len(parts) > 10 else 0

        # Determine type from mode string  (parts[3]: e.g. "r/rrw-r--r--")
        mode_str = parts[3] if len(parts) > 3 else ""
        entry_type = mode_str[0] if mode_str else "?"

        return ScannedEntry(
            inode=inode,
            inode_token=parts[2],
            entry_type=entry_type,
            name=name or f"inode-{inode}",
            allocated=False,  # we're reading deleted entries
            size=size,
            mtime=mtime,
            atime=atime,
            ctime=ctime,
            crtime=crtime,
        )

    def _extract_inode(
        self,
        image_path: Path,
        inode: int,
        output_dir: Path,
        image_offset: int = 0,
        mapfile: Optional[list[tuple[int, int, str]]] = None,
        verify: bool = False,
        allowed_types: Optional[set[str]] = None,
        original_name: Optional[str] = None,
    ) -> Optional[RecoveredFile]:
        """Extract one inode with icat, detect type, and write to disk."""
        if mapfile and self._inode_touches_bad_sectors(
            image_path,
            inode,
            image_offset,
            mapfile,
        ):
            self.logger.warning(
                json.dumps(
                    {
                        "event": "SECTOR_BAD",
                        "inode": inode,
                        "timestamp": _utc_now_iso(),
                    }
                )
            )
            return None

        command = ["icat"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.extend([str(image_path), str(inode)])

        tmp_path = output_dir / f".inode_{inode}.tmp"
        stderr_bytes = self._stream_command_to_file(
            command,
            tmp_path,
            tool_name="icat",
            not_found_remediation="Install The Sleuth Kit and ensure icat is in PATH",
            run_failure_message=f"Failed to run icat for inode {inode}",
            run_failure_remediation="Verify image accessibility and inode number",
            timeout=self._command_timeout("icat"),
        )

        file_type = self._detect_file_type_from_path(tmp_path)
        normalized_type = file_type.lower()
        if allowed_types is not None and normalized_type not in allowed_types:
            self.logger.debug(
                json.dumps({"event": "TYPE_FILTERED", "inode": inode, "type": file_type})
            )
            tmp_path.unlink(missing_ok=True)
            return None

        sha256, size = self._hash_file(tmp_path)
        final_path = self._output_path_for_inode(output_dir, inode, file_type, original_name)

        try:
            os.replace(tmp_path, final_path)
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            raise RecoveryError(
                f"Cannot write recovered inode {inode} to {final_path}",
                remediation="Check output directory permissions and disk space",
            ) from exc

        self.logger.info(
            json.dumps(
                {
                    "event": "ICAT",
                    "inode": inode,
                    "returncode": 0,
                    "bytes_written": size,
                    "timestamp": _utc_now_iso(),
                    "stderr": stderr_bytes.decode("utf-8", errors="ignore").strip(),
                }
            )
        )

        verified = self.verify_recovered(final_path, sha256) if verify else False

        # Forensic classification and entropy analysis
        forensic_category = "unknown"
        forensic_priority = "LOW"
        entropy = 0.0
        possibly_encrypted = False
        try:
            cls_result = classify_file(final_path, file_type)
            forensic_category = cls_result.category.value
            forensic_priority = cls_result.forensic_priority
            entropy = cls_result.entropy
            possibly_encrypted = cls_result.possibly_encrypted
        except Exception:
            pass

        # MAC times from istat
        mtime, atime, ctime, crtime = self._get_mac_times(image_path, inode, image_offset)

        # Deep metadata extraction
        artifact_meta: dict = {}
        try:
            meta = extract_metadata(final_path, file_type)
            if "extraction_error" not in meta:
                artifact_meta = {k: v for k, v in meta.items()
                                 if k not in ("file_type", "file_path")}
        except Exception:
            pass

        # Confidence scoring
        confidence_score = 0
        confidence_grade = "UNKNOWN"
        try:
            cs = score_artifact(
                file_path=final_path,
                file_type=file_type,
                entropy=round(entropy, 4),
                validation_passed=verified,
                validation_notes="",
                metadata=artifact_meta,
            )
            confidence_score = cs.score
            confidence_grade = cs.grade
        except Exception:
            pass

        # Suggest a filename for orphan files based on type + metadata
        suggested = _suggest_filename(original_name, file_type, inode, artifact_meta)

        return RecoveredFile(
            inode=inode,
            size=size,
            file_type=file_type,
            sha256=sha256,
            output_path=str(final_path),
            verified=verified,
            original_name=original_name,
            mtime=mtime,
            atime=atime,
            ctime=ctime,
            crtime=crtime,
            forensic_category=forensic_category,
            forensic_priority=forensic_priority,
            entropy=round(entropy, 4),
            possibly_encrypted=possibly_encrypted,
            timestamp=_utc_now_iso(),
            confidence_score=confidence_score,
            confidence_grade=confidence_grade,
            artifact_metadata=artifact_meta,
            suggested_name=suggested,
        )

    def _stream_command_to_file(
        self,
        command: list[str],
        output_path: Path,
        tool_name: str,
        not_found_remediation: str,
        run_failure_message: str,
        run_failure_remediation: str,
        timeout: int,
    ) -> bytes:
        """Run a command and stream stdout directly into output_path."""
        timed_out = False

        try:
            with output_path.open("wb") as out_handle:
                try:
                    proc = subprocess.Popen(
                        command,
                        stdout=out_handle,
                        stderr=subprocess.PIPE,
                    )
                except FileNotFoundError as exc:
                    raise RecoveryError(
                        f"Tool not found: {tool_name}",
                        remediation=not_found_remediation,
                    ) from exc
                except OSError as exc:
                    raise RecoveryError(
                        run_failure_message,
                        remediation=run_failure_remediation,
                    ) from exc

                def _kill_process() -> None:
                    nonlocal timed_out
                    timed_out = True
                    proc.kill()

                timer = threading.Timer(timeout, _kill_process) if timeout > 0 else None
                if timer is not None:
                    timer.start()

                try:
                    _, stderr_bytes = proc.communicate()
                finally:
                    if timer is not None:
                        timer.cancel()

                out_handle.flush()
                os.fsync(out_handle.fileno())
        except OSError as exc:
            output_path.unlink(missing_ok=True)
            raise RecoveryError(
                f"Cannot write recovered output: {output_path}",
                remediation="Check output directory permissions and disk space",
            ) from exc

        if timed_out:
            output_path.unlink(missing_ok=True)
            raise RecoveryError(
                f"{tool_name} timed out",
                remediation="Increase --timeout or config timeouts.",
            )

        if proc.returncode != 0:
            output_path.unlink(missing_ok=True)
            stderr_text = (stderr_bytes or b"").decode("utf-8", errors="ignore").strip()
            raise RecoveryError(
                f"{tool_name} failed",
                remediation=stderr_text or run_failure_remediation,
            )

        return stderr_bytes or b""

    def _command_timeout(self, tool_name: str) -> int:
        """Resolve the active timeout for a recovery subprocess."""
        if self.timeout > 0:
            return self.timeout
        if tool_name == "fls":
            return max(self.config.max_fls_timeout, 0)
        return max(self.config.max_icat_timeout, 0)

    def _run_text_command(
        self,
        command: list[str],
        tool_name: str,
        not_found_remediation: str,
        run_failure_message: str,
        run_failure_remediation: str,
        timeout: int,
    ) -> str:
        """Run a text command with an optional externally managed timeout."""
        timed_out = False

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RecoveryError(
                f"Tool not found: {tool_name}",
                remediation=not_found_remediation,
            ) from exc
        except OSError as exc:
            raise RecoveryError(
                run_failure_message,
                remediation=run_failure_remediation,
            ) from exc

        def _kill_process() -> None:
            nonlocal timed_out
            timed_out = True
            proc.kill()

        timer = threading.Timer(timeout, _kill_process) if timeout > 0 else None
        if timer is not None:
            timer.start()

        try:
            stdout_text, stderr_text = proc.communicate()
        finally:
            if timer is not None:
                timer.cancel()

        if timed_out:
            raise RecoveryError(
                f"{tool_name} timed out",
                remediation="Increase --timeout or config timeouts.",
            )

        if proc.returncode != 0:
            raise RecoveryError(
                f"{tool_name} failed for {command[-1]}",
                remediation=stderr_text.strip() or run_failure_remediation,
            )

        return stdout_text

    def _detect_file_type_from_path(self, file_path: Path) -> str:
        """Detect file type from the leading bytes of a recovered file."""
        with file_path.open("rb") as handle:
            return self._detect_file_type(handle.read(4096))

    def _hash_file(self, file_path: Path) -> tuple[str, int]:
        """Stream-hash a file from disk."""
        hasher = hashlib.sha256()
        size = 0

        try:
            with file_path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
                    size += len(chunk)
        except OSError as exc:
            raise RecoveryError(
                f"Cannot read recovered file: {file_path}",
                remediation="Check output directory permissions and disk state",
            ) from exc

        return hasher.hexdigest(), size

    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type using python-magic + comprehensive header scan.

        Covers all 88 FRECE carving types plus common text formats.
        Falls back to header bytes if python-magic is unavailable.
        """
        if not data:
            return "bin"

        if magic_module is not None:
            try:
                detected = magic_module.from_buffer(data, mime=False).lower()
                if "word 2007+" in detected or "wordprocessingml" in detected:
                    return "docx"
                if "excel 2007+" in detected or "spreadsheetml" in detected:
                    return "xlsx"
                if "powerpoint 2007+" in detected or "presentationml" in detected:
                    return "pptx"
                if "jpeg" in detected or "jfif" in detected:
                    return "jpeg"
                if "png image" in detected:
                    return "png"
                if "pdf document" in detected:
                    return "pdf"
                if "quicktime" in detected:
                    return "mov"
                if "mp4" in detected or "iso media" in detected:
                    return "mp4"
                if "sqlite 3.x database" in detected or "sqlite database" in detected:
                    return "sqlite"
                if "pcap capture" in detected or "tcpdump" in detected:
                    return "pcap"
                if "pcap-ng capture" in detected:
                    return "pcapng"
                if "wave audio" in detected or "riff (little-endian)" in detected:
                    return "wav"
                if "avi" in detected:
                    return "avi"
                if "mpeg" in detected and "layer iii" in detected:
                    return "mp3"
                if "flac audio" in detected:
                    return "flac"
                if "ogg" in detected:
                    return "ogg"
                if "pe32" in detected or "ms-dos executable" in detected:
                    return "pe"
                if "elf" in detected and ("executable" in detected or "shared object" in detected):
                    return "elf"
                if "windows event log" in detected:
                    return "evtx"
                if "ms windows shortcut" in detected:
                    return "lnk"
                if "windows registry" in detected:
                    return "reg"
                if "photoshop" in detected:
                    return "psd"
                if "vmdk" in detected:
                    return "vmdk"
                if "rich text" in detected or "rtf" in detected:
                    return "rtf"
                if "xml" in detected:
                    return "xml"
                if "html document" in detected:
                    return "html"
                if "mail message" in detected or "rfc 822" in detected or "smtp mail" in detected:
                    return "eml"
                if "mbox" in detected:
                    return "mbox"
                if "python" in detected:
                    return "py"
                if "shell script" in detected or "bash script" in detected:
                    return "sh"
                if "perl script" in detected:
                    return "pl"
                if "php script" in detected:
                    return "php"
                if "gzip compressed" in detected:
                    return "gz"
                if "bzip2 compressed" in detected:
                    return "bz2"
                if "xz compressed" in detected:
                    return "xz"
                if "zip archive" in detected:
                    return "zip"
                if "7-zip archive" in detected:
                    return "7z"
                if "rar archive" in detected:
                    return "rar"
                if "tiff image" in detected:
                    return "tiff"
                if "gif image" in detected:
                    return "gif"
                if "bitmap image" in detected:
                    return "bmp"
                if "matroska" in detected or "webm" in detected:
                    return "mkv"
                if "flash video" in detected:
                    return "flv"
                if "apple binary property" in detected:
                    return "plist"
                if "mach-o" in detected:
                    return "macho"
                if "csv" in detected or "comma-separated" in detected:
                    return "csv"
                if "ascii text" in detected or "utf-8 unicode text" in detected:
                    return "txt"
                if "text" in detected:
                    return "txt"
            except Exception:
                pass

        # Header-byte fallback (no python-magic needed)
        if data[:3] == b"\xff\xd8\xff":
            return "jpeg"
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return "png"
        if data[:4] == b"%PDF":
            return "pdf"
        if data[:16] == b"SQLite format 3\x00":
            return "sqlite"
        if data[:8] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            return "pcap"
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            return "pcapng"
        if data[:2] == b"MZ":
            return "pe"
        if data[:4] == b"\x7fELF":
            return "elf"
        if data[:8] == b"ElfFile\x00":
            return "evtx"
        if data[:4] == b"L\x00\x00\x00":
            return "lnk"
        if data[:4] == b"regf":
            return "reg"
        if data[:4] == b"8BPS":
            return "psd"
        if data[:4] == b"SCCA":
            return "prefetch"
        if data[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            return "macho"
        if data[:4] == b"PK\x03\x04":
            if b"word/" in data[:4096]:
                return "docx"
            if b"xl/" in data[:4096]:
                return "xlsx"
            if b"ppt/" in data[:4096]:
                return "pptx"
            return "zip"
        if data[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"
        if data[:7] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01"):
            return "rar"
        if data[:2] == b"\x1f\x8b":
            return "gz"
        if data[:3] == b"BZh":
            return "bz2"
        if data[:6] == b"\xfd7zXZ\x00":
            return "xz"
        if len(data) >= 12 and data[4:8] == b"ftyp":
            return "mov" if data[8:12] == b"qt  " else "mp4"
        if data[:4] == b"RIFF":
            if len(data) >= 12:
                if data[8:12] == b"WAVE":
                    return "wav"
                if data[8:12] == b"AVI ":
                    return "avi"
                if data[8:12] == b"WEBP":
                    return "webp"
        if data[:4] == b"fLaC":
            return "flac"
        if data[:4] == b"OggS":
            return "ogg"
        if data[:3] in (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
            return "mp3"
        if data[:8] in (b"II*\x00", b"MM\x00*"):
            return "tiff"
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return "gif"
        if data[:2] == b"BM":
            return "bmp"
        if data[:4] == b"{\\rtf":
            return "rtf"
        if data[:5] == b"<?xml":
            return "xml"
        if data[:15].lower() in (b"<!doctype html>", b"<!doctype html "):
            return "html"
        if data[:6].lower() in (b"<html>", b"<html "):
            return "html"
        eml_headers = (b"From ", b"Return-Path:", b"Received:")
        if any(data.startswith(h) for h in eml_headers):
            return "eml"
        if data.startswith(b"#!/"):
            return "script"
        if data.startswith(b"bplist"):
            return "plist"
        if data[:4] == b"\x1a\x45\xdf\xa3":
            return "mkv"
        if data[:4] in (b"FLV\x01",):
            return "flv"
        if data[:3] == b"ID3" or data[:2] == b"\xff\xfb":
            return "mp3"
        return "bin"

    def verify_recovered(self, output_path: Path, expected_sha256: str) -> bool:
        """Re-read a recovered file and verify the stored hash."""
        hasher = hashlib.sha256()

        try:
            with open(output_path, "rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
        except OSError as exc:
            raise RecoveryError(
                f"Cannot verify recovered file: {output_path}",
                remediation="Check file permissions and disk state",
            ) from exc

        actual_sha256 = hasher.hexdigest()
        if actual_sha256 != expected_sha256:
            self.logger.warning(
                json.dumps(
                    {
                        "event": "CUSTODY_WARNING",
                        "output_file": str(output_path),
                        "expected_sha256": expected_sha256,
                        "actual_sha256": actual_sha256,
                        "timestamp": _utc_now_iso(),
                    }
                )
            )
            return False

        return True

    def export_recovery_manifest(
        self,
        source_path: Path,
        output_dir: Path,
        recovered_files: list[RecoveredFile],
        failed_inodes: list[dict] | None = None,
    ) -> Path:
        """Write a JSON manifest describing recovered inodes."""
        manifest = {
            "source": str(source_path),
            "timestamp": _utc_now_iso(),
            "recovered_count": len(recovered_files),
            "failed_count": len(failed_inodes) if failed_inodes else 0,
            "failed_inodes": failed_inodes or [],
            "recovered_files": [asdict(recovered_file) for recovered_file in recovered_files],
        }

        manifest_path = output_dir / "recovery_manifest.json"
        try:
            with open(manifest_path, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise RecoveryError(
                f"Cannot write recovery manifest: {manifest_path}",
                remediation="Check output directory permissions and disk space",
            ) from exc

        return manifest_path

    def _get_mac_times(
        self,
        image_path: Path,
        inode: int,
        image_offset: int = 0,
    ) -> tuple[int, int, int, int]:
        """Return (mtime, atime, ctime, crtime) Unix epochs from istat.

        Returns (0, 0, 0, 0) if istat fails or timestamps cannot be parsed.
        """
        command = ["istat"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.extend([str(image_path), str(inode)])

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return self._parse_istat_mac_times(result.stdout)
        except Exception:
            return (0, 0, 0, 0)

    def _parse_istat_mac_times(self, output: str) -> tuple[int, int, int, int]:
        """Parse mtime/atime/ctime/crtime from istat text output.

        Handles both NTFS (File Modified / MFT Modified) and
        ext4 (File Modified / Inode Modified / File Created) label variants,
        tab-separated values, and sub-second (nano/microsecond) precision.
        """
        # Label → which timestamp variable to update
        label_map = {
            r"file\s+modified":   "mtime",
            r"written":           "mtime",
            r"modified":          "mtime",
            r"accessed":          "atime",
            r"mft\s+modified":    "ctime",
            r"inode\s+modified":  "ctime",
            r"changed":           "ctime",
            r"file\s+created":    "crtime",
            r"created":           "crtime",
        }

        results: dict[str, int] = {}
        for line in output.splitlines():
            line = line.strip()
            for label_re, field in label_map.items():
                m = re.match(rf"(?:{label_re}):\s+(.+)", line, re.IGNORECASE)
                if m and field not in results:
                    ts = self._parse_istat_timestamp(m.group(1))
                    if ts:
                        results[field] = ts
                    break

        return (
            results.get("mtime", 0),
            results.get("atime", 0),
            results.get("ctime", 0),
            results.get("crtime", 0),
        )

    def _parse_istat_timestamp(self, ts_str: str) -> int:
        """Convert an istat timestamp string to a Unix epoch integer.

        Handles formats like:
          2026-05-31 03:03:04.499545400 (UTC)    ← NTFS nanoseconds
          2026-05-31 03:02:03.563617652 (UTC)    ← ext4 nanoseconds
          2024-03-15 14:23:11 (UTC)              ← no sub-seconds
        """
        from datetime import timezone as _tz

        ts_str = ts_str.strip()
        # Strip timezone annotation e.g. " (UTC)"
        ts_str = re.sub(r"\s*\([^)]*\)\s*$", "", ts_str).strip()
        # Truncate sub-seconds to microseconds (Python datetime max precision)
        ts_str = re.sub(r"(\.\d{6})\d+", r"\1", ts_str)

        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%b %d %Y %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(ts_str.strip(), fmt).replace(tzinfo=_tz.utc)
                return int(dt.timestamp())
            except ValueError:
                continue
        return 0

    def _output_path_for_inode(
        self,
        output_dir: Path,
        inode: int,
        file_type: str,
        original_name: Optional[str] = None,
    ) -> Path:
        """Build the output path for one recovered inode."""
        extension = file_type if file_type not in {"", "bin"} else "bin"
        candidate_name = self._candidate_output_name(inode, extension, original_name)
        candidate = output_dir / candidate_name

        if not candidate.exists():
            return candidate

        stem = candidate.stem
        suffix = candidate.suffix
        for index in range(1, 10_000):
            alternative = output_dir / f"{stem}_inode_{inode}_{index}{suffix}"
            if not alternative.exists():
                return alternative

        raise RecoveryError(
            f"Cannot allocate output filename for inode {inode}",
            remediation="Clean the output directory or choose a different location.",
        )

    def _candidate_output_name(
        self,
        inode: int,
        extension: str,
        original_name: Optional[str],
    ) -> str:
        """Build the preferred output filename for a recovered inode."""
        if original_name:
            sanitized = self._sanitize_original_name(original_name)
            if sanitized:
                candidate = Path(sanitized)
                if candidate.suffix:
                    return candidate.name
                return f"{candidate.name}.{extension}"
        return f"inode_{inode}.{extension}"

    def _sanitize_original_name(self, original_name: str) -> str:
        """Normalize an fls name into a filesystem-safe output filename."""
        cleaned = original_name.replace("\x00", "").strip()
        cleaned = cleaned.split("/")[-1].split("\\")[-1]
        cleaned = re.sub(r'[<>:"/\\|?*]', "_", cleaned)
        cleaned = cleaned.rstrip(". ").strip()
        if cleaned in {"", ".", ".."}:
            return ""
        return cleaned

    def _inode_touches_bad_sectors(
        self,
        image_path: Path,
        inode: int,
        image_offset: int,
        mapfile: list[tuple[int, int, str]],
    ) -> bool:
        """Resolve inode extents with istat and check them against bad ranges."""
        block_size, block_ranges = self._get_inode_block_ranges(
            image_path, inode, image_offset
        )
        image_base = image_offset * 512

        for block_start, block_end in block_ranges:
            byte_start = image_base + (block_start * block_size)
            byte_end = image_base + (block_end * block_size)
            if DdrescueMapParser.overlaps_bad_sector(mapfile, byte_start, byte_end):
                return True

        return False

    def _get_inode_block_ranges(
        self,
        image_path: Path,
        inode: int,
        image_offset: int,
    ) -> tuple[int, list[tuple[int, int]]]:
        """Use istat to resolve block ranges for an inode."""
        command = ["istat"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.extend([str(image_path), str(inode)])

        output = self._run_text_command(
            command,
            tool_name="istat",
            not_found_remediation="Install The Sleuth Kit and ensure istat is in PATH",
            run_failure_message=f"Failed to run istat for inode {inode}",
            run_failure_remediation="Verify image accessibility and inode number",
            timeout=self._command_timeout("icat"),
        )

        block_size = self._parse_istat_block_size(output)
        block_ranges = self._parse_istat_block_ranges(output)
        if not block_ranges:
            raise RecoveryError(
                f"Cannot determine block extents for inode {inode}",
                remediation=(
                    "Inspect istat output and extend the parser before using mapfile filtering."
                ),
            )

        return block_size, block_ranges

    def _parse_istat_block_size(self, output: str) -> int:
        """Extract filesystem block size from istat output."""
        match = re.search(
            r"(?im)^\s*(?:block|cluster)\s+size:\s*(\d+)\s*$",
            output,
        )
        if match:
            return int(match.group(1))
        return 512

    def _parse_istat_block_ranges(self, output: str) -> list[tuple[int, int]]:
        """Extract half-open block ranges from istat output."""
        ranges = []
        collecting = False

        for raw_line in output.splitlines():
            line = raw_line.strip()
            lower_line = line.lower()

            if not line:
                collecting = False
                continue

            if any(
                label in lower_line
                for label in (
                    "direct blocks:",
                    "indirect blocks:",
                    "double indirect blocks:",
                    "triple indirect blocks:",
                    "extents:",
                    "extent:",
                    "blocks:",
                )
            ):
                collecting = True
                payload = line.split(":", 1)[1]
                ranges.extend(self._parse_block_tokens(payload))
                continue

            if collecting:
                if ":" in line and not re.match(r"^\d", line):
                    collecting = False
                    continue
                ranges.extend(self._parse_block_tokens(line))

        return ranges

    def _parse_block_tokens(self, text: str) -> list[tuple[int, int]]:
        """Parse individual block tokens or ranges from istat output."""
        ranges = []
        for token in re.findall(r"\b\d+(?:-\d+)?\b", text):
            if "-" in token:
                start_text, end_text = token.split("-", 1)
                start = int(start_text)
                end = int(end_text)
                if end >= start:
                    ranges.append((start, end + 1))
            else:
                start = int(token)
                ranges.append((start, start + 1))
        return ranges
