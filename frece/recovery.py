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
    """One deleted file as seen by fls - no extraction performed."""

    inode: int
    inode_token: str
    entry_type: str
    name: str
    allocated: bool


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

        return RecoveredFile(
            inode=inode,
            size=size,
            file_type=file_type,
            sha256=sha256,
            output_path=str(final_path),
            verified=verified,
            original_name=original_name,
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
        """Detect file type using python-magic when available, else header scan."""
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
                if "jpeg" in detected:
                    return "jpeg"
                if "png" in detected:
                    return "png"
                if "pdf" in detected:
                    return "pdf"
                if "quicktime" in detected:
                    return "mov"
                if "mp4" in detected or "iso media" in detected:
                    return "mp4"
                if "zip" in detected:
                    return "zip"
                if "wave audio" in detected or "wav" in detected:
                    return "wav"
                if "avi" in detected:
                    return "avi"
                if "mpeg" in detected and "layer iii" in detected:
                    return "mp3"
                if "mail" in detected or "rfc 822" in detected:
                    return "eml"
                if "html" in detected:
                    return "html"
                if "text" in detected:
                    return "txt"
            except Exception:
                pass

        if data.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if data.startswith(b"%PDF"):
            return "pdf"
        if data.startswith(b"PK\x03\x04"):
            if b"word/" in data[:4096]:
                return "docx"
            if b"xl/" in data[:4096]:
                return "xlsx"
            if b"ppt/" in data[:4096]:
                return "pptx"
            return "zip"
        if len(data) >= 12 and data[4:8] == b"ftyp":
            if data[8:12] == b"qt  ":
                return "mov"
            return "mp4"
        if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
            return "wav"
        if data.startswith(b"RIFF") and data[8:12] == b"AVI ":
            return "avi"
        if data.startswith((b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"ID3")):
            return "mp3"
        if data.startswith(b"From "):
            return "eml"
        if data.startswith((b"<!DOCTYPE html", b"<html")):
            return "html"
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
