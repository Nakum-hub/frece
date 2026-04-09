"""Deleted file recovery using The Sleuth Kit tools."""

import hashlib
import json
import logging
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import magic
except ImportError:
    magic = None

from frece.errors import RecoveryError


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


class DdrescueMapParser:
    """Parse ddrescue mapfile to identify bad sectors."""

    BAD_SECTOR_FLAG = "-"

    @staticmethod
    def load_mapfile(mapfile_path: Path) -> list[tuple[int, int, str]]:
        """Load ddrescue mapfile and return byte ranges with status flags."""
        sectors = []

        if not mapfile_path.exists():
            return sectors

        try:
            with open(mapfile_path, "r") as f:
                for line in f:
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
        except OSError as e:
            raise RecoveryError(
                f"Cannot read mapfile: {mapfile_path}",
                remediation="Verify the ddrescue mapfile path and permissions",
            ) from e

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

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

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

        deleted_inodes = self._list_deleted_inodes(image_path, image_offset)
        if inodes is not None:
            inodes_set = set(inodes)
            deleted_inodes = [inode for inode in deleted_inodes if inode in inodes_set]
        mapfile = (
            DdrescueMapParser.load_mapfile(mapfile_path) if mapfile_path else []
        )

        recovered_files = []
        failed_inodes: list[dict] = []
        for inode in deleted_inodes:
            try:
                recovered = self._extract_inode(
                    image_path,
                    inode,
                    output_dir,
                    image_offset=image_offset,
                    mapfile=mapfile,
                    verify=verify,
                )
                if recovered is not None:
                    recovered_files.append(recovered)
            except RecoveryError as exc:
                failed_inodes.append({"inode": inode, "reason": exc.message})
                self.logger.warning(
                    json.dumps(
                        {
                            "event": "INODE_SKIP",
                            "inode": inode,
                            "reason": exc.message,
                            "timestamp": _utc_now_iso(),
                        }
                    )
                )
            except Exception as exc:
                failed_inodes.append({"inode": inode, "reason": str(exc)})
                self.logger.warning(
                    json.dumps(
                        {
                            "event": "INODE_SKIP",
                            "inode": inode,
                            "reason": str(exc),
                            "timestamp": _utc_now_iso(),
                        }
                    )
                )

        if file_types is not None:
            file_type_aliases = {"jpg": "jpeg"}
            ft_lower = {
                file_type_aliases.get(file_type.lower().lstrip("."), file_type.lower().lstrip("."))
                for file_type in file_types
            }
            recovered_files = [
                recovered_file
                for recovered_file in recovered_files
                if recovered_file.file_type.lower() in ft_lower
            ]

        manifest = self.export_recovery_manifest(
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
        command = ["fls", "-r", "-d"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.append(str(image_path))

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError as e:
            raise RecoveryError(
                "Tool not found: fls",
                remediation="Install The Sleuth Kit: apt-get install sleuthkit",
            ) from e
        except OSError as e:
            raise RecoveryError(
                f"Failed to run fls on {image_path}",
                remediation="Verify image path and permissions",
            ) from e

        if result.returncode != 0:
            raise RecoveryError(
                f"fls failed: {result.stderr.strip()}",
                remediation="Check image format and filesystem offset",
            )

        entries: list[ScannedEntry] = []
        seen_inodes: set[int] = set()

        for line in result.stdout.splitlines():
            entry = self._parse_fls_line(line)
            if entry is not None and entry.inode not in seen_inodes:
                seen_inodes.add(entry.inode)
                entries.append(entry)

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

    def _parse_fls_line(self, line: str) -> ScannedEntry | None:
        """Parse one fls output line into a ScannedEntry."""
        line = line.strip()
        if not line:
            return None

        match = re.match(
            r"^([a-zA-Z])/[a-zA-Z\-]+\s+(\*\s+)?([0-9]+(?:-[0-9]+)*)\s*:\s*(.*)",
            line,
        )
        if not match:
            return None

        entry_type = match.group(1).lower()
        is_unallocated = match.group(2) is not None
        inode_token = match.group(3)
        name = match.group(4).strip() or "(no name)"

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

    def _list_deleted_inodes(self, image_path: Path, image_offset: int = 0) -> list[int]:
        """List deleted inodes from a filesystem image using fls."""
        command = ["fls", "-r", "-d"]
        if image_offset:
            command.extend(["-o", str(image_offset)])
        command.append(str(image_path))

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError as e:
            raise RecoveryError(
                "Tool not found: fls",
                remediation="Install The Sleuth Kit and ensure fls is in PATH",
            ) from e
        except OSError as e:
            raise RecoveryError(
                f"Failed to run fls on {image_path}",
                remediation="Verify the image path and local filesystem access",
            ) from e

        if result.returncode != 0:
            raise RecoveryError(
                f"fls failed for {image_path}",
                remediation=result.stderr.strip()
                or "Check the image format and filesystem offset",
            )

        inodes = []
        seen = set()
        for line in result.stdout.splitlines():
            inode = self._parse_inode_from_fls(line)
            if inode is not None and inode not in seen:
                seen.add(inode)
                inodes.append(inode)

        return inodes

    def _parse_inode_from_fls(self, line: str) -> Optional[int]:
        """Extract an inode number from a single fls output line."""
        match = re.search(r"\*\s+([0-9]+(?:-[0-9]+)*)\s*:", line)
        if not match:
            match = re.search(r"\s([0-9]+(?:-[0-9]+)*)\s*:", line)
        if not match:
            return None

        inode_token = match.group(1)
        inode_text = inode_token.split("-")[0]
        try:
            return int(inode_text)
        except ValueError:
            return None

    def _extract_inode(
        self,
        image_path: Path,
        inode: int,
        output_dir: Path,
        image_offset: int = 0,
        mapfile: Optional[list[tuple[int, int, str]]] = None,
        verify: bool = False,
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

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError as e:
            raise RecoveryError(
                "Tool not found: icat",
                remediation="Install The Sleuth Kit and ensure icat is in PATH",
            ) from e
        except OSError as e:
            raise RecoveryError(
                f"Failed to run icat for inode {inode}",
                remediation="Verify image accessibility and inode number",
            ) from e

        self.logger.info(
            json.dumps(
                {
                    "event": "ICAT",
                    "inode": inode,
                    "returncode": result.returncode,
                    "bytes_written": len(result.stdout),
                    "timestamp": _utc_now_iso(),
                }
            )
        )

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="ignore").strip()
            raise RecoveryError(
                f"icat failed for inode {inode}",
                remediation=stderr or "Check filesystem offset and inode availability",
            )

        file_data = result.stdout
        file_type = self._detect_file_type(file_data)
        output_path = self._output_path_for_inode(output_dir, inode, file_type)

        try:
            output_path.write_bytes(file_data)
        except OSError as e:
            raise RecoveryError(
                f"Cannot write recovered inode {inode} to {output_path}",
                remediation="Check output directory permissions and disk space",
            ) from e

        sha256 = hashlib.sha256(file_data).hexdigest()
        verified = self.verify_recovered(output_path, sha256) if verify else False

        return RecoveredFile(
            inode=inode,
            size=len(file_data),
            file_type=file_type,
            sha256=sha256,
            output_path=str(output_path),
            verified=verified,
        )

    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type using python-magic when available, else header scan."""
        if not data:
            return "bin"

        if magic is not None:
            try:
                detected = magic.from_buffer(data, mime=False).lower()
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
            with open(output_path, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    hasher.update(chunk)
        except OSError as e:
            raise RecoveryError(
                f"Cannot verify recovered file: {output_path}",
                remediation="Check file permissions and disk state",
            ) from e

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
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)
        except OSError as e:
            raise RecoveryError(
                f"Cannot write recovery manifest: {manifest_path}",
                remediation="Check output directory permissions and disk space",
            ) from e

        return manifest_path

    def _output_path_for_inode(self, output_dir: Path, inode: int, file_type: str) -> Path:
        """Build the output path for one recovered inode."""
        extension = file_type if file_type not in {"", "bin"} else "bin"
        return output_dir / f"inode_{inode}.{extension}"

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

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError as e:
            raise RecoveryError(
                "Tool not found: istat",
                remediation="Install The Sleuth Kit and ensure istat is in PATH",
            ) from e
        except OSError as e:
            raise RecoveryError(
                f"Failed to run istat for inode {inode}",
                remediation="Verify image accessibility and inode number",
            ) from e

        if result.returncode != 0:
            raise RecoveryError(
                f"istat failed for inode {inode}",
                remediation=result.stderr.strip()
                or "Check filesystem offset and inode availability",
            )

        block_size = self._parse_istat_block_size(result.stdout)
        block_ranges = self._parse_istat_block_ranges(result.stdout)
        if not block_ranges:
            raise RecoveryError(
                f"Cannot determine block extents for inode {inode}",
                remediation="Inspect istat output and extend the parser before using mapfile filtering.",
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
