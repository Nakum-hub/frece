"""Streaming file carver with signature-based recovery."""

import hashlib
import json
import os
import re
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Generator

from frece.errors import CarveError, ValidationError


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class CarvedFile:
    """Metadata for a carved file."""

    offset: int
    size: int
    file_type: str
    sha256: str
    validation_passed: bool
    validation_notes: str = ""


@dataclass
class CarveManifest:
    """Structured carving manifest with dict-style compatibility."""

    source: str
    source_sha256: str
    timestamp: str
    carved_files: list[CarvedFile]

    def to_dict(self) -> dict:
        """Return the JSON-serializable manifest shape."""
        return {
            "source": self.source,
            "source_sha256": self.source_sha256,
            "timestamp": self.timestamp,
            "carved_files": [asdict(carved_file) for carved_file in self.carved_files],
        }

    def __getitem__(self, key: str):
        """Support legacy dict-style access used by older tests/callers."""
        return self.to_dict()[key]


class SignatureDatabase:
    """File signatures and validation rules."""

    SIGNATURES = {
        b"\xff\xd8\xff": "jpeg",
        b"\x89PNG\r\n\x1a\n": "png",
        b"PK\x03\x04": "zip",
        b"\xff\xfb\x90\x00": "mp3",
        b"\xff\xf3\x90\x00": "mp3",
        b"\xff\xf2\x90\x00": "mp3",
        b"ID3": "mp3",
        b"RIFF": "riff",
        b"%PDF": "pdf",
        b"GIF89a": "gif",
        b"GIF87a": "gif",
        b"BM": "bmp",
        b"II\x2a\x00": "tiff",
        b"MM\x00\x2a": "tiff",
        b"SQLITE format": "sqlite",
        b"\x00\x00\x00\x20ftypmp42": "mp4",
        b"\x00\x00\x00\x1cftypM4V ": "mp4",
        b"\x00\x00\x00\x1cftypisom": "mp4",
        b"\x00\x00\x00\x1cftypqt  ": "mov",
        b"From ": "eml",
    }

    MAX_SIGNATURE_LENGTH = 2048

    @staticmethod
    def find_signatures(
        data: bytes, offset: int = 0
    ) -> Generator[tuple[int, str], None, None]:
        """Find all signatures in data chunk."""
        for sig, file_type in SignatureDatabase.SIGNATURES.items():
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                yield (offset + pos, file_type)
                start = pos + 1


class StreamingCarver:
    """Memory-efficient file carver using chunked reads."""

    def __init__(self, chunk_size: int | object = 64 * 1024 * 1024, max_sig_len: int = 2048):
        self.max_video_size = 0
        if isinstance(chunk_size, int):
            self.chunk_size = chunk_size
            self.max_sig_len = max_sig_len
            return

        config = chunk_size
        self.chunk_size = getattr(config, "chunk_size", 64 * 1024 * 1024)
        self.max_sig_len = getattr(config, "max_signature_length", max_sig_len)
        self.max_video_size = getattr(config, "max_video_size", 0)

    def carve(
        self,
        source_path: Path,
        output_dir: Path,
        verify: bool = True,
    ):
        """Carve files from source with streaming reads."""
        source_path = Path(source_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            source_hash, found_sigs = self._scan_and_hash(source_path)
        except OSError as exc:
            raise CarveError(
                f"Cannot open source: {source_path}",
                remediation="Verify path exists and is readable",
            ) from exc

        carved_files = []
        carved_ranges: list[tuple[int, int, str]] = []

        for sig_offset in sorted(found_sigs):
            types = found_sigs[sig_offset]
            if self._should_skip_nested_signature(sig_offset, types, carved_ranges):
                continue

            file_type = self._disambiguate_type(source_path, sig_offset, types)
            if not file_type:
                continue

            size = self._measure_file_size(source_path, sig_offset, file_type)
            if size <= 0:
                continue

            output_file = output_dir / f"{sig_offset:016x}_{file_type}"
            file_sha256, actual_size = self._write_carved_file(
                source_path,
                sig_offset,
                size,
                output_file,
            )
            if actual_size <= 0:
                output_file.unlink(missing_ok=True)
                continue

            validation_passed = True
            validation_notes = ""

            if verify:
                try:
                    validation_notes = self._validate_output_file(
                        file_type,
                        output_file,
                        actual_size,
                    )
                except ValidationError as exc:
                    validation_passed = False
                    validation_notes = str(exc)

            carved_file = CarvedFile(
                offset=sig_offset,
                size=actual_size,
                file_type=file_type,
                sha256=file_sha256,
                validation_passed=validation_passed,
                validation_notes=validation_notes,
            )
            carved_files.append(carved_file)

            if file_type in {"zip", "docx", "xlsx", "pptx"} and actual_size > 0:
                carved_ranges.append((sig_offset, sig_offset + actual_size, file_type))

        manifest = CarveManifest(
            source=str(source_path),
            source_sha256=source_hash,
            timestamp=_utc_now_iso(),
            carved_files=carved_files,
        )

        manifest_path = output_dir / "carve_manifest.json"
        try:
            with open(manifest_path, "w", encoding="utf-8") as handle:
                json.dump(manifest.to_dict(), handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise CarveError(
                f"Cannot write carving manifest: {manifest_path}",
                remediation="Check output directory permissions and disk space",
            ) from exc

        return manifest

    def _scan_and_hash(self, source_path: Path) -> tuple[str, dict[int, list[str]]]:
        """Single pass: compute SHA256 and collect all signature positions."""
        sha256 = hashlib.sha256()
        found_sigs: dict[int, list[str]] = {}
        chunk_offset = 0
        previous_overlap = b""

        with open(source_path, "rb") as handle:
            while True:
                chunk = handle.read(self.chunk_size)
                if not chunk:
                    break

                sha256.update(chunk)
                combined = previous_overlap + chunk
                abs_offset = chunk_offset - len(previous_overlap)

                for sig_offset, sig_type in SignatureDatabase.find_signatures(combined, abs_offset):
                    found_sigs.setdefault(sig_offset, []).append(sig_type)

                chunk_offset += len(chunk)
                previous_overlap = chunk[-self.max_sig_len :] if self.max_sig_len else b""

        return sha256.hexdigest(), found_sigs

    def _measure_file_size(self, source_path: Path, offset: int, file_type: str) -> int:
        """Measure how many bytes should be copied for a carved artifact."""
        with open(source_path, "rb") as handle:
            handle.seek(offset)

            if file_type in {"mp4", "mov"}:
                return self._get_mp4_size(handle, offset, source_path)
            if file_type in {"zip", "docx", "xlsx", "pptx"}:
                return self._find_zip_end(handle, offset, source_path)
            if file_type == "pdf":
                return self._find_pdf_end(handle, offset, source_path)
            if file_type == "jpeg":
                return self._find_jpeg_end(handle)
            if file_type == "png":
                return self._find_png_end(handle)
            return self._estimate_file_size(file_type)

    def _disambiguate_type(
        self, source_path: Path, offset: int, types: list[str]
    ) -> str:
        """Resolve ambiguous signatures."""
        unique_types = set(types)

        if "zip" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset + 30)
                    filename = handle.read(256).split(b"\x00")[0].decode(
                        "utf-8", errors="ignore"
                    )

                    if "word/" in filename:
                        return "docx"
                    if "xl/" in filename:
                        return "xlsx"
                    if "ppt/" in filename:
                        return "pptx"
            except (OSError, UnicodeDecodeError):
                pass
            return "zip"

        if "riff" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset + 8)
                    riff_type = handle.read(4)

                    if riff_type == b"WAVE":
                        return "wav"
                    if riff_type == b"AVI ":
                        return "avi"
            except OSError:
                pass
            return "riff"

        if "eml" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset)
                    next_bytes = handle.read(512)
                    if re.search(rb"^[A-Za-z\-]+:\s", next_bytes, re.MULTILINE):
                        return "eml"
                    return ""
            except OSError:
                pass
            return "eml"

        return types[0] if types else "unknown"

    def _write_carved_file(
        self, source_path: Path, offset: int, size: int, output_file: Path
    ) -> tuple[str, int]:
        """Stream-copy bytes from the source image into an output artifact."""
        sha256 = hashlib.sha256()
        written = 0
        chunk_size = 4 * 1024 * 1024

        try:
            with open(source_path, "rb") as src, open(output_file, "wb") as dst:
                src.seek(offset)
                remaining = size
                while remaining > 0:
                    to_read = min(chunk_size, remaining)
                    chunk = src.read(to_read)
                    if not chunk:
                        break
                    dst.write(chunk)
                    sha256.update(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)

                dst.flush()
                os.fsync(dst.fileno())
        except OSError as exc:
            raise CarveError(
                f"Cannot write carved file: {output_file}",
                remediation="Check output directory permissions and disk space",
            ) from exc

        return sha256.hexdigest(), written

    def _get_mp4_size(self, handle: BinaryIO, offset: int, source_path: Path) -> int:
        """Scan forward from ftyp to find total file extent via mdat atom."""
        source_size = source_path.stat().st_size
        fallback_size = source_size - offset
        if self.max_video_size > 0:
            fallback_size = min(fallback_size, self.max_video_size)

        handle.seek(offset)
        pos = offset
        while pos < source_size - 8:
            handle.seek(pos)
            header = handle.read(8)
            if len(header) < 8:
                break
            atom_size = int(struct.unpack(">I", header[0:4])[0])
            atom_type = header[4:8]
            header_size = 8
            if atom_size == 1:
                largesize = handle.read(8)
                if len(largesize) < 8:
                    break
                atom_size = int(struct.unpack(">Q", largesize)[0])
                header_size = 16
            elif atom_size == 0:
                if atom_type == b"mdat":
                    return fallback_size
                break
            if atom_type == b"mdat":
                return (pos + atom_size) - offset
            if atom_size < header_size:
                break
            pos += atom_size
        return fallback_size

    def _find_zip_end(self, handle: BinaryIO, offset: int, source_path: Path) -> int:
        """Find ZIP end-of-central-directory to bound ZIP-based containers."""
        start_pos = handle.tell()
        source_size = source_path.stat().st_size
        max_size = min(500 * 1024 * 1024, source_size - offset)
        chunk_size = 1024 * 1024
        overlap = 66 * 1024
        pos = start_pos
        prev_bytes = b""

        while pos - start_pos < max_size:
            chunk = handle.read(min(chunk_size, max_size - (pos - start_pos)))
            if not chunk:
                break

            combined = prev_bytes + chunk
            idx = combined.rfind(b"PK\x05\x06")
            if idx != -1 and len(combined) >= idx + 22:
                comment_len = int(struct.unpack("<H", combined[idx + 20 : idx + 22])[0])
                eocd_end = idx + 22 + comment_len
                if len(combined) >= eocd_end:
                    return pos - start_pos - len(prev_bytes) + eocd_end

            pos += len(chunk)
            prev_bytes = combined[-overlap:]

        return max_size

    def _find_jpeg_end(self, handle: BinaryIO) -> int:
        """Find JPEG EOF marker (FF D9)."""
        start_pos = handle.tell()
        max_size = 100 * 1024 * 1024

        chunk_size = 1024 * 1024
        pos = start_pos
        prev_byte = b""

        while pos - start_pos < max_size:
            chunk = handle.read(chunk_size)
            if not chunk:
                break

            combined = prev_byte + chunk
            idx = combined.find(b"\xff\xd9")
            if idx != -1:
                return pos - start_pos - len(prev_byte) + idx + 2

            pos += len(chunk)
            prev_byte = combined[-1:]

        return min(max_size, pos - start_pos)

    def _find_png_end(self, handle: BinaryIO) -> int:
        """Find PNG IEND chunk."""
        start_pos = handle.tell()
        max_size = 100 * 1024 * 1024

        chunk_size = 1024 * 1024
        pos = start_pos
        prev_bytes = b""

        while pos - start_pos < max_size:
            chunk = handle.read(chunk_size)
            if not chunk:
                break

            combined = prev_bytes + chunk
            idx = combined.find(b"IEND")
            if idx != -1:
                return pos - start_pos - len(prev_bytes) + idx + 8

            pos += len(chunk)
            prev_bytes = combined[-4:]

        return min(max_size, pos - start_pos)

    def _find_pdf_end(self, handle: BinaryIO, offset: int, source_path: Path) -> int:
        """Find the last PDF EOF marker within the carving window."""
        start_pos = handle.tell()
        source_size = source_path.stat().st_size
        max_size = min(500 * 1024 * 1024, source_size - offset)

        chunk_size = 1024 * 1024
        pos = start_pos
        prev_bytes = b""
        eof_end = 0

        while pos - start_pos < max_size:
            chunk = handle.read(min(chunk_size, max_size - (pos - start_pos)))
            if not chunk:
                break

            combined = prev_bytes + chunk
            for match in re.finditer(rb"%%EOF(?:\r\n|\n|\r)?", combined):
                eof_end = pos - start_pos - len(prev_bytes) + match.end()

            pos += len(chunk)
            prev_bytes = combined[-100:]

        if eof_end:
            return eof_end

        return min(max_size, pos - start_pos)

    def _validate_output_file(self, file_type: str, output_file: Path, size: int) -> str:
        """Validate a carved artifact without loading large payloads wholesale."""
        if size <= 16 * 1024 * 1024:
            return self._validate_file(file_type, output_file.read_bytes())

        match file_type:
            case "jpeg":
                head = self._read_prefix(output_file, 4)
                tail = self._read_suffix(output_file, 2)
                if len(head) < 4:
                    raise ValidationError("JPEG too small")
                if head[0:2] != b"\xff\xd8":
                    raise ValidationError("JPEG: Invalid SOI marker")
                if tail != b"\xff\xd9":
                    raise ValidationError("JPEG: Missing EOI marker")
                return "JPEG validated: SOI and EOI present"

            case "png":
                head = self._read_prefix(output_file, 24)
                if len(head) < 24:
                    raise ValidationError("PNG too small")
                if head[8:12] != b"IHDR":
                    raise ValidationError("PNG: Invalid IHDR chunk")
                return "PNG validated: IHDR present"

            case "bmp":
                head = self._read_prefix(output_file, 54)
                if len(head) < 54:
                    raise ValidationError("BMP too small")
                if head[0:2] != b"BM":
                    raise ValidationError("BMP: Invalid signature")
                file_size_field = int(struct.unpack_from("<I", head, 2)[0])
                if not (int(size * 0.8) <= file_size_field <= int(size * 1.2)):
                    raise ValidationError(
                        "BMP: file_size field "
                        f"{file_size_field} inconsistent with carved size {size}"
                    )
                pixel_offset = int(struct.unpack_from("<I", head, 10)[0])
                if pixel_offset < 26:
                    raise ValidationError(f"BMP: Invalid pixel data offset {pixel_offset}")
                return "BMP validated: signature and size field consistent"

            case "pdf":
                if not self._file_contains_any(output_file, (b"xref", b"stream")):
                    raise ValidationError("PDF: No xref or stream found")
                return "PDF validated: xref/stream present"

            case "gif":
                head = self._read_prefix(output_file, 13)
                tail = self._read_suffix(output_file, 1)
                if len(head) < 13:
                    raise ValidationError("GIF too small")
                if head[0:6] not in (b"GIF87a", b"GIF89a"):
                    raise ValidationError("GIF: Invalid header")
                if tail != b"\x3b":
                    raise ValidationError("GIF: Missing trailer byte")
                return "GIF validated: header and trailer present"

            case "tiff":
                head = self._read_prefix(output_file, 8)
                if len(head) < 8:
                    raise ValidationError("TIFF too small")
                byte_order = head[0:2]
                if byte_order == b"II":
                    magic = struct.unpack_from("<H", head, 2)[0]
                elif byte_order == b"MM":
                    magic = struct.unpack_from(">H", head, 2)[0]
                else:
                    raise ValidationError("TIFF: Invalid byte order marker")
                if magic != 42:
                    raise ValidationError(f"TIFF: Invalid magic number {magic}")
                return f"TIFF validated: {('little' if byte_order == b'II' else 'big')}-endian"

            case "mp3":
                head = self._read_prefix(output_file, 4)
                if len(head) < 4:
                    raise ValidationError("MP3 too small")
                sync = head[0:2]
                if sync not in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
                    raise ValidationError("MP3: Invalid frame sync")
                return "MP3 validated: frame sync present"

            case "sqlite":
                head = self._read_prefix(output_file, 20)
                if len(head) < 20:
                    raise ValidationError("SQLite too small")
                try:
                    page_size = int(struct.unpack(">H", head[16:18])[0])
                    if page_size == 1:
                        page_size = 65536
                    if (
                        page_size < 512
                        or page_size > 65536
                        or (page_size & (page_size - 1)) != 0
                    ):
                        raise ValidationError(f"SQLite: Invalid page size {page_size}")
                    return f"SQLite validated: page size {page_size}"
                except struct.error as exc:
                    raise ValidationError("SQLite: Cannot read page size") from exc

            case _:
                return "No secondary validation for this type"

    def _read_prefix(self, output_file: Path, size: int) -> bytes:
        """Read the leading bytes of a carved artifact."""
        with output_file.open("rb") as handle:
            return handle.read(size)

    def _read_suffix(self, output_file: Path, size: int) -> bytes:
        """Read the trailing bytes of a carved artifact."""
        if size <= 0:
            return b""

        file_size = output_file.stat().st_size
        with output_file.open("rb") as handle:
            handle.seek(max(file_size - size, 0))
            return handle.read(size)

    def _file_contains_any(self, output_file: Path, needles: tuple[bytes, ...]) -> bool:
        """Stream-search a file for any of the given byte markers."""
        overlap = max(len(needle) for needle in needles)
        previous = b""

        with output_file.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break

                combined = previous + chunk
                if any(needle in combined for needle in needles):
                    return True
                previous = combined[-overlap:]

        return False

    def _validate_file(self, file_type: str, data: bytes) -> str:
        """Apply secondary validation rules."""
        match file_type:
            case "jpeg":
                if len(data) < 4:
                    raise ValidationError("JPEG too small")
                if data[0:2] != b"\xff\xd8":
                    raise ValidationError("JPEG: Invalid SOI marker")
                if data[-2:] != b"\xff\xd9":
                    raise ValidationError("JPEG: Missing EOI marker")
                return "JPEG validated: SOI and EOI present"

            case "png":
                if len(data) < 24:
                    raise ValidationError("PNG too small")
                if data[8:12] != b"IHDR":
                    raise ValidationError("PNG: Invalid IHDR chunk")
                return "PNG validated: IHDR present"

            case "bmp":
                if len(data) < 54:
                    raise ValidationError("BMP too small")
                if data[0:2] != b"BM":
                    raise ValidationError("BMP: Invalid signature")
                file_size_field = int(struct.unpack_from("<I", data, 2)[0])
                if not (int(len(data) * 0.8) <= file_size_field <= int(len(data) * 1.2)):
                    raise ValidationError(
                        f"BMP: file_size field {file_size_field} "
                        f"inconsistent with carved size {len(data)}"
                    )
                pixel_offset = int(struct.unpack_from("<I", data, 10)[0])
                if pixel_offset < 26:
                    raise ValidationError(f"BMP: Invalid pixel data offset {pixel_offset}")
                return "BMP validated: signature and size field consistent"

            case "pdf":
                if len(data) < 10:
                    raise ValidationError("PDF too small")
                if not (b"xref" in data or b"stream" in data):
                    raise ValidationError("PDF: No xref or stream found")
                return "PDF validated: xref/stream present"

            case "gif":
                if len(data) < 13:
                    raise ValidationError("GIF too small")
                if data[0:6] not in (b"GIF87a", b"GIF89a"):
                    raise ValidationError("GIF: Invalid header")
                if data[-1:] != b"\x3b":
                    raise ValidationError("GIF: Missing trailer byte")
                return "GIF validated: header and trailer present"

            case "tiff":
                if len(data) < 8:
                    raise ValidationError("TIFF too small")
                byte_order = data[0:2]
                if byte_order == b"II":
                    magic = struct.unpack_from("<H", data, 2)[0]
                elif byte_order == b"MM":
                    magic = struct.unpack_from(">H", data, 2)[0]
                else:
                    raise ValidationError("TIFF: Invalid byte order marker")
                if magic != 42:
                    raise ValidationError(f"TIFF: Invalid magic number {magic}")
                return f"TIFF validated: {('little' if byte_order == b'II' else 'big')}-endian"

            case "mp3":
                if len(data) < 4:
                    raise ValidationError("MP3 too small")
                sync = data[0:2]
                if sync not in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
                    raise ValidationError("MP3: Invalid frame sync")
                return "MP3 validated: frame sync present"

            case "sqlite":
                if len(data) < 20:
                    raise ValidationError("SQLite too small")
                try:
                    page_size = int(struct.unpack(">H", data[16:18])[0])
                    if page_size == 1:
                        page_size = 65536
                    if (
                        page_size < 512
                        or page_size > 65536
                        or (page_size & (page_size - 1)) != 0
                    ):
                        raise ValidationError(f"SQLite: Invalid page size {page_size}")
                    return f"SQLite validated: page size {page_size}"
                except struct.error as exc:
                    raise ValidationError("SQLite: Cannot read page size") from exc

            case _:
                return "No secondary validation for this type"

    def _estimate_file_size(self, file_type: str) -> int:
        """Estimate carving size limit by type."""
        sizes = {
            "jpeg": 50 * 1024 * 1024,
            "png": 100 * 1024 * 1024,
            "zip": 500 * 1024 * 1024,
            "docx": 500 * 1024 * 1024,
            "xlsx": 500 * 1024 * 1024,
            "pptx": 500 * 1024 * 1024,
            "pdf": 500 * 1024 * 1024,
            "mp3": 500 * 1024 * 1024,
            "avi": 2 * 1024 * 1024 * 1024,
        }
        return sizes.get(file_type, 10 * 1024 * 1024)

    def _should_skip_nested_signature(
        self,
        offset: int,
        types: list[str],
        carved_ranges: list[tuple[int, int, str]],
    ) -> bool:
        """Skip nested ZIP local headers already covered by a parent container."""
        if "zip" not in set(types):
            return False

        for start, end, file_type in carved_ranges:
            if file_type in {"zip", "docx", "xlsx", "pptx"} and start < offset < end:
                return True

        return False
