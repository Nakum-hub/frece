"""Streaming file carver with signature-based recovery."""

import hashlib
import json
import re
import struct
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

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

    def __init__(self, chunk_size: int = 64 * 1024 * 1024, max_sig_len: int = 2048):
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
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            with open(source_path, "rb") as f:
                source_hash = self._hash_file(f)
        except OSError as e:
            raise CarveError(
                f"Cannot open source: {source_path}",
                remediation="Verify path exists and is readable",
            ) from e

        carved_files = []
        carved_ranges: list[tuple[int, int, str]] = []
        found_sigs = {}

        with open(source_path, "rb") as f:
            for chunk_offset, chunk_data in self._read_chunks(f):
                for sig_offset, sig_type in SignatureDatabase.find_signatures(
                    chunk_data, chunk_offset
                ):
                    if sig_offset not in found_sigs:
                        found_sigs[sig_offset] = []
                    found_sigs[sig_offset].append(sig_type)

        for sig_offset in sorted(found_sigs.keys()):
            types = found_sigs[sig_offset]
            if self._should_skip_nested_signature(sig_offset, types, carved_ranges):
                continue
            file_type = self._disambiguate_type(source_path, sig_offset, types)

            if not file_type:
                continue

            file_data, actual_size = self._extract_file(
                source_path, sig_offset, file_type
            )

            if not file_data:
                continue

            file_sha256 = hashlib.sha256(file_data).hexdigest()

            validation_passed = True
            validation_notes = ""

            if verify:
                try:
                    validation_notes = self._validate_file(file_type, file_data)
                except ValidationError as e:
                    validation_passed = False
                    validation_notes = str(e)

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

            output_file = output_dir / f"{sig_offset:016x}_{file_type}"
            try:
                output_file.write_bytes(file_data)
            except OSError as e:
                raise CarveError(
                    f"Cannot write carved file: {output_file}",
                    remediation="Check output directory permissions and disk space",
                ) from e

        manifest = CarveManifest(
            source=str(source_path),
            source_sha256=source_hash,
            timestamp=_utc_now_iso(),
            carved_files=carved_files,
        )

        manifest_path = output_dir / "carve_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest.to_dict(), f, indent=2)

        return manifest

    def _read_chunks(
        self, f
    ) -> Generator[tuple[int, bytes], None, None]:
        """Read file in overlapping chunks."""
        chunk_offset = 0
        previous_overlap = b""

        while True:
            chunk = f.read(self.chunk_size)
            if not chunk:
                break

            combined = previous_overlap + chunk
            yield (chunk_offset - len(previous_overlap), combined)

            chunk_offset += len(chunk)
            previous_overlap = chunk[-self.max_sig_len :]

    def _hash_file(self, f) -> str:
        """Compute SHA256 of entire file in one pass."""
        f.seek(0)
        hasher = hashlib.sha256()
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
        return hasher.hexdigest()

    def _disambiguate_type(
        self, source_path: Path, offset: int, types: list[str]
    ) -> str:
        """Resolve ambiguous signatures."""
        unique_types = set(types)

        if "zip" in unique_types:
            try:
                with open(source_path, "rb") as f:
                    f.seek(offset + 30)
                    filename = f.read(256).split(b"\x00")[0].decode("utf-8", errors="ignore")

                    if "word/" in filename:
                        return "docx"
                    elif "xl/" in filename:
                        return "xlsx"
                    elif "ppt/" in filename:
                        return "pptx"
            except (OSError, UnicodeDecodeError):
                pass
            return "zip"

        if "riff" in unique_types:
            try:
                with open(source_path, "rb") as f:
                    f.seek(offset + 8)
                    riff_type = f.read(4)

                    if riff_type == b"WAVE":
                        return "wav"
                    elif riff_type == b"AVI ":
                        return "avi"
            except OSError:
                pass
            return "riff"

        if "eml" in unique_types:
            try:
                with open(source_path, "rb") as f:
                    f.seek(offset)
                    next_bytes = f.read(512)
                    if re.search(rb"^[A-Za-z\-]+:\s", next_bytes, re.MULTILINE):
                        return "eml"
                    else:
                        return ""
            except OSError:
                pass
            return "eml"

        return types[0] if types else "unknown"

    def _extract_file(
        self, source_path: Path, offset: int, file_type: str
    ) -> tuple[bytes, int]:
        """Extract file from source."""
        with open(source_path, "rb") as f:
            f.seek(offset)

            if file_type in {"mp4", "mov"}:
                size = self._get_mp4_size(f, offset, source_path)
            elif file_type in {"zip", "docx", "xlsx", "pptx"}:
                size = self._find_zip_end(f, offset, source_path)
            elif file_type == "pdf":
                size = self._find_pdf_end(f, offset, source_path)
            elif file_type == "jpeg":
                size = self._find_jpeg_end(f)
            elif file_type == "png":
                size = self._find_png_end(f)
            else:
                size = self._estimate_file_size(file_type)

            f.seek(offset)
            data = f.read(size)

        return data, len(data)

    def _get_mp4_size(self, f, offset: int, source_path: Path) -> int:
        """Scan forward from ftyp to find total file extent via mdat atom."""
        source_size = source_path.stat().st_size
        fallback_size = source_size - offset
        if self.max_video_size:
            fallback_size = min(fallback_size, self.max_video_size)

        # ftyp box tells us nothing about file size - scan for mdat
        f.seek(offset)
        pos = offset
        while pos < source_size - 8:
            f.seek(pos)
            header = f.read(8)
            if len(header) < 8:
                break
            atom_size = struct.unpack(">I", header[0:4])[0]
            atom_type = header[4:8]
            header_size = 8
            if atom_size == 1:
                largesize = f.read(8)
                if len(largesize) < 8:
                    break
                atom_size = struct.unpack(">Q", largesize)[0]
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

    def _find_zip_end(self, f, offset: int, source_path: Path) -> int:
        """Find ZIP end-of-central-directory to bound ZIP-based containers."""
        start_pos = f.tell()
        source_size = source_path.stat().st_size
        max_size = min(500 * 1024 * 1024, source_size - offset)
        chunk_size = 1024 * 1024
        overlap = 66 * 1024
        pos = start_pos
        prev_bytes = b""

        while pos - start_pos < max_size:
            chunk = f.read(min(chunk_size, max_size - (pos - start_pos)))
            if not chunk:
                break

            combined = prev_bytes + chunk
            idx = combined.rfind(b"PK\x05\x06")
            if idx != -1 and len(combined) >= idx + 22:
                comment_len = struct.unpack("<H", combined[idx + 20 : idx + 22])[0]
                eocd_end = idx + 22 + comment_len
                if len(combined) >= eocd_end:
                    return pos - start_pos - len(prev_bytes) + eocd_end

            pos += len(chunk)
            prev_bytes = combined[-overlap:]

        return max_size

    def _find_jpeg_end(self, f) -> int:
        """Find JPEG EOF marker (FF D9)."""
        start_pos = f.tell()
        max_size = 100 * 1024 * 1024

        chunk_size = 1024 * 1024
        pos = start_pos
        prev_byte = b""

        while pos - start_pos < max_size:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            combined = prev_byte + chunk
            idx = combined.find(b"\xff\xd9")

            if idx != -1:
                return pos - start_pos - len(prev_byte) + idx + 2

            pos += len(chunk)
            prev_byte = combined[-1:]

        return min(max_size, pos - start_pos)

    def _find_png_end(self, f) -> int:
        """Find PNG IEND chunk."""
        start_pos = f.tell()
        max_size = 100 * 1024 * 1024

        chunk_size = 1024 * 1024
        pos = start_pos
        prev_bytes = b""

        while pos - start_pos < max_size:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            combined = prev_bytes + chunk
            idx = combined.find(b"IEND")

            if idx != -1:
                return pos - start_pos - len(prev_bytes) + idx + 8

            pos += len(chunk)
            prev_bytes = combined[-4:]

        return min(max_size, pos - start_pos)

    def _find_pdf_end(self, f, offset: int, source_path: Path) -> int:
        """Find the last PDF EOF marker within the carving window."""
        start_pos = f.tell()
        source_size = source_path.stat().st_size
        max_size = min(500 * 1024 * 1024, source_size - offset)

        chunk_size = 1024 * 1024
        pos = start_pos
        prev_bytes = b""
        eof_end = 0

        while pos - start_pos < max_size:
            chunk = f.read(min(chunk_size, max_size - (pos - start_pos)))
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
                file_size_field = struct.unpack_from("<I", data, 2)[0]
                if not (int(len(data) * 0.8) <= file_size_field <= int(len(data) * 1.2)):
                    raise ValidationError(
                        f"BMP: file_size field {file_size_field} "
                        f"inconsistent with carved size {len(data)}"
                    )
                pixel_offset = struct.unpack_from("<I", data, 10)[0]
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
                    page_size = struct.unpack(">H", data[16:18])[0]
                    if page_size == 1:
                        page_size = 65536
                    if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)) != 0:
                        raise ValidationError(f"SQLite: Invalid page size {page_size}")
                    return f"SQLite validated: page size {page_size}"
                except struct.error as e:
                    raise ValidationError("SQLite: Cannot read page size") from e

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
