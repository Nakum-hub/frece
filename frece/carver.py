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

from frece.classifier import classify_file
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
    entropy: float = 0.0
    forensic_category: str = "unknown"
    forensic_priority: str = "LOW"
    possibly_encrypted: bool = False


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
    """File signatures and validation rules — 40+ forensic file types."""

    # Primary byte-sequence signatures.
    # Disambiguation into sub-types happens in StreamingCarver._disambiguate_type.
    SIGNATURES: dict[bytes, str] = {
        # ── Images ────────────────────────────────────────────────────────────
        b"\xff\xd8\xff": "jpeg",
        b"\x89PNG\r\n\x1a\n": "png",
        b"GIF89a": "gif",
        b"GIF87a": "gif",
        b"BM": "bmp",
        b"II\x2a\x00": "tiff",
        b"MM\x00\x2a": "tiff",
        b"8BPS": "psd",          # Adobe Photoshop
        # WebP: starts with RIFF (handled via RIFF disambiguation)
        # HEIC/HEIF: ftyp box, handled as heic_ftyp below

        # ── Documents ─────────────────────────────────────────────────────────
        b"%PDF": "pdf",
        b"{\rtf": "rtf",
        b"<?xml": "xml",
        b"<!DOCTYPE html": "html",
        b"<html": "html",

        # ── Office / OLE compound document ────────────────────────────────────
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "ole",  # DOC/XLS/PPT/MSG/PST

        # ── Archives ──────────────────────────────────────────────────────────
        b"PK\x03\x04": "zip",
        b"7z\xBC\xAF\x27\x1C": "7z",
        b"Rar!\x1A\x07\x00": "rar",        # RAR 4.x
        b"Rar!\x1A\x07\x01\x00": "rar",    # RAR 5.x
        b"\x1F\x8B": "gz",                  # gzip
        b"BZh": "bz2",                      # bzip2
        b"\xFD7zXZ\x00": "xz",             # XZ / LZMA2

        # ── Audio / Video ─────────────────────────────────────────────────────
        b"\xff\xfb": "mp3",
        b"\xff\xf3": "mp3",
        b"\xff\xf2": "mp3",
        b"ID3": "mp3",
        b"RIFF": "riff",                    # WAV / AVI / WebP (disambiguate)
        b"fLaC": "flac",
        b"OggS": "ogg",

        # ── MPEG-4 / QuickTime ftyp boxes ─────────────────────────────────────
        b"\x00\x00\x00\x18ftyp": "ftyp",   # covers MP4/MOV/M4V/HEIC/HEIF/…
        b"\x00\x00\x00\x1cftyp": "ftyp",
        b"\x00\x00\x00\x14ftyp": "ftyp",
        b"\x00\x00\x00\x20ftyp": "ftyp",
        b"\x00\x00\x00\x24ftyp": "ftyp",

        # ── Executables ───────────────────────────────────────────────────────
        b"MZ": "pe",                        # Windows PE: EXE / DLL / SYS / …
        b"\x7FELF": "elf",                  # Linux / Unix ELF

        # ── Windows forensic artifacts ────────────────────────────────────────
        b"ElfFile\x00": "evtx",            # Windows Event Log (.evtx)
        b"L\x00\x00\x00\x01\x14\x02\x00": "lnk",  # Windows Shell Link (.lnk)
        b"regf": "reg",                     # Windows Registry hive

        # ── Databases ─────────────────────────────────────────────────────────
        b"SQLite format 3\x00": "sqlite",

        # ── Network captures ──────────────────────────────────────────────────
        b"\xD4\xC3\xB2\xA1": "pcap",       # PCAP little-endian
        b"\xA1\xB2\xC3\xD4": "pcap",       # PCAP big-endian
        b"\xA1\xB2\x3C\x4D": "pcap",       # PCAP ns-resolution
        b"\x0A\x0D\x0D\x0A": "pcapng",     # PCAPNG

        # ── Email ─────────────────────────────────────────────────────────────
        b"From ": "eml",
        b"Return-Path:": "eml",
        b"Received:": "eml",
        b"MIME-Version:": "eml",

        # ── Scripts / code ────────────────────────────────────────────────────
        b"#!/": "script",
        b"<?php": "php",

        # ── Crypto / forensic containers ─────────────────────────────────────
        b"-----BEGIN ": "pem",             # PEM certificate / key
    }

    # Signatures longer than this won't be split across chunk boundaries.
    MAX_SIGNATURE_LENGTH = 2048

    # Minimum file size to carve (bytes) — skip zero-byte false positives.
    MIN_CARVE_SIZE = 16

    @staticmethod
    def find_signatures(
        data: bytes, offset: int = 0
    ) -> Generator[tuple[int, str], None, None]:
        """Find all signatures in data chunk, yielding (absolute_offset, type)."""
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

            # Entropy + forensic classification
            try:
                cls_result = classify_file(output_file, file_type)
                carved_file.entropy = cls_result.entropy
                carved_file.forensic_category = cls_result.category.value
                carved_file.forensic_priority = cls_result.forensic_priority
                carved_file.possibly_encrypted = cls_result.possibly_encrypted
            except Exception:
                pass

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
            manifest_dict = manifest.to_dict()
            # Keep disk manifest consistent with CLI JSON output
            manifest_dict["manifest_path"] = str(manifest_path)
            manifest_dict["files_carved"] = len(carved_files)
            with open(manifest_path, "w", encoding="utf-8") as handle:
                json.dump(manifest_dict, handle, indent=2)
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

            if file_type in {"mp4", "mov", "heic", "m4v"}:
                return self._get_mp4_size(handle, offset, source_path)
            if file_type in {"zip", "docx", "xlsx", "pptx", "7z"}:
                return self._find_zip_end(handle, offset, source_path)
            if file_type == "pdf":
                return self._find_pdf_end(handle, offset, source_path)
            if file_type == "jpeg":
                return self._find_jpeg_end(handle)
            if file_type == "png":
                return self._find_png_end(handle)
            if file_type == "gif":
                return self._find_gif_end(handle)
            return self._estimate_file_size(file_type)

    def _disambiguate_type(
        self, source_path: Path, offset: int, types: list[str]
    ) -> str:
        """Resolve ambiguous signatures to a specific canonical type."""
        unique_types = set(types)

        # ── ftyp ISO Base Media (MP4, MOV, HEIC, HEIF, M4V, …) ──────────────
        if "ftyp" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset + 8)
                    brand = handle.read(4)
                    handle.seek(offset + 8)
                    brands_data = handle.read(64)
                    heic_brands = {b"heic", b"heix", b"hevc", b"hevx",
                                   b"mif1", b"msf1", b"avif", b"avis"}
                    if brand in heic_brands or any(b in brands_data for b in heic_brands):
                        return "heic"
                    qt_brands = {b"qt  ", b"mqt "}
                    if brand in qt_brands:
                        return "mov"
                    mp4_brands = {b"mp41", b"mp42", b"isom", b"M4V ",
                                  b"M4A ", b"f4v ", b"dash"}
                    if brand in mp4_brands or any(b in brands_data for b in mp4_brands):
                        return "mp4"
                    return "mp4"  # generic ftyp fallback
            except OSError:
                return "mp4"

        # ── RIFF container: WAV / AVI / WebP ─────────────────────────────────
        if "riff" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset + 8)
                    riff_type = handle.read(4)
                    if riff_type == b"WAVE":
                        return "wav"
                    if riff_type == b"AVI ":
                        return "avi"
                    if riff_type == b"WEBP":
                        return "webp"
            except OSError:
                pass
            return "riff"

        # ── ZIP / DOCX / XLSX / PPTX ─────────────────────────────────────────
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

        # ── OLE compound document: DOC / XLS / PPT / MSG ─────────────────────
        if "ole" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset)
                    sample = handle.read(4096)
                # Look for well-known OLE stream name markers
                if b"M\x00e\x00s\x00s\x00a\x00g\x00e" in sample:
                    return "msg"
                if b"W\x00o\x00r\x00d\x00D\x00o\x00c" in sample:
                    return "doc"
                if b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k" in sample:
                    return "xls"
                if b"P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t" in sample:
                    return "ppt"
            except OSError:
                pass
            return "ole"

        # ── EML: validate it has RFC-822 headers ─────────────────────────────
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

        # ── Script: check shebang line ────────────────────────────────────────
        if "script" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset)
                    line = handle.read(64)
                    if b"python" in line:
                        return "py"
                    if b"bash" in line or b"sh\n" in line:
                        return "sh"
                    if b"perl" in line:
                        return "pl"
                    if b"ruby" in line:
                        return "rb"
                    if b"node" in line or b"javascript" in line:
                        return "js"
                    return "script"
            except OSError:
                return "script"

        # ── PE: validate MZ header ────────────────────────────────────────────
        if "pe" in unique_types:
            try:
                with open(source_path, "rb") as handle:
                    handle.seek(offset)
                    header = handle.read(64)
                    if header[:2] == b"MZ":
                        # Check for valid PE offset
                        if len(header) >= 60:
                            pe_offset = struct.unpack_from("<I", header, 60)[0]
                            if 64 <= pe_offset <= 1024:
                                return "pe"
                        return "pe"
            except OSError:
                pass
            return "pe"

        # ── MP3: multiple signatures may overlap ─────────────────────────────
        if "mp3" in unique_types:
            return "mp3"

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
        """Validate a carved artifact — covers all 40+ supported types."""
        match file_type:
            # ── Images ───────────────────────────────────────────────────────
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
                if head[0:8] != b"\x89PNG\r\n\x1a\n":
                    raise ValidationError("PNG: Invalid signature")
                if head[12:16] != b"IHDR":
                    raise ValidationError("PNG: Invalid IHDR chunk")
                return "PNG validated: signature and IHDR present"

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

            case "bmp":
                head = self._read_prefix(output_file, 54)
                if len(head) < 54:
                    raise ValidationError("BMP too small")
                if head[0:2] != b"BM":
                    raise ValidationError("BMP: Invalid signature")
                file_size_field = int(struct.unpack_from("<I", head, 2)[0])
                if not (int(size * 0.8) <= file_size_field <= int(size * 1.2)):
                    raise ValidationError(
                        f"BMP: size field {file_size_field} vs carved {size}"
                    )
                pixel_offset = int(struct.unpack_from("<I", head, 10)[0])
                if pixel_offset < 26:
                    raise ValidationError(f"BMP: Invalid pixel offset {pixel_offset}")
                return "BMP validated: signature and size field consistent"

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
                    raise ValidationError(f"TIFF: Invalid magic {magic}")
                endian = "little" if byte_order == b"II" else "big"
                return f"TIFF validated: {endian}-endian"

            case "psd":
                head = self._read_prefix(output_file, 6)
                if len(head) < 6 or head[0:4] != b"8BPS":
                    raise ValidationError("PSD: Invalid signature")
                version = struct.unpack_from(">H", head, 4)[0]
                if version not in (1, 2):
                    raise ValidationError(f"PSD: Invalid version {version}")
                return f"PSD validated: version {version}"

            # ── Documents ────────────────────────────────────────────────────
            case "pdf":
                if not self._file_contains_any(output_file, (b"xref", b"stream")):
                    raise ValidationError("PDF: No xref or stream found")
                return "PDF validated: xref/stream present"

            case "rtf":
                head = self._read_prefix(output_file, 6)
                if not head.startswith(b"{\\rtf"):
                    raise ValidationError("RTF: Missing {\\rtf header")
                return "RTF validated: header present"

            case "xml":
                head = self._read_prefix(output_file, 64)
                text = head.decode("utf-8", errors="ignore").lstrip()
                if not (text.startswith("<?xml") or text.startswith("<")):
                    raise ValidationError("XML: No opening tag found")
                return "XML validated: opening tag present"

            case "html" | "htm":
                head = self._read_prefix(output_file, 256)
                text = head.lower().decode("utf-8", errors="ignore")
                if "<!doctype" not in text and "<html" not in text:
                    raise ValidationError("HTML: No DOCTYPE or <html> tag")
                return "HTML validated: root element present"

            # ── Office / OLE ─────────────────────────────────────────────────
            case "ole" | "doc" | "xls" | "ppt" | "msg":
                head = self._read_prefix(output_file, 8)
                if head != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
                    raise ValidationError("OLE: Invalid compound document signature")
                return "OLE validated: compound document signature"

            # ── Archives ─────────────────────────────────────────────────────
            case "zip" | "docx" | "xlsx" | "pptx" | "odt":
                head = self._read_prefix(output_file, 4)
                if head[:4] not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
                    raise ValidationError("ZIP: Invalid PK signature")
                return "ZIP validated: PK signature present"

            case "7z":
                head = self._read_prefix(output_file, 6)
                if head != b"7z\xBC\xAF\x27\x1C":
                    raise ValidationError("7z: Invalid signature")
                return "7z validated"

            case "rar":
                head = self._read_prefix(output_file, 8)
                v4 = head[:7] == b"Rar!\x1A\x07\x00"
                v5 = head[:8] == b"Rar!\x1A\x07\x01\x00"
                if not (v4 or v5):
                    raise ValidationError("RAR: Invalid signature")
                return f"RAR validated: {'5.x' if v5 else '4.x'}"

            case "gz":
                head = self._read_prefix(output_file, 3)
                if head[:2] != b"\x1f\x8b":
                    raise ValidationError("GZ: Invalid magic")
                return f"GZ validated: method=0x{head[2]:02x}"

            case "bz2":
                head = self._read_prefix(output_file, 3)
                if not head.startswith(b"BZh"):
                    raise ValidationError("BZ2: Invalid header")
                return "BZ2 validated: BZh header present"

            case "xz":
                head = self._read_prefix(output_file, 6)
                if head != b"\xFD7zXZ\x00":
                    raise ValidationError("XZ: Invalid magic")
                return "XZ validated"

            # ── Audio ─────────────────────────────────────────────────────────
            case "mp3":
                head = self._read_prefix(output_file, 4)
                if len(head) < 3:
                    raise ValidationError("MP3 too small")
                if head[:3] == b"ID3":
                    return "MP3 validated: ID3 tag present"
                if head[0:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
                    return "MP3 validated: frame sync present"
                raise ValidationError("MP3: No ID3 tag or frame sync")

            case "flac":
                head = self._read_prefix(output_file, 4)
                if head != b"fLaC":
                    raise ValidationError("FLAC: Invalid marker")
                return "FLAC validated"

            case "ogg":
                head = self._read_prefix(output_file, 4)
                if head != b"OggS":
                    raise ValidationError("OGG: Invalid capture pattern")
                return "OGG validated"

            # ── Databases ─────────────────────────────────────────────────────
            case "sqlite":
                head = self._read_prefix(output_file, 20)
                if len(head) < 20:
                    raise ValidationError("SQLite too small")
                if head[:16] != b"SQLite format 3\x00":
                    raise ValidationError("SQLite: Invalid header string")
                try:
                    page_size = struct.unpack(">H", head[16:18])[0]
                    if page_size == 1:
                        page_size = 65536
                    if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)):
                        raise ValidationError(f"SQLite: Invalid page size {page_size}")
                    return f"SQLite validated: page_size={page_size}"
                except struct.error as exc:
                    raise ValidationError("SQLite: Cannot read page size") from exc

            # ── Executables ───────────────────────────────────────────────────
            case "pe":
                head = self._read_prefix(output_file, 64)
                if len(head) < 4 or head[0:2] != b"MZ":
                    raise ValidationError("PE: Missing MZ signature")
                if len(head) >= 60:
                    pe_off = struct.unpack_from("<I", head, 60)[0]
                    if 64 <= pe_off <= 1024:
                        pe_head = self._read_prefix(output_file, pe_off + 4)
                        if len(pe_head) >= pe_off + 4:
                            if pe_head[pe_off:pe_off + 4] == b"PE\x00\x00":
                                return f"PE validated: MZ + PE at offset {pe_off}"
                return "PE validated: MZ signature (PE header unconfirmed)"

            case "elf":
                head = self._read_prefix(output_file, 16)
                if len(head) < 16 or head[0:4] != b"\x7fELF":
                    raise ValidationError("ELF: Invalid magic bytes")
                bits = {1: "32-bit", 2: "64-bit"}.get(head[4], f"cls-{head[4]}")
                endian = {1: "LE", 2: "BE"}.get(head[5], "?E")
                return f"ELF validated: {bits} {endian}"

            # ── Windows artifacts ─────────────────────────────────────────────
            case "evtx":
                head = self._read_prefix(output_file, 8)
                if head[:8] != b"ElfFile\x00":
                    raise ValidationError("EVTX: Invalid ElfFile signature")
                return "EVTX validated"

            case "lnk":
                head = self._read_prefix(output_file, 4)
                if head != b"L\x00\x00\x00":
                    raise ValidationError("LNK: Invalid header size field")
                return "LNK validated: Shell Link header present"

            case "reg":
                head = self._read_prefix(output_file, 4)
                if head != b"regf":
                    raise ValidationError("REG: Invalid hive signature")
                return "Registry hive validated: regf signature"

            # ── Network ───────────────────────────────────────────────────────
            case "pcap":
                head = self._read_prefix(output_file, 24)
                if len(head) < 24:
                    raise ValidationError("PCAP too small")
                magic = head[0:4]
                valid = (b"\xD4\xC3\xB2\xA1", b"\xA1\xB2\xC3\xD4", b"\xA1\xB2\x3C\x4D")
                if magic not in valid:
                    raise ValidationError(f"PCAP: Invalid magic {magic.hex()}")
                endian = "<" if magic[0:1] == b"\xD4" else ">"
                link_type = struct.unpack_from(f"{endian}I", head, 20)[0]
                return f"PCAP validated: link_type={link_type}"

            case "pcapng":
                head = self._read_prefix(output_file, 12)
                if len(head) < 12 or head[0:4] != b"\x0A\x0D\x0D\x0A":
                    raise ValidationError("PCAPng: Invalid Section Header Block")
                return "PCAPng validated: SHB magic present"

            # ── Email ─────────────────────────────────────────────────────────
            case "eml":
                head = self._read_prefix(output_file, 512)
                text = head.decode("utf-8", errors="ignore")
                rfc822_starts = (
                    "From ", "Return-Path:", "Received:", "MIME-Version:",
                    "Date:", "Subject:", "To:", "Message-ID:",
                )
                if not any(text.startswith(h) for h in rfc822_starts):
                    raise ValidationError("EML: No recognized RFC-822 header")
                return "EML validated: RFC-822 header present"

            # ── Scripts ───────────────────────────────────────────────────────
            case "script" | "py" | "sh" | "pl" | "rb" | "js":
                head = self._read_prefix(output_file, 8)
                if head.startswith(b"#!"):
                    return "Script validated: shebang present"
                return "Script: no shebang (may still be valid)"

            case "php":
                head = self._read_prefix(output_file, 64)
                if b"<?php" not in head and b"<?" not in head:
                    raise ValidationError("PHP: No opening tag found")
                return "PHP validated: opening tag present"

            # ── Crypto ────────────────────────────────────────────────────────
            case "pem":
                head = self._read_prefix(output_file, 64)
                text = head.decode("utf-8", errors="ignore")
                if "-----BEGIN " not in text:
                    raise ValidationError("PEM: Missing BEGIN marker")
                kind = text.split("-----BEGIN ")[1].split("-----")[0]
                return f"PEM validated: {kind}"

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
        """Validate carved bytes; delegates to _validate_output_file via a temp path.

        This entry-point exists for callers that already have the raw bytes in
        memory (e.g. small-file carving path, tests).  It writes the bytes to a
        temporary file so that the single _validate_output_file implementation
        is authoritative for all validation logic.
        """
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)

        try:
            return self._validate_output_file(file_type, tmp_path, len(data))
        finally:
            tmp_path.unlink(missing_ok=True)

    def _find_gif_end(self, handle: BinaryIO) -> int:
        """Find GIF trailer byte (0x3B)."""
        start_pos = handle.tell()
        max_size = 50 * 1024 * 1024  # 50 MB max GIF

        chunk_size = 512 * 1024
        pos = start_pos
        prev_byte = b""

        while pos - start_pos < max_size:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            combined = prev_byte + chunk
            idx = combined.rfind(b"\x3b")
            if idx != -1:
                return pos - start_pos - len(prev_byte) + idx + 1
            pos += len(chunk)
            prev_byte = combined[-1:]

        return min(max_size, pos - start_pos)

    def _estimate_file_size(self, file_type: str) -> int:
        """Estimate carving size limit by type."""
        sizes: dict[str, int] = {
            # images
            "jpeg": 50 * 1024 * 1024,
            "png": 100 * 1024 * 1024,
            "gif": 50 * 1024 * 1024,
            "bmp": 100 * 1024 * 1024,
            "tiff": 500 * 1024 * 1024,
            "psd": 500 * 1024 * 1024,
            "webp": 50 * 1024 * 1024,
            "heic": 50 * 1024 * 1024,
            # documents
            "pdf": 500 * 1024 * 1024,
            "rtf": 50 * 1024 * 1024,
            "xml": 50 * 1024 * 1024,
            "html": 10 * 1024 * 1024,
            # office
            "zip": 500 * 1024 * 1024,
            "docx": 500 * 1024 * 1024,
            "xlsx": 500 * 1024 * 1024,
            "pptx": 500 * 1024 * 1024,
            "doc": 50 * 1024 * 1024,
            "xls": 50 * 1024 * 1024,
            "ppt": 50 * 1024 * 1024,
            "ole": 50 * 1024 * 1024,
            "msg": 50 * 1024 * 1024,
            # archives
            "7z": 2 * 1024 * 1024 * 1024,
            "rar": 2 * 1024 * 1024 * 1024,
            "gz": 500 * 1024 * 1024,
            "bz2": 500 * 1024 * 1024,
            "xz": 500 * 1024 * 1024,
            # audio
            "mp3": 500 * 1024 * 1024,
            "wav": 2 * 1024 * 1024 * 1024,
            "flac": 500 * 1024 * 1024,
            "ogg": 500 * 1024 * 1024,
            # video
            "avi": 2 * 1024 * 1024 * 1024,
            "wmv": 2 * 1024 * 1024 * 1024,
            # executables
            "pe": 100 * 1024 * 1024,
            "elf": 100 * 1024 * 1024,
            # forensic
            "evtx": 500 * 1024 * 1024,
            "lnk": 4 * 1024,
            "reg": 100 * 1024 * 1024,
            "sqlite": 500 * 1024 * 1024,
            # network
            "pcap": 2 * 1024 * 1024 * 1024,
            "pcapng": 2 * 1024 * 1024 * 1024,
            # scripts / misc
            "script": 1 * 1024 * 1024,
            "py": 1 * 1024 * 1024,
            "sh": 1 * 1024 * 1024,
            "php": 1 * 1024 * 1024,
            "pem": 32 * 1024,
            "eml": 50 * 1024 * 1024,
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
