# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential. Unauthorized use, copying, modification, or distribution is prohibited.
"""Forensic file classifier: entropy analysis, category detection, relevance scoring."""

import math
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ForensicCategory(str, Enum):
    """Forensic evidence category for triage and prioritisation."""

    DOCUMENT = "document"       # PDF, DOCX, XLSX, RTF, TXT …
    IMAGE = "image"             # JPEG, PNG, GIF, TIFF, PSD, HEIC, WebP …
    VIDEO = "video"             # MP4, AVI, MOV, MKV …
    AUDIO = "audio"             # MP3, WAV, FLAC, AAC …
    ARCHIVE = "archive"         # ZIP, 7Z, RAR, TAR …
    EXECUTABLE = "executable"   # PE (EXE/DLL), ELF, Mach-O, script …
    DATABASE = "database"       # SQLite, MDB …
    NETWORK = "network"         # PCAP, PCAPNG …
    EMAIL = "email"             # EML, PST, MSG, OST …
    SYSTEM = "system"           # EVTX, LNK, Windows Registry hive …
    CRYPTOGRAPHIC = "crypto"    # High-entropy – possibly encrypted/compressed
    UNKNOWN = "unknown"         # Could not classify


# Map canonical file-type strings to forensic categories
_TYPE_CATEGORY: dict[str, ForensicCategory] = {
    # documents
    "pdf": ForensicCategory.DOCUMENT,
    "docx": ForensicCategory.DOCUMENT,
    "xlsx": ForensicCategory.DOCUMENT,
    "pptx": ForensicCategory.DOCUMENT,
    "doc": ForensicCategory.DOCUMENT,
    "xls": ForensicCategory.DOCUMENT,
    "ppt": ForensicCategory.DOCUMENT,
    "rtf": ForensicCategory.DOCUMENT,
    "txt": ForensicCategory.DOCUMENT,
    "odt": ForensicCategory.DOCUMENT,
    "ods": ForensicCategory.DOCUMENT,
    "odp": ForensicCategory.DOCUMENT,
    "xml": ForensicCategory.DOCUMENT,
    "html": ForensicCategory.DOCUMENT,
    "htm": ForensicCategory.DOCUMENT,
    "csv": ForensicCategory.DOCUMENT,
    "json": ForensicCategory.DOCUMENT,
    # images
    "jpeg": ForensicCategory.IMAGE,
    "jpg": ForensicCategory.IMAGE,
    "png": ForensicCategory.IMAGE,
    "gif": ForensicCategory.IMAGE,
    "tiff": ForensicCategory.IMAGE,
    "tif": ForensicCategory.IMAGE,
    "bmp": ForensicCategory.IMAGE,
    "psd": ForensicCategory.IMAGE,
    "heic": ForensicCategory.IMAGE,
    "heif": ForensicCategory.IMAGE,
    "webp": ForensicCategory.IMAGE,
    "svg": ForensicCategory.IMAGE,
    # video
    "mp4": ForensicCategory.VIDEO,
    "avi": ForensicCategory.VIDEO,
    "mov": ForensicCategory.VIDEO,
    "mkv": ForensicCategory.VIDEO,
    "wmv": ForensicCategory.VIDEO,
    "flv": ForensicCategory.VIDEO,
    "m4v": ForensicCategory.VIDEO,
    # audio
    "mp3": ForensicCategory.AUDIO,
    "wav": ForensicCategory.AUDIO,
    "flac": ForensicCategory.AUDIO,
    "aac": ForensicCategory.AUDIO,
    "ogg": ForensicCategory.AUDIO,
    "wma": ForensicCategory.AUDIO,
    "m4a": ForensicCategory.AUDIO,
    # archives
    "zip": ForensicCategory.ARCHIVE,
    "7z": ForensicCategory.ARCHIVE,
    "rar": ForensicCategory.ARCHIVE,
    "tar": ForensicCategory.ARCHIVE,
    "gz": ForensicCategory.ARCHIVE,
    "bz2": ForensicCategory.ARCHIVE,
    "xz": ForensicCategory.ARCHIVE,
    # executables
    "pe": ForensicCategory.EXECUTABLE,
    "elf": ForensicCategory.EXECUTABLE,
    "script": ForensicCategory.EXECUTABLE,
    "macho": ForensicCategory.EXECUTABLE,
    # databases
    "sqlite": ForensicCategory.DATABASE,
    "db": ForensicCategory.DATABASE,
    "mdb": ForensicCategory.DATABASE,
    "accdb": ForensicCategory.DATABASE,
    # network captures
    "pcap": ForensicCategory.NETWORK,
    "pcapng": ForensicCategory.NETWORK,
    # email
    "eml": ForensicCategory.EMAIL,
    "pst": ForensicCategory.EMAIL,
    "ost": ForensicCategory.EMAIL,
    "msg": ForensicCategory.EMAIL,
    "ole": ForensicCategory.EMAIL,
    # system artifacts
    "evtx": ForensicCategory.SYSTEM,
    "lnk": ForensicCategory.SYSTEM,
    "reg": ForensicCategory.SYSTEM,
    "hive": ForensicCategory.SYSTEM,
    "prefetch": ForensicCategory.SYSTEM,
    # crypto / unknown
    "bin": ForensicCategory.UNKNOWN,
}

# Entropy thresholds
ENTROPY_HIGH = 7.5    # likely encrypted or compressed
ENTROPY_MEDIUM = 6.5  # possibly compressed or encoded
ENTROPY_LOW = 3.0     # text / structured data


@dataclass
class ClassificationResult:
    """Result of classifying a single file."""

    file_type: str
    category: ForensicCategory
    entropy: float
    entropy_label: str        # LOW / MEDIUM / HIGH / ENCRYPTED
    possibly_encrypted: bool
    forensic_priority: str    # CRITICAL / HIGH / MEDIUM / LOW
    notes: list[str]


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits per byte) for a byte sequence.

    Returns a value in [0.0, 8.0].  Truly random / encrypted data approaches 8.0.
    """
    if not data:
        return 0.0
    counts: list[int] = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_label(entropy: float) -> str:
    """Human-readable label for an entropy value."""
    if entropy >= ENTROPY_HIGH:
        return "ENCRYPTED"
    if entropy >= ENTROPY_MEDIUM:
        return "HIGH"
    if entropy >= ENTROPY_LOW:
        return "MEDIUM"
    return "LOW"


def classify_file(
    file_path: Path,
    file_type: str,
    sample_bytes: int = 65536,
) -> ClassificationResult:
    """Classify a file by forensic category and compute its entropy.

    Args:
        file_path:    Path to the file on disk.
        file_type:    Canonical type string from carver/recovery detection.
        sample_bytes: Number of bytes to read for entropy calculation.

    Returns:
        ClassificationResult with category, entropy, priority and notes.
    """
    category = _TYPE_CATEGORY.get(file_type.lower(), ForensicCategory.UNKNOWN)
    notes: list[str] = []

    # Read sample for entropy
    try:
        with file_path.open("rb") as fh:
            sample = fh.read(sample_bytes)
    except OSError:
        sample = b""

    entropy = shannon_entropy(sample)
    elabel = entropy_label(entropy)
    possibly_encrypted = entropy >= ENTROPY_HIGH

    # Override category for high-entropy unknown files
    if possibly_encrypted and category == ForensicCategory.UNKNOWN:
        category = ForensicCategory.CRYPTOGRAPHIC
        notes.append("High entropy – may be encrypted, encoded or compressed")

    # Archive types naturally have high entropy – don't flag them
    if possibly_encrypted and category == ForensicCategory.ARCHIVE:
        possibly_encrypted = False  # already compressed, entropy expected

    # OLE container disambiguation
    if file_type == "ole":
        ole_sub = _disambiguate_ole(sample)
        if ole_sub:
            notes.append(f"OLE sub-type detected: {ole_sub}")
            category = _TYPE_CATEGORY.get(ole_sub, ForensicCategory.DOCUMENT)

    # Forensic priority
    priority = _compute_priority(category, file_type, entropy, file_path)

    return ClassificationResult(
        file_type=file_type,
        category=category,
        entropy=round(entropy, 4),
        entropy_label=elabel,
        possibly_encrypted=possibly_encrypted,
        forensic_priority=priority,
        notes=notes,
    )


def classify_bytes(
    data: bytes,
    file_type: str,
) -> ClassificationResult:
    """Classify from an in-memory byte sequence (no file I/O needed)."""
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        return classify_file(tmp_path, file_type, sample_bytes=len(data))
    finally:
        tmp_path.unlink(missing_ok=True)


# ──────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────

def _compute_priority(
    category: ForensicCategory,
    file_type: str,
    entropy: float,
    file_path: Path,
) -> str:
    """Assign a forensic triage priority level."""
    # Executables are always critical
    if category == ForensicCategory.EXECUTABLE:
        return "CRITICAL"
    # Encrypted blobs of significant size are critical
    if entropy >= ENTROPY_HIGH and file_path.stat().st_size > 1024:
        return "CRITICAL"
    # Evidence-rich types
    if category in (
        ForensicCategory.EMAIL,
        ForensicCategory.DATABASE,
        ForensicCategory.NETWORK,
        ForensicCategory.SYSTEM,
        ForensicCategory.CRYPTOGRAPHIC,
    ):
        return "HIGH"
    # Documents and images often hold key evidence
    if category in (ForensicCategory.DOCUMENT, ForensicCategory.IMAGE):
        return "MEDIUM"
    # Media and archives – lower immediate priority
    if category in (ForensicCategory.VIDEO, ForensicCategory.AUDIO):
        return "LOW"
    if category == ForensicCategory.ARCHIVE:
        return "MEDIUM"
    return "LOW"


def _disambiguate_ole(data: bytes) -> Optional[str]:
    """Try to identify the specific OLE document type from the directory stream.

    Returns a subtype string such as 'msg', 'doc', 'xls', 'ppt', or None.
    """
    if len(data) < 512:
        return None

    # Root entry name in OLE is at a fixed position; look for known class GUIDs
    # or well-known compound-stream entry name markers in the first sector.
    msg_marker = b"Message\x00"
    doc_markers = (b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t",)
    xls_markers = (b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k",)
    ppt_markers = (b"P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t",)

    search = data[:4096]

    if msg_marker in search:
        return "msg"
    for m in doc_markers:
        if m in search:
            return "doc"
    for m in xls_markers:
        if m in search:
            return "xls"
    for m in ppt_markers:
        if m in search:
            return "ppt"

    return None


def bulk_classify(
    paths_and_types: list[tuple[Path, str]],
    sample_bytes: int = 65536,
) -> list[ClassificationResult]:
    """Classify a list of (path, file_type) pairs in order."""
    results = []
    for path, ftype in paths_and_types:
        try:
            result = classify_file(path, ftype, sample_bytes=sample_bytes)
        except Exception:
            result = ClassificationResult(
                file_type=ftype,
                category=ForensicCategory.UNKNOWN,
                entropy=0.0,
                entropy_label="LOW",
                possibly_encrypted=False,
                forensic_priority="LOW",
                notes=["Classification failed"],
            )
        results.append(result)
    return results
