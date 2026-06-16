# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential. Unauthorized use, copying, modification, or distribution is prohibited.
"""Recovery confidence scoring system.

Produces a 0-100 confidence score for each carved or recovered artifact based
on multiple forensic evidence dimensions.  No other CLI carving tool does this
systematically — it is a key differentiator over PhotoRec, Foremost, Scalpel
and Bulk Extractor.

Score components (each 0-25 points):
  S1 Structural integrity  — header/footer validation result
  S2 Entropy plausibility  — entropy consistent with claimed file type
  S3 Size plausibility     — size within expected range for the type
  S4 Metadata presence     — file-type-specific metadata extractable

Final grade:
  90-100 : CONFIRMED   — high confidence, court-presentable
  75-89  : PROBABLE    — strong evidence, minor anomalies
  50-74  : POSSIBLE    — partial evidence, manual review recommended
  25-49  : SUSPECT     — structural issues, low reliability
  0-24   : REJECTED    — likely false positive, do not present as evidence
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


# Expected entropy ranges per type (min, max) for non-encrypted content
_ENTROPY_RANGES: dict[str, tuple[float, float]] = {
    "jpeg":   (3.0, 7.9),
    "png":    (4.5, 7.9),
    "gif":    (2.0, 7.5),
    "bmp":    (1.0, 7.5),
    "tiff":   (2.0, 7.5),
    "psd":    (2.0, 7.5),
    "pdf":    (3.5, 7.9),
    "docx":   (3.5, 7.5),
    "xlsx":   (3.5, 7.5),
    "pptx":   (3.5, 7.5),
    "rtf":    (2.0, 6.0),
    "xml":    (2.0, 6.5),
    "html":   (2.0, 6.5),
    "eml":    (1.5, 6.5),
    "zip":    (5.5, 8.0),
    "7z":     (5.5, 8.0),
    "rar":    (5.5, 8.0),
    "gz":     (5.5, 8.0),
    "mp3":    (5.5, 8.0),
    "wav":    (4.0, 8.0),
    "flac":   (5.0, 8.0),
    "ogg":    (5.0, 8.0),
    "mp4":    (5.5, 8.0),
    "avi":    (4.5, 8.0),
    "mov":    (5.0, 8.0),
    "sqlite": (0.0, 7.0),
    "pe":     (3.0, 7.5),
    "elf":    (3.0, 7.5),
    "pcap":   (1.0, 7.5),
    "pcapng": (1.0, 7.5),
    "evtx":   (1.0, 6.5),
    "lnk":    (1.0, 6.0),
    "reg":    (1.0, 6.0),
    "ole":    (2.0, 7.5),
    "script": (1.5, 5.5),
    "py":     (1.5, 5.5),
    "sh":     (1.5, 5.0),
    "pem":    (1.5, 5.0),
}

# Minimum credible size (bytes) per type — below this is likely noise
_MIN_SIZES: dict[str, int] = {
    "jpeg": 100,
    "png": 40,
    "gif": 35,
    "bmp": 54,
    "tiff": 8,
    "psd": 26,
    "pdf": 30,
    "eml": 40,
    "sqlite": 1024,
    "pe": 100,
    "elf": 52,
    "pcap": 24,
    "pcapng": 28,
    "evtx": 512,
    "lnk": 76,
    "zip": 22,
    "7z": 32,
    "rar": 7,
    "mp3": 128,
    "wav": 44,
    "rtf": 10,
}


@dataclass
class ConfidenceScore:
    """Confidence assessment for a single recovered / carved artifact."""

    score: int                # 0-100
    grade: str                # CONFIRMED / PROBABLE / POSSIBLE / SUSPECT / REJECTED
    structural_score: int     # 0-25  — validation result
    entropy_score: int        # 0-25  — entropy plausibility
    size_score: int           # 0-25  — size plausibility
    metadata_score: int       # 0-25  — metadata extractable
    notes: list[str]          # human-readable score breakdown


def score_artifact(
    file_path: Path,
    file_type: str,
    entropy: float,
    validation_passed: bool,
    validation_notes: str,
    metadata: dict | None = None,
) -> ConfidenceScore:
    """Compute a 0-100 forensic confidence score for an artifact.

    Args:
        file_path:        Path to the file on disk.
        file_type:        Canonical type string ('jpeg', 'pe', …).
        entropy:          Pre-computed Shannon entropy (0-8).
        validation_passed: True when _validate_output_file succeeded.
        validation_notes: Text from the validator.
        metadata:         Optional dict from frece.metadata.extract().

    Returns:
        ConfidenceScore with all component scores and grade.
    """
    notes: list[str] = []

    # ── S1: Structural integrity (0-25) ─────────────────────────────────────
    if validation_passed:
        structural = 25
        notes.append("S1: Header/footer validation passed (+25)")
    else:
        structural = 0
        notes.append(f"S1: Validation failed — {validation_notes[:80]} (+0)")

    # ── S2: Entropy plausibility (0-25) ──────────────────────────────────────
    entropy_range = _ENTROPY_RANGES.get(file_type.lower())
    if entropy_range is None:
        entropy_s = 12  # unknown type — neutral score
        notes.append(f"S2: No entropy baseline for '{file_type}' (+12)")
    else:
        lo, hi = entropy_range
        if lo <= entropy <= hi:
            entropy_s = 25
            notes.append(f"S2: Entropy {entropy:.2f} within expected {lo:.1f}-{hi:.1f} (+25)")
        elif entropy < lo:
            gap = lo - entropy
            entropy_s = max(0, int(25 - gap * 8))
            notes.append(f"S2: Entropy {entropy:.2f} below minimum {lo:.1f} (+{entropy_s})")
        else:
            # above range — possibly encrypted / compressed within a non-expected type
            entropy_s = 5
            label = f"S2: Entropy {entropy:.2f} above max {hi:.1f} — may be encrypted (+5)"
            notes.append(label)

    # ── S3: Size plausibility (0-25) ─────────────────────────────────────────
    try:
        size = file_path.stat().st_size
    except OSError:
        size = 0

    min_size = _MIN_SIZES.get(file_type.lower(), 16)
    if size < min_size:
        size_s = 0
        notes.append(f"S3: Size {size} bytes below minimum {min_size} (+0)")
    elif size > 2 * 1024 * 1024 * 1024:  # >2GB likely over-carve
        size_s = 5
        notes.append(f"S3: Size {size // 1024 // 1024}MB suspiciously large (+5)")
    else:
        size_s = 25
        notes.append(f"S3: Size {size} bytes plausible (+25)")

    # ── S4: Metadata presence (0-25) ─────────────────────────────────────────
    if metadata is None:
        meta_s = 0
        notes.append("S4: No metadata extracted (+0)")
    elif metadata.get("extraction_error"):
        meta_s = 5
        notes.append(f"S4: Metadata error: {metadata['extraction_error'][:60]} (+5)")
    else:
        # Count meaningful fields (exclude bookkeeping keys)
        skip = {"file_type", "file_path", "extraction_error"}
        meaningful = {k: v for k, v in metadata.items() if k not in skip and v is not None}
        if len(meaningful) >= 3:
            meta_s = 25
            notes.append(f"S4: {len(meaningful)} metadata fields extracted (+25)")
        elif len(meaningful) >= 1:
            meta_s = 12
            notes.append(f"S4: {len(meaningful)} metadata field(s) extracted (+12)")
        else:
            meta_s = 0
            notes.append("S4: No meaningful metadata fields (+0)")

    total = structural + entropy_s + size_s + meta_s

    grade = (
        "CONFIRMED" if total >= 90
        else "PROBABLE" if total >= 75
        else "POSSIBLE" if total >= 50
        else "SUSPECT" if total >= 25
        else "REJECTED"
    )

    return ConfidenceScore(
        score=total,
        grade=grade,
        structural_score=structural,
        entropy_score=entropy_s,
        size_score=size_s,
        metadata_score=meta_s,
        notes=notes,
    )


def score_batch(
    artifacts: list[dict],
    base_dir: Path,
) -> list[dict]:
    """Score a list of artifact dicts (from carve/recovery manifest).

    Each dict is expected to have: file_type, entropy, validation_passed,
    validation_notes, and one of: offset (carve) or output_path (recovery).

    Returns the input dicts augmented with confidence_score, confidence_grade,
    and score_notes fields.
    """
    scored = []
    for art in artifacts:
        ftype = art.get("file_type", "bin")
        entropy = art.get("entropy", 0.0)
        val_ok = art.get("validation_passed", False)
        val_notes = art.get("validation_notes", "")
        # Use pre-computed metadata from manifest if available (Bug-C: same algo)
        metadata = art.get("artifact_metadata") or None

        # Find the file on disk — try output_path first, then reconstruct
        output_path = art.get("output_path") or art.get("carved_path")
        if not output_path:
            offset = art.get("offset", 0)
            fname = f"{offset:016x}_{ftype}"
            output_path = str(base_dir / fname)

        file_path = Path(output_path)

        cs = score_artifact(
            file_path=file_path,
            file_type=ftype,
            entropy=entropy,
            validation_passed=val_ok,
            validation_notes=val_notes,
            metadata=metadata,
        )

        art_copy = dict(art)
        art_copy["confidence_score"] = cs.score
        art_copy["confidence_grade"] = cs.grade
        art_copy["score_notes"] = cs.notes
        scored.append(art_copy)

    return scored
