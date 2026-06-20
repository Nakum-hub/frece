# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""E01 / EWF (Expert Witness Format) forensic image adapter.

Supports reading E01, E01x, Ex01, S01, AFF and other formats that ship
with the libewf / ewf-tools suite.  We use the installed CLI tools
(ewfinfo, ewfmount, ewfexport) rather than a Python binding because
libewf's Python API is rarely pre-built and the CLI tools are standard
on forensic workstations.

Usage in FRECE commands:
    frece carve evidence.E01          # auto-detected
    frece recover evidence.E01
    frece scan evidence.E01
    frece hash evidence.E01

The adapter transparently:
  1. Detects E01/EWF/AFF by file extension and magic bytes
  2. Exports a raw stream via ewfexport --target=/tmp/frece_ewf_XXXX.raw
  3. Returns the temporary raw path to the caller
  4. Cleans up the temp file when done (context manager)
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


# Magic bytes that identify EWF segments
_EWF_MAGIC = b"EVF"
_LEWA_MAGIC = b"LVF"   # Smart
_AFF_MAGIC = b"\xd0\x0d\xfb\xfb"

# Extensions that are likely EWF/AFF
EWF_EXTENSIONS = {
    ".e01", ".e02", ".e03", ".ex01", ".s01", ".l01", ".lx01",
    ".aff", ".afd", ".afm",
}


def is_ewf_image(path: Path) -> bool:
    """Return True if *path* appears to be an EWF/AFF forensic image."""
    if path.suffix.lower() in EWF_EXTENSIONS:
        return True
    try:
        magic = path.read_bytes()[:4]
        return magic[:3] in (_EWF_MAGIC, _LEWA_MAGIC) or magic == _AFF_MAGIC
    except OSError:
        return False


def ewfinfo(image_path: Path) -> dict:
    """Run ewfinfo and return parsed metadata as a dict."""
    result: dict = {
        "image_path": str(image_path),
        "format": "EWF/E01",
    }

    try:
        # "ewfinfo" is a standard forensic tool expected on PATH (ewf-tools
        # package). Partial path is intentional — operators may have it in
        # a custom PATH location (e.g. virtualenv, /opt/forensics/bin).
        proc = subprocess.run(  # nosec B603 B607
            ["ewfinfo", str(image_path)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        output = proc.stdout + proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["ewfinfo_error"] = "ewfinfo not found — install ewf-tools"
        return result

    patterns = {
        "case_number": r"Case number:\s*(.+)",
        "description": r"Description:\s*(.+)",
        "examiner": r"Examiner name:\s*(.+)",
        "evidence_number": r"Evidence number:\s*(.+)",
        "notes": r"Notes:\s*(.+)",
        "acquired_date": r"Acquired date:\s*(.+)",
        "system_date": r"System date:\s*(.+)",
        "operating_system": r"Operating system used:\s*(.+)",
        "software_version": r"Software version:\s*(.+)",
        "password": r"Password:\s*(.+)",
        "compression": r"Compression method:\s*(.+)",
        "media_size": r"Media size:\s*(.+)",
        "media_type": r"Media type:\s*(.+)",
        "bytes_per_sector": r"Bytes per sector:\s*(\d+)",
        "number_of_sectors": r"Number of sectors:\s*(\d+)",
        "md5_hash": r"MD5 hash:\s*([0-9a-fA-F]+)",
        "sha1_hash": r"SHA1 hash:\s*([0-9a-fA-F]+)",
        "sha256_hash": r"SHA256 hash:\s*([0-9a-fA-F]+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            result[key] = m.group(1).strip()

    return result


class EwfReader:
    """Context manager that exports an EWF image to a raw temporary file.

    Example::

        with EwfReader(Path("evidence.E01")) as raw_path:
            frece_carve(raw_path, output_dir)

    The temporary file is deleted when the context exits.
    """

    def __init__(
        self,
        image_path: Path,
        chunk_size_mb: int = 64,
        show_progress: bool = False,
    ) -> None:
        self.image_path = image_path
        self.chunk_size_mb = chunk_size_mb
        self.show_progress = show_progress
        self._tmp_dir: Optional[str] = None
        self._raw_path: Optional[Path] = None

    def __enter__(self) -> Path:
        self._tmp_dir = tempfile.mkdtemp(prefix="frece_ewf_")
        raw_path = Path(self._tmp_dir) / "evidence.raw"

        self._export(raw_path)
        self._raw_path = raw_path
        return raw_path

    def __exit__(self, *_: object) -> None:
        if self._tmp_dir:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def _export(self, output_path: Path) -> None:
        """Export EWF to raw using ewfexport."""
        if not shutil.which("ewfexport"):
            raise EwfError(
                "ewfexport not found",
                remediation="Install ewf-tools: apt-get install ewf-tools",
            )

        cmd = [
            "ewfexport",
            "-t", str(output_path.with_suffix("")),  # ewfexport adds .raw
            "-f", "raw",
            str(self.image_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=not self.show_progress,
                text=True,
                timeout=86400,  # 24h max
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise EwfError("ewfexport timed out") from exc
        except FileNotFoundError as exc:
            raise EwfError(
                "ewfexport not found",
                remediation="Install ewf-tools: apt-get install ewf-tools",
            ) from exc

        # ewfexport writes to output_path.raw
        exported = output_path.with_suffix("").with_suffix(".raw")
        if not exported.exists():
            exported = output_path  # some versions write without extension

        if not exported.exists():
            raise EwfError(
                f"ewfexport failed: {result.stderr[:200] if result else 'unknown'}",
                remediation="Check the E01 file is not corrupted and ewf-tools is installed",
            )

        if exported != output_path:
            exported.rename(output_path)

    @property
    def raw_path(self) -> Optional[Path]:
        """The exported raw file path (only valid inside the context)."""
        return self._raw_path


def open_image(image_path: Path, show_progress: bool = False) -> "ImageHandle":
    """Open any forensic image format, returning a unified handle.

    For raw images (.dd, .img, .bin, etc.) the handle wraps the path directly.
    For EWF/E01 images the handle exports to a temp raw file transparently.

    Example::

        with open_image(Path("evidence.E01")) as handle:
            raw_path = handle.raw_path
            run_carve(raw_path, output_dir)
    """
    if is_ewf_image(image_path):
        return EwfImageHandle(image_path, show_progress=show_progress)
    return RawImageHandle(image_path)


class ImageHandle:
    """Base class for unified image handles."""

    def __enter__(self) -> "ImageHandle":
        return self

    def __exit__(self, *_: object) -> None:
        pass

    @property
    def raw_path(self) -> Path:
        raise NotImplementedError

    @property
    def image_info(self) -> dict:
        return {}


class RawImageHandle(ImageHandle):
    """Handle for raw (.dd/.img) images — no conversion needed."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def raw_path(self) -> Path:
        return self._path

    @property
    def image_info(self) -> dict:
        return {
            "format": "raw",
            "image_path": str(self._path),
            "size_bytes": self._path.stat().st_size if self._path.exists() else 0,
        }


class EwfImageHandle(ImageHandle):
    """Handle for EWF/E01 images — exports to temp raw on enter."""

    def __init__(self, path: Path, show_progress: bool = False) -> None:
        self._path = path
        self._reader = EwfReader(path, show_progress=show_progress)
        self._raw: Optional[Path] = None
        self._info: dict = {}

    def __enter__(self) -> "EwfImageHandle":
        # Gather metadata before export (fast)
        self._info = ewfinfo(self._path)
        self._raw = self._reader.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._reader.__exit__(*args)
        self._raw = None

    @property
    def raw_path(self) -> Path:
        if self._raw is None:
            raise EwfError("EwfImageHandle not entered — use as context manager")
        return self._raw

    @property
    def image_info(self) -> dict:
        return self._info


class EwfError(Exception):
    """Raised when EWF operations fail."""

    def __init__(self, message: str, remediation: str = "") -> None:
        super().__init__(message)
        self.remediation = remediation
