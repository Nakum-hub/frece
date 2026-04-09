"""Pytest configuration and shared fixtures."""

import io
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_jpeg_data():
    """Sample JPEG file with SOI and EOI markers."""
    return b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 100 + b"\xff\xd9"


@pytest.fixture
def sample_png_data():
    """Sample PNG file with IHDR chunk."""
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\x0dIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde"
        + b"\x00" * 50
    )


@pytest.fixture
def sample_eml_data():
    """Sample EML file with RFC 2822 header."""
    return b"From user@example.com\nTo: recipient@example.com\nSubject: Test\n" + b"Body\n"


@pytest.fixture
def sample_docx_data():
    """Minimal DOCX (ZIP with word/ entry in local file header)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


@pytest.fixture
def sample_xlsx_data():
    """Minimal XLSX (ZIP with xl/ entry)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml", "<workbook/>")
    return buf.getvalue()


@pytest.fixture
def sample_zip_data():
    """Sample ZIP file header (PK\x03\x04)."""
    return b"PK\x03\x04" + b"\x00" * 50


@pytest.fixture
def sample_wave_data():
    """Sample WAVE file (RIFF...WAVE)."""
    return b"RIFF\x24\x00\x00\x00WAVE" + b"\x00" * 30


@pytest.fixture
def sample_avi_data():
    """Sample AVI file (RIFF...AVI )."""
    return b"RIFF\x24\x00\x00\x00AVI " + b"\x00" * 30


@pytest.fixture
def sample_bmp_data():
    """Minimal valid BMP header (54 bytes)."""
    file_size = 54
    reserved = 0
    pixel_offset = 54
    header_size = 40
    width, height = 1, 1
    planes, bpp = 1, 24
    data = struct.pack(
        "<IIIIIIHHIIIIII",
        file_size, reserved, pixel_offset,
        header_size, width, height,
        planes, bpp, 0, 3, 0, 0, 0, 0,
    )
    return b"BM" + data


@pytest.fixture
def sample_gif_data():
    """Minimal GIF89a with trailer."""
    return (
        b"GIF89a"
        + b"\x01\x00\x01\x00\x80\x00\x00"
        + b"\xff\xff\xff\x00\x00\x00"
        + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        + b"\x02\x02\x44\x01\x00"
        + b"\x3b"
    )


@pytest.fixture
def sample_tiff_le_data():
    """Minimal little-endian TIFF."""
    return b"II" + struct.pack("<H", 42) + struct.pack("<I", 8) + b"\x00" * 20
