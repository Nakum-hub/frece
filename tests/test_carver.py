"""Tests for StreamingCarver."""

import struct

import pytest

from frece.carver import StreamingCarver


class TestStreamingCarver:
    """Test streaming carver functionality."""

    @pytest.fixture
    def carver(self):
        """Create a carver instance."""
        return StreamingCarver(chunk_size=1024 * 1024)

    def test_carver_init(self, carver):
        """Test carver initialization."""
        assert carver.chunk_size == 1024 * 1024
        assert carver.max_sig_len == 2048

    def test_find_jpeg_signature(self, carver, temp_dir, sample_jpeg_data):
        """Test JPEG signature detection."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 1000 + sample_jpeg_data)

        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)

        assert len(manifest["carved_files"]) > 0
        assert any(f["file_type"] == "jpeg" for f in manifest["carved_files"])

    def test_docx_disambiguation(self, carver, temp_dir, sample_docx_data):
        """ZIP header containing word/ must be classified as docx, not zip."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 500 + sample_docx_data)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)
        assert any(f["file_type"] == "docx" for f in manifest["carved_files"])
        assert not any(f["file_type"] == "zip" for f in manifest["carved_files"])

    def test_xlsx_disambiguation(self, carver, temp_dir, sample_xlsx_data):
        """ZIP header containing xl/ must be classified as xlsx, not zip."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 500 + sample_xlsx_data)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)
        assert any(f["file_type"] == "xlsx" for f in manifest["carved_files"])

    def test_bmp_validation(self, carver, temp_dir, sample_bmp_data):
        """Valid BMP must pass secondary validation."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + sample_bmp_data)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=True)
        bmp = next((f for f in manifest.carved_files if f.file_type == "bmp"), None)
        assert bmp is not None
        assert bmp.validation_passed

    def test_bmp_rejects_pe_header(self, carver, temp_dir):
        """BMP validation must reject a PE executable with MZ prefix."""
        pe_stub = b"BM" + b"\x00\x04\x00\x00" + b"\x00" * 50 + b"PE\x00\x00"
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + pe_stub + b"\x00" * 1000)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=True)
        bmp = next((f for f in manifest.carved_files if f.file_type == "bmp"), None)
        if bmp:
            assert not bmp.validation_passed

    def test_bmp_rejects_inconsistent_size_field(self, carver, temp_dir):
        """BMP with an inconsistent size field must fail validation."""
        bad_bmp = b"BM" + struct.pack("<I", 4096) + b"\x00" * 50
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + bad_bmp)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=True)
        bmp = next((f for f in manifest.carved_files if f.file_type == "bmp"), None)
        if bmp:
            assert not bmp.validation_passed

    def test_gif_validation(self, carver, temp_dir, sample_gif_data):
        """Valid GIF89a must pass secondary validation."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + sample_gif_data)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=True)
        gif = next((f for f in manifest.carved_files if f.file_type == "gif"), None)
        assert gif is not None
        assert gif.validation_passed

    def test_tiff_validation(self, carver, temp_dir, sample_tiff_le_data):
        """Valid little-endian TIFF must pass secondary validation."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + sample_tiff_le_data)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=True)
        tiff = next((f for f in manifest.carved_files if f.file_type == "tiff"), None)
        assert tiff is not None
        assert tiff.validation_passed

    def test_gif_rejects_missing_trailer(self, carver, temp_dir):
        """GIF without trailer byte must fail validation."""
        bad_gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00" * 50
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + bad_gif)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=True)
        gif = next((f for f in manifest.carved_files if f.file_type == "gif"), None)
        if gif:
            assert not gif.validation_passed

    def test_pdf_carving_keeps_eof(self, carver, temp_dir):
        """PDF carving must include the terminal %%EOF marker."""
        pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<<>>\nendobj\n"
            b"xref\n0 1\n0000000000 65535 f \n"
            b"trailer\n<<>>\nstartxref\n9\n%%EOF\n"
        )
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 256 + pdf_bytes)

        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)

        pdf_file = next(f for f in manifest.carved_files if f.file_type == "pdf")
        carved_path = temp_dir / "carved" / f"{pdf_file.offset:016x}_pdf"
        assert carved_path.read_bytes().endswith(b"%%EOF\n")
        assert pdf_file.size == len(pdf_bytes)

    def test_manifest_object_access(self, carver, temp_dir, sample_jpeg_data):
        """Manifest must support both object and dict-style access."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(sample_jpeg_data)

        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)

        assert manifest.carved_files
        assert manifest["carved_files"]

    def test_eml_false_positive_rejected(self, carver, temp_dir):
        """'From ' in a non-email context must not produce an eml artifact."""
        non_email = b"From the desk of the CEO\nThis is a memo.\n"
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + non_email)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)
        assert not any(f["file_type"] == "eml" for f in manifest["carved_files"])

    def test_eml_valid_header(self, carver, temp_dir, sample_eml_data):
        """Valid EML with RFC 2822 headers must be recognized."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 200 + sample_eml_data)
        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)
        assert any(f["file_type"] == "eml" for f in manifest["carved_files"])

    def test_wave_disambiguation(self, carver, temp_dir, sample_wave_data):
        """Test RIFF disambiguation to WAVE."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 500 + sample_wave_data)

        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)

        wave_file = next((f for f in manifest["carved_files"] if f["file_type"] == "wav"), None)
        assert wave_file is not None

    def test_avi_disambiguation(self, carver, temp_dir, sample_avi_data):
        """Test RIFF disambiguation to AVI."""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"\x00" * 500 + sample_avi_data)

        manifest = carver.carve(test_file, temp_dir / "carved", verify=False)

        avi_file = next((f for f in manifest["carved_files"] if f["file_type"] == "avi"), None)
        assert avi_file is not None

    def test_custody_key_is_random(self, temp_dir):
        """Case secret key must not be predictable across two case creations."""
        from frece.custody import create_case_secret_key
        key1 = create_case_secret_key(temp_dir / "case1")
        key2 = create_case_secret_key(temp_dir / "case2")
        assert key1 != key2
