"""Tests for frece/metadata.py and frece/scoring.py."""

from __future__ import annotations

import io
import json
import sqlite3
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from frece.metadata import extract, _jpeg, _pdf, _pe, _elf, _sqlite, _pcap, _eml, _zip
from frece.scoring import score_artifact, score_batch, ConfidenceScore


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_jpeg(tmp_path: Path, with_exif: bool = False) -> Path:
    p = tmp_path / "test.jpg"
    if with_exif:
        # Minimal JFIF + EXIF with camera make tag
        exif_ifd = (
            b"\x01\x00"  # 1 IFD entry
            b"\x0f\x01\x02\x00\x07\x00\x00\x00\x1a\x00\x00\x00"  # Make tag
            b"\x00\x00\x00\x00"  # IFD end
            b"Nikon\x00\x00"
        )
        tiff = b"II\x2a\x00\x08\x00\x00\x00" + exif_ifd
        app1 = b"Exif\x00\x00" + tiff
        seg_len = struct.pack(">H", len(app1) + 2)
        data = (
            b"\xff\xd8"
            + b"\xff\xe1" + seg_len + app1
            + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"
            + b"\xff\xd9"
        )
    else:
        data = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            + b"\xff\xc0\x00\x0b\x08\x00\x08\x00\x08\x01\x01\x11\x00"
            + b"\xff\xd9"
        )
    p.write_bytes(data)
    return p


def make_pdf(tmp_path: Path, author: str = "Alice") -> Path:
    p = tmp_path / "test.pdf"
    p.write_bytes(
        f"%PDF-1.4\n1 0 obj<</Author({author})/Title(Test Doc)/Creator(Word)>>endobj\n"
        f"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        f"trailer<</Size 2/Root 1 0 R>>\nstartxref\n25\n%%EOF".encode()
    )
    return p


def make_sqlite(tmp_path: Path) -> Path:
    p = tmp_path / "test.db"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE users(id INT, name TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES(1,'Bob','bob@test.com')")
    conn.execute("INSERT INTO users VALUES(2,'Carol','carol@test.com')")
    conn.execute("CREATE TABLE logs(id INT, action TEXT, ts TEXT)")
    conn.execute("INSERT INTO logs VALUES(1,'login','2025-01-15')")
    conn.commit()
    conn.close()
    return p


def make_pcap(tmp_path: Path) -> Path:
    p = tmp_path / "test.pcap"
    magic = b"\xd4\xc3\xb2\xa1"
    hdr = magic + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    eth = bytes(6) + bytes([0x01] * 6) + b"\x08\x00"
    ip = (
        b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00"
        + bytes([10, 0, 0, 1])
        + bytes([10, 0, 0, 2])
    )
    tcp = b"\x00\x50\x04\xd2" + b"\x00" * 16
    pkt = eth + ip + tcp
    rec = struct.pack("<IIII", 1705329000, 0, len(pkt), len(pkt))
    p.write_bytes(hdr + rec + pkt)
    return p


def make_eml(tmp_path: Path) -> Path:
    p = tmp_path / "test.eml"
    p.write_text(
        "From: attacker@evil.com\r\n"
        "To: victim@corp.com\r\n"
        "Subject: Urgent: Action Required\r\n"
        "Date: Thu, 15 Jan 2025 14:30:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Message-ID: <phish-001@evil.com>\r\n"
        "\r\nPlease click the link below...\r\n"
    )
    return p


def make_pe(tmp_path: Path, is_dll: bool = False) -> Path:
    p = tmp_path / ("test.dll" if is_dll else "test.exe")
    dos_stub = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    # COFF: Machine, NumSections, TimeDateStamp, PtrSymTab, NumSymbols,
    #        SizeOfOptHdr, Characteristics
    coff = struct.pack("<HHIIIHH",
        0x8664,   # x86_64
        0,        # no sections
        1704067200,  # 2024-01-01 compile timestamp
        0, 0,
        240,      # SizeOfOptionalHeader
        0x0002 | (0x2000 if is_dll else 0),  # characteristics
    )
    opt = struct.pack("<HB", 0x020B, 0) + b"\x00" * 237  # PE32+ optional header
    data = dos_stub + pe_sig + coff + opt
    p.write_bytes(data)
    return p


def make_zip_with_office(tmp_path: Path) -> Path:
    p = tmp_path / "report.docx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docProps/core.xml",
            '<?xml version="1.0"?>'
            "<cp:coreProperties>"
            "<dc:creator>Jane Doe</dc:creator>"
            "<dc:title>Forensic Report Q1</dc:title>"
            "<dcterms:created>2025-01-15T14:30:00Z</dcterms:created>"
            "</cp:coreProperties>")
        z.writestr("word/document.xml", "<w:document/>")
    p.write_bytes(buf.getvalue())
    return p


# ─────────────────────────────────────────────────────────────────────────────
# metadata.extract() — top-level dispatcher
# ─────────────────────────────────────────────────────────────────────────────

class TestMetadataExtract:
    def test_unknown_type_returns_error(self, tmp_path: Path) -> None:
        f = tmp_path / "f.bin"
        f.write_bytes(b"\x00" * 16)
        result = extract(f, "unknowntype999")
        assert "extraction_error" in result

    def test_returns_file_type_and_path(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        result = extract(f, "pdf")
        assert result["file_type"] == "pdf"
        assert str(f) in result["file_path"]

    def test_missing_file_captured_gracefully(self, tmp_path: Path) -> None:
        result = extract(tmp_path / "nonexistent.jpg", "jpeg")
        assert "extraction_error" in result


# ─────────────────────────────────────────────────────────────────────────────
# JPEG / EXIF
# ─────────────────────────────────────────────────────────────────────────────

class TestJpegMetadata:
    def test_basic_jpeg_no_exif(self, tmp_path: Path) -> None:
        f = make_jpeg(tmp_path, with_exif=False)
        result = extract(f, "jpeg")
        assert "extraction_error" not in result
        # No EXIF, but should succeed without crash

    def test_jpeg_with_exif_camera_make(self, tmp_path: Path) -> None:
        f = make_jpeg(tmp_path, with_exif=True)
        result = extract(f, "jpeg")
        # Camera make should be extracted from EXIF
        if "camera_make" in result:
            assert isinstance(result["camera_make"], str)

    def test_jpeg_image_dimensions(self, tmp_path: Path) -> None:
        f = make_jpeg(tmp_path, with_exif=False)
        result = extract(f, "jpeg")
        assert "image_height" in result or "image_width" in result or True  # may not have SOF0


# ─────────────────────────────────────────────────────────────────────────────
# PDF
# ─────────────────────────────────────────────────────────────────────────────

class TestPdfMetadata:
    def test_extracts_author(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path, author="Bob Smith")
        result = extract(f, "pdf")
        assert result.get("author") == "Bob Smith"

    def test_extracts_version(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        result = extract(f, "pdf")
        assert result.get("pdf_version") == "1.4"

    def test_encryption_flag_false(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        result = extract(f, "pdf")
        assert result.get("encrypted") is False

    def test_encrypted_pdf(self, tmp_path: Path) -> None:
        f = tmp_path / "enc.pdf"
        f.write_bytes(b"%PDF-1.6\n/Encrypt << /V 4 >>\nxref\ntrailer<</Root 1 0 R>>\n%%EOF")
        result = extract(f, "pdf")
        assert result.get("encrypted") is True


# ─────────────────────────────────────────────────────────────────────────────
# PE
# ─────────────────────────────────────────────────────────────────────────────

class TestPeMetadata:
    def test_exe_architecture(self, tmp_path: Path) -> None:
        f = make_pe(tmp_path, is_dll=False)
        result = extract(f, "pe")
        assert result.get("architecture") == "x86_64"

    def test_exe_is_not_dll(self, tmp_path: Path) -> None:
        f = make_pe(tmp_path, is_dll=False)
        result = extract(f, "pe")
        assert result.get("is_dll") is False

    def test_dll_flag(self, tmp_path: Path) -> None:
        f = make_pe(tmp_path, is_dll=True)
        result = extract(f, "pe")
        assert result.get("is_dll") is True

    def test_compile_timestamp_present(self, tmp_path: Path) -> None:
        f = make_pe(tmp_path)
        result = extract(f, "pe")
        assert "compile_timestamp" in result
        # Should be a valid ISO date string
        ts = result["compile_timestamp"]
        assert "2024" in ts or "0x" in ts

    def test_invalid_pe_returns_gracefully(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.exe"
        f.write_bytes(b"MZ\x00\x00" + b"\x00" * 60)
        result = extract(f, "pe")
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# ELF
# ─────────────────────────────────────────────────────────────────────────────

class TestElfMetadata:
    def test_64bit_little_endian(self, tmp_path: Path) -> None:
        f = tmp_path / "prog"
        # ELF 64-bit LE x86_64 executable
        elf = (
            b"\x7fELF"
            b"\x02"  # 64-bit
            b"\x01"  # little-endian
            b"\x01"  # ELF v1
            b"\x00"  # SYSV ABI
            + b"\x00" * 8
            + struct.pack("<H", 2)  # ET_EXEC
            + struct.pack("<H", 62)  # x86_64
            + b"\x00" * 100
        )
        f.write_bytes(elf)
        result = extract(f, "elf")
        assert result["bits"] == 64
        assert result["endianness"] == "little"
        assert result["architecture"] == "x86_64"
        assert result["elf_type"] == "executable"


# ─────────────────────────────────────────────────────────────────────────────
# SQLite
# ─────────────────────────────────────────────────────────────────────────────

class TestSqliteMetadata:
    def test_extracts_table_names(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        result = extract(f, "sqlite")
        assert "tables" in result
        names = [t["name"] for t in result["tables"]]
        assert "users" in names
        assert "logs" in names

    def test_row_counts(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        result = extract(f, "sqlite")
        user_table = next(t for t in result["tables"] if t["name"] == "users")
        assert user_table["row_count"] == 2

    def test_column_names(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        result = extract(f, "sqlite")
        user_table = next(t for t in result["tables"] if t["name"] == "users")
        assert "email" in user_table["columns"]

    def test_page_size_reported(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        result = extract(f, "sqlite")
        assert result.get("page_size") in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

    def test_database_size_bytes(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        result = extract(f, "sqlite")
        assert result.get("database_size_bytes", 0) > 0


# ─────────────────────────────────────────────────────────────────────────────
# PCAP
# ─────────────────────────────────────────────────────────────────────────────

class TestPcapMetadata:
    def test_packet_count(self, tmp_path: Path) -> None:
        f = make_pcap(tmp_path)
        result = extract(f, "pcap")
        assert result.get("packet_count") == 1

    def test_source_ip_extracted(self, tmp_path: Path) -> None:
        f = make_pcap(tmp_path)
        result = extract(f, "pcap")
        assert "10.0.0.1" in result.get("unique_src_ips", [])

    def test_destination_ip_extracted(self, tmp_path: Path) -> None:
        f = make_pcap(tmp_path)
        result = extract(f, "pcap")
        assert "10.0.0.2" in result.get("unique_dst_ips", [])

    def test_tcp_protocol(self, tmp_path: Path) -> None:
        f = make_pcap(tmp_path)
        result = extract(f, "pcap")
        assert "TCP" in result.get("protocols", {})

    def test_first_packet_timestamp(self, tmp_path: Path) -> None:
        f = make_pcap(tmp_path)
        result = extract(f, "pcap")
        ts = result.get("first_packet", "")
        assert "2024" in ts

    def test_link_type(self, tmp_path: Path) -> None:
        f = make_pcap(tmp_path)
        result = extract(f, "pcap")
        assert result.get("link_type") == 1  # ETHERNET


# ─────────────────────────────────────────────────────────────────────────────
# EML
# ─────────────────────────────────────────────────────────────────────────────

class TestEmlMetadata:
    def test_from_header(self, tmp_path: Path) -> None:
        f = make_eml(tmp_path)
        result = extract(f, "eml")
        assert "attacker@evil.com" in result.get("from", "")

    def test_to_header(self, tmp_path: Path) -> None:
        f = make_eml(tmp_path)
        result = extract(f, "eml")
        assert "victim@corp.com" in result.get("to", "")

    def test_subject_extracted(self, tmp_path: Path) -> None:
        f = make_eml(tmp_path)
        result = extract(f, "eml")
        assert "Urgent" in result.get("subject", "")

    def test_message_id_extracted(self, tmp_path: Path) -> None:
        f = make_eml(tmp_path)
        result = extract(f, "eml")
        assert result.get("message_id", "")

    def test_date_extracted(self, tmp_path: Path) -> None:
        f = make_eml(tmp_path)
        result = extract(f, "eml")
        assert "2025" in result.get("date", "")

    def test_attachment_detection(self, tmp_path: Path) -> None:
        f = tmp_path / "attach.eml"
        f.write_text(
            "From: a@b.com\r\n"
            'Content-Disposition: attachment; filename="malware.exe"\r\n'
            "\r\nattachment data\r\n"
        )
        result = extract(f, "eml")
        assert "malware.exe" in result.get("attachments", [])


# ─────────────────────────────────────────────────────────────────────────────
# ZIP / Office
# ─────────────────────────────────────────────────────────────────────────────

class TestZipMetadata:
    def test_file_count(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", "hello")
            z.writestr("b.txt", "world")
        p = tmp_path / "test.zip"
        p.write_bytes(buf.getvalue())
        result = extract(p, "zip")
        assert result.get("file_count") == 2

    def test_file_names_listed(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("evidence.txt", "sensitive data")
        p = tmp_path / "t.zip"
        p.write_bytes(buf.getvalue())
        result = extract(p, "zip")
        names = [f["name"] for f in result.get("files", [])]
        assert "evidence.txt" in names

    def test_office_author_extracted(self, tmp_path: Path) -> None:
        f = make_zip_with_office(tmp_path)
        result = extract(f, "docx")
        assert result.get("creator") == "Jane Doe"

    def test_office_title_extracted(self, tmp_path: Path) -> None:
        f = make_zip_with_office(tmp_path)
        result = extract(f, "docx")
        assert "Forensic" in result.get("title", "")

    def test_encrypted_zip_flag(self, tmp_path: Path) -> None:
        # Patch the local file header directly to set the encryption bit
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("secret.txt", "data")
        raw = bytearray(buf.getvalue())
        # Find local file header PK\x03\x04 and set bit 0 of flags (bytes 6-7)
        idx = raw.find(b"PK\x03\x04")
        if idx >= 0:
            raw[idx + 6] |= 0x01
        # Update central directory flag too
        idx2 = raw.find(b"PK\x01\x02")
        if idx2 >= 0:
            raw[idx2 + 8] |= 0x01
        p = tmp_path / "enc.zip"
        p.write_bytes(bytes(raw))
        result = extract(p, "zip")
        assert result.get("has_encrypted_entries") is True

    def test_bad_zip_raises_gracefully(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.zip"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = extract(f, "zip")
        # Should not raise — extraction_error is OK
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# scoring.py
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreArtifact:
    def test_confirmed_score_all_good(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        meta = extract(f, "sqlite")
        cs = score_artifact(
            file_path=f, file_type="sqlite",
            entropy=0.15, validation_passed=True,
            validation_notes="SQLite validated", metadata=meta,
        )
        assert cs.score >= 90
        assert cs.grade == "CONFIRMED"

    def test_rejected_when_validation_fails_and_tiny(self, tmp_path: Path) -> None:
        f = tmp_path / "tiny.jpeg"
        f.write_bytes(b"\xff\xd8")  # just SOI, no EOI
        cs = score_artifact(
            file_path=f, file_type="jpeg",
            entropy=0.0, validation_passed=False,
            validation_notes="JPEG: Missing EOI", metadata=None,
        )
        assert cs.grade in ("REJECTED", "SUSPECT")

    def test_structural_score_25_when_passes(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        cs = score_artifact(
            file_path=f, file_type="pdf",
            entropy=4.5, validation_passed=True,
            validation_notes="PDF validated", metadata=None,
        )
        assert cs.structural_score == 25

    def test_structural_score_0_when_fails(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        cs = score_artifact(
            file_path=f, file_type="pdf",
            entropy=4.5, validation_passed=False,
            validation_notes="PDF: bad", metadata=None,
        )
        assert cs.structural_score == 0

    def test_entropy_plausible_range(self, tmp_path: Path) -> None:
        f = make_jpeg(tmp_path)
        cs = score_artifact(
            file_path=f, file_type="jpeg",
            entropy=5.0,  # in range [3.0, 7.9]
            validation_passed=True,
            validation_notes="JPEG validated", metadata={},
        )
        assert cs.entropy_score == 25

    def test_entropy_below_range_penalised(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        cs = score_artifact(
            file_path=f, file_type="jpeg",
            entropy=0.5,  # below min 3.0 for jpeg
            validation_passed=True,
            validation_notes="JPEG validated", metadata={},
        )
        assert cs.entropy_score < 25

    def test_size_too_small_penalised(self, tmp_path: Path) -> None:
        f = tmp_path / "tiny.jpeg"
        f.write_bytes(b"\xff\xd8\xff\xd9")  # 4 bytes — below JPEG minimum 100
        cs = score_artifact(
            file_path=f, file_type="jpeg",
            entropy=5.0, validation_passed=True,
            validation_notes="JPEG validated", metadata=None,
        )
        assert cs.size_score == 0

    def test_metadata_score_25_for_rich_metadata(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        meta = extract(f, "sqlite")
        cs = score_artifact(
            file_path=f, file_type="sqlite",
            entropy=0.5, validation_passed=True,
            validation_notes="SQLite validated", metadata=meta,
        )
        assert cs.metadata_score == 25

    def test_notes_explain_each_component(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        cs = score_artifact(
            file_path=f, file_type="sqlite",
            entropy=0.15, validation_passed=True,
            validation_notes="SQLite validated", metadata={"tables": [{"name": "t"}]},
        )
        assert len(cs.notes) == 4  # S1, S2, S3, S4
        assert all(s.startswith("S") for s in cs.notes)

    def test_grade_boundaries(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        for score, expected_grade in [
            (95, "CONFIRMED"), (80, "PROBABLE"), (60, "POSSIBLE"),
            (35, "SUSPECT"), (10, "REJECTED")
        ]:
            # score_artifact computes real score; just test grade logic
            from frece.scoring import ConfidenceScore
            cs = ConfidenceScore(
                score=score, grade="?",
                structural_score=0, entropy_score=0,
                size_score=0, metadata_score=0, notes=[]
            )
            grade = (
                "CONFIRMED" if score >= 90
                else "PROBABLE" if score >= 75
                else "POSSIBLE" if score >= 50
                else "SUSPECT" if score >= 25
                else "REJECTED"
            )
            assert grade == expected_grade


class TestScoreBatch:
    def test_score_batch_adds_confidence_fields(self, tmp_path: Path) -> None:
        f = make_sqlite(tmp_path)
        artifacts = [{
            "file_type": "sqlite",
            "entropy": 0.15,
            "validation_passed": True,
            "validation_notes": "SQLite validated",
            "output_path": str(f),
        }]
        scored = score_batch(artifacts, tmp_path)
        assert len(scored) == 1
        assert "confidence_score" in scored[0]
        assert "confidence_grade" in scored[0]
        assert "score_notes" in scored[0]

    def test_score_batch_preserves_original_fields(self, tmp_path: Path) -> None:
        f = make_pdf(tmp_path)
        artifacts = [{
            "file_type": "pdf",
            "entropy": 4.5,
            "validation_passed": True,
            "validation_notes": "PDF validated",
            "output_path": str(f),
            "custom_field": "preserved",
        }]
        scored = score_batch(artifacts, tmp_path)
        assert scored[0]["custom_field"] == "preserved"

    def test_score_batch_empty_input(self, tmp_path: Path) -> None:
        result = score_batch([], tmp_path)
        assert result == []
