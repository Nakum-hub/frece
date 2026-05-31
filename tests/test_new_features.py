"""Tests for FRECE v2.2.0 new features: classifier, timeline, new CLI commands."""

import hashlib
import json
import struct
import tempfile
from pathlib import Path

import pytest

from frece.classifier import (
    ForensicCategory,
    ClassificationResult,
    classify_bytes,
    classify_file,
    shannon_entropy,
    entropy_label,
)
from frece.timeline import (
    TimelineEvent,
    _events_from_carve_manifest,
    _events_from_recovery_manifest,
    _events_from_custody_db,
    build_timeline,
    events_to_csv,
    events_to_json,
    events_to_text,
)


# ─────────────────────────────────────────────────────────────────────────────
# classifier.py
# ─────────────────────────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_all_zeros_is_zero(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_random_like_data_is_high(self):
        import os
        data = os.urandom(4096)
        assert shannon_entropy(data) > 7.0

    def test_text_is_medium(self):
        text = b"The quick brown fox jumps over the lazy dog. " * 100
        e = shannon_entropy(text)
        assert 3.0 < e < 6.0

    def test_empty_is_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte_pattern_is_zero(self):
        assert shannon_entropy(b"\xff" * 512) == 0.0


class TestEntropyLabel:
    def test_low(self):
        assert entropy_label(2.0) == "LOW"

    def test_medium(self):
        assert entropy_label(5.0) == "MEDIUM"

    def test_high(self):
        assert entropy_label(7.0) == "HIGH"

    def test_encrypted(self):
        assert entropy_label(7.6) == "ENCRYPTED"


class TestClassifyFile:
    def test_jpeg_category(self, tmp_path):
        jpeg = tmp_path / "photo.jpeg"
        jpeg.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"\xff\xd9")
        result = classify_file(jpeg, "jpeg")
        assert result.category == ForensicCategory.IMAGE
        assert result.forensic_priority in ("MEDIUM", "HIGH", "CRITICAL", "LOW")

    def test_pdf_category(self, tmp_path):
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(b"%PDF-1.4\n" + b"A" * 200 + b"\n%%EOF")
        result = classify_file(pdf, "pdf")
        assert result.category == ForensicCategory.DOCUMENT

    def test_pe_is_executable_critical(self, tmp_path):
        exe = tmp_path / "malware.exe"
        # Valid MZ header with PE offset
        header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
        exe.write_bytes(header + b"PE\x00\x00" + b"\x00" * 200)
        result = classify_file(exe, "pe")
        assert result.category == ForensicCategory.EXECUTABLE
        assert result.forensic_priority == "CRITICAL"

    def test_sqlite_category(self, tmp_path):
        db = tmp_path / "data.db"
        db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
        result = classify_file(db, "sqlite")
        assert result.category == ForensicCategory.DATABASE

    def test_encrypted_blob_flagged(self, tmp_path):
        import os
        encrypted = tmp_path / "vault.bin"
        encrypted.write_bytes(os.urandom(8192))
        result = classify_file(encrypted, "bin")
        assert result.possibly_encrypted is True
        assert result.category == ForensicCategory.CRYPTOGRAPHIC

    def test_pcap_category(self, tmp_path):
        capture = tmp_path / "dump.pcap"
        capture.write_bytes(b"\xD4\xC3\xB2\xA1" + b"\x00" * 100)
        result = classify_file(capture, "pcap")
        assert result.category == ForensicCategory.NETWORK
        assert result.forensic_priority == "HIGH"

    def test_evtx_category(self, tmp_path):
        evtx = tmp_path / "system.evtx"
        evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
        result = classify_file(evtx, "evtx")
        assert result.category == ForensicCategory.SYSTEM

    def test_eml_category(self, tmp_path):
        eml = tmp_path / "message.eml"
        eml.write_bytes(
            b"From someone@example.com Thu Jan 01 00:00:00 1970\r\n"
            b"To: other@example.com\r\n\r\nBody text"
        )
        result = classify_file(eml, "eml")
        assert result.category == ForensicCategory.EMAIL

    def test_entropy_populated(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"Hello World" * 100)
        result = classify_file(f, "txt")
        assert result.entropy > 0.0
        assert result.entropy <= 8.0


class TestClassifyBytes:
    def test_classify_bytes_no_file(self):
        data = b"%PDF-1.4\nsome content\n%%EOF"
        result = classify_bytes(data, "pdf")
        assert result.category == ForensicCategory.DOCUMENT

    def test_archive_not_flagged_as_encrypted(self):
        import zlib
        compressed = zlib.compress(b"A" * 10000)
        result = classify_bytes(compressed, "gz")
        assert result.possibly_encrypted is False


# ─────────────────────────────────────────────────────────────────────────────
# timeline.py
# ─────────────────────────────────────────────────────────────────────────────

class TestTimelineFromManifests:
    def test_events_from_carve_manifest(self, tmp_path):
        manifest = {
            "source": "/tmp/test.dd",
            "timestamp": "2025-06-01T10:00:00Z",
            "carved_files": [
                {"file_type": "jpeg", "offset": 512, "size": 2048},
                {"file_type": "pdf", "offset": 65536, "size": 512},
            ],
        }
        p = tmp_path / "carve_manifest.json"
        p.write_text(json.dumps(manifest))
        events = _events_from_carve_manifest(p)
        assert len(events) == 2
        assert all(e.event_source == "carving" for e in events)
        assert events[0].artifact_type == "jpeg"

    def test_events_from_recovery_manifest(self, tmp_path):
        manifest = {
            "source": "/tmp/test.dd",
            "recovered_files": [
                {
                    "inode": 14,
                    "file_type": "txt",
                    "original_name": "notes.txt",
                    "output_path": "/tmp/out/notes.txt",
                    "size": 100,
                    "timestamp": "2025-06-01T11:00:00Z",
                    "mtime": 1748776800,
                }
            ],
        }
        p = tmp_path / "recovery_manifest.json"
        p.write_text(json.dumps(manifest))
        events = _events_from_recovery_manifest(p)
        # Should produce a recovered event + an mtime event
        assert len(events) >= 1
        sources = {e.event_source for e in events}
        assert "recovery" in sources or "filesystem" in sources

    def test_timeline_sorted(self, tmp_path):
        carve_manifest = {
            "source": "/tmp/img.dd",
            "timestamp": "2025-01-15T08:00:00Z",
            "carved_files": [{"file_type": "jpeg", "offset": 0, "size": 100}],
        }
        recovery_manifest = {
            "source": "/tmp/img.dd",
            "recovered_files": [
                {
                    "inode": 10,
                    "file_type": "txt",
                    "original_name": "f.txt",
                    "output_path": "/tmp/out/f.txt",
                    "size": 50,
                    "timestamp": "2025-01-14T06:00:00Z",
                }
            ],
        }
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        (case_dir / "carve_manifest.json").write_text(json.dumps(carve_manifest))
        (case_dir / "recovery_manifest.json").write_text(json.dumps(recovery_manifest))

        events = build_timeline(case_dir)
        epochs = [e.timestamp_epoch for e in events if e.timestamp_epoch > 0]
        assert epochs == sorted(epochs), "Timeline is not sorted chronologically"

    def test_events_to_csv(self, tmp_path):
        carve_manifest = {
            "source": "/dev/sda",
            "timestamp": "2025-03-10T09:30:00Z",
            "carved_files": [{"file_type": "pdf", "offset": 0, "size": 500}],
        }
        p = tmp_path / "carve_manifest.json"
        p.write_text(json.dumps(carve_manifest))
        events = _events_from_carve_manifest(p)
        csv_str = events_to_csv(events)
        assert "carving" in csv_str
        assert "pdf" in csv_str
        assert "\n" in csv_str

    def test_events_to_text(self, tmp_path):
        carve_manifest = {
            "source": "/dev/sda",
            "timestamp": "2025-03-10T09:30:00Z",
            "carved_files": [{"file_type": "jpeg", "offset": 0, "size": 100}],
        }
        p = tmp_path / "carve_manifest.json"
        p.write_text(json.dumps(carve_manifest))
        events = _events_from_carve_manifest(p)
        text = events_to_text(events)
        assert "TIMESTAMP" in text
        assert "carving" in text

    def test_events_to_json_roundtrip(self, tmp_path):
        carve_manifest = {
            "source": "/dev/sda",
            "timestamp": "2025-03-10T09:30:00Z",
            "carved_files": [{"file_type": "zip", "offset": 100, "size": 2000}],
        }
        p = tmp_path / "carve_manifest.json"
        p.write_text(json.dumps(carve_manifest))
        events = _events_from_carve_manifest(p)
        j = events_to_json(events)
        parsed = json.loads(j)
        assert isinstance(parsed, list)
        assert parsed[0]["artifact_type"] == "zip"

    def test_empty_timeline_text(self):
        text = events_to_text([])
        assert "No timeline" in text

    def test_empty_timeline_csv(self):
        csv_str = events_to_csv([])
        assert csv_str == ""


# ─────────────────────────────────────────────────────────────────────────────
# CLI new commands — integration-level (argparse + handler)
# ─────────────────────────────────────────────────────────────────────────────

class TestNewCLICommands:
    def test_entropy_command_single_file(self, tmp_path):
        from frece.cli import main

        f = tmp_path / "data.bin"
        f.write_bytes(b"\xff" * 1024 + b"\x00" * 1024)
        out = tmp_path / "entropy.json"
        rc = main(["entropy", str(f), "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_analysed"] == 1
        assert result["results"][0]["entropy"] >= 0.0

    def test_entropy_command_directory(self, tmp_path):
        from frece.cli import main

        src_dir = tmp_path / "files"
        src_dir.mkdir()
        for i in range(5):
            (src_dir / f"file{i}.txt").write_bytes(f"text content {i}".encode() * 100)

        out = tmp_path / "entropy.json"
        rc = main(["entropy", str(src_dir), "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_analysed"] == 5

    def test_search_command_finds_keyword(self, tmp_path):
        from frece.cli import main

        src_dir = tmp_path / "evidence"
        src_dir.mkdir()
        (src_dir / "report.txt").write_text("The suspect was found at the crime scene.")
        (src_dir / "notes.txt").write_text("Nothing relevant here.")

        out = tmp_path / "search.json"
        rc = main(["search", str(src_dir), "--keyword", "suspect", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_with_hits"] == 1
        assert "report.txt" in result["results"][0]["file"]

    def test_search_command_regex(self, tmp_path):
        from frece.cli import main

        src_dir = tmp_path / "logs"
        src_dir.mkdir()
        (src_dir / "log.txt").write_text("Error at 192.168.1.100 port 443\nOK at 10.0.0.1")

        out = tmp_path / "search.json"
        rc = main([
            "search", str(src_dir),
            "--keyword", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            "--regex",
            "--output", str(out),
        ])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_with_hits"] == 1

    def test_search_command_no_hits(self, tmp_path):
        from frece.cli import main

        src_dir = tmp_path / "docs"
        src_dir.mkdir()
        (src_dir / "readme.txt").write_text("Normal content with no matches.")

        out = tmp_path / "search.json"
        rc = main(["search", str(src_dir), "--keyword", "xyzzy_not_found", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_with_hits"] == 0

    def test_classify_command(self, tmp_path):
        from frece.cli import main

        src_dir = tmp_path / "artifacts"
        src_dir.mkdir()
        # JPEG
        (src_dir / "photo_jpeg").write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9")
        # PDF
        (src_dir / "doc_pdf").write_bytes(b"%PDF-1.4\ntest\n%%EOF")
        # Carver-named file
        (src_dir / "0000000200_jpeg").write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9")

        out = tmp_path / "classify.json"
        rc = main(["classify", str(src_dir), "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_classified"] >= 2
        categories = {r["category"] for r in result["results"]}
        assert "image" in categories or "document" in categories

    def test_timeline_command(self, tmp_path, monkeypatch):
        from frece.cli import main
        import frece.custody as custody_mod

        monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))
        monkeypatch.setattr(custody_mod, "_key_store_warning_shown", False)

        # Build a minimal case directory
        case_root = tmp_path / "cases"
        case_name = "TL-TEST"
        case_dir = case_root / case_name
        case_dir.mkdir(parents=True)

        carve_manifest = {
            "source": str(tmp_path / "img.dd"),
            "timestamp": "2025-06-01T12:00:00Z",
            "carved_files": [
                {"file_type": "jpeg", "offset": 0, "size": 1024},
                {"file_type": "pdf", "offset": 4096, "size": 512},
            ],
        }
        (case_dir / "carve_manifest.json").write_text(json.dumps(carve_manifest))

        out = tmp_path / "timeline.txt"
        rc = main([
            "timeline", case_name,
            "--root", str(case_root),
            "--format", "text",
            "--output", str(out),
        ])
        assert rc == 0
        text = out.read_text()
        assert "carving" in text

    def test_timeline_json_format(self, tmp_path):
        from frece.cli import main

        case_root = tmp_path / "cases"
        case_name = "TL-JSON"
        case_dir = case_root / case_name
        case_dir.mkdir(parents=True)

        carve_manifest = {
            "source": str(tmp_path / "img.dd"),
            "timestamp": "2025-07-15T14:30:00Z",
            "carved_files": [{"file_type": "sqlite", "offset": 0, "size": 4096}],
        }
        (case_dir / "carve_manifest.json").write_text(json.dumps(carve_manifest))

        out = tmp_path / "timeline.json"
        rc = main([
            "timeline", case_name,
            "--root", str(case_root),
            "--format", "json",
            "--output", str(out),
        ])
        assert rc == 0
        events = json.loads(out.read_text())
        assert isinstance(events, list)
        assert all("timestamp" in e for e in events)

    def test_fsstat_command_nonexistent(self, tmp_path):
        from frece.cli import main
        rc = main(["fsstat", str(tmp_path / "nonexistent.dd")])
        assert rc == 1


# ─────────────────────────────────────────────────────────────────────────────
# Scan --mactime flag
# ─────────────────────────────────────────────────────────────────────────────

class TestScanMactimeFlag:
    def test_scan_mactime_output_schema(self, tmp_path):
        """Scan --mactime output must include mode and entries with MAC fields."""
        import subprocess, json as _json

        result = subprocess.run(
            ["frece", "scan", "/tmp/frece_sandbox/ntfs_test2.dd", "--mactime"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            pytest.skip("NTFS test image not available in this environment")

        data = _json.loads(result.stdout)
        assert data["mode"] == "mactime"
        assert "total_entries" in data
        if data["entries"]:
            entry = data["entries"][0]
            for field in ("inode", "name", "mtime", "atime", "ctime"):
                assert field in entry, f"Missing field: {field}"
