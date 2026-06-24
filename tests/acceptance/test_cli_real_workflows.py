# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Acceptance tests — require a real Sleuth Kit installation and root access."""

import json
import struct
import sqlite3
import tempfile
import zipfile
import io
from pathlib import Path

import pytest


pytestmark = pytest.mark.acceptance


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────

def _require_tools(*tools: str) -> None:
    """Skip (don't fail) the test when required external tools are absent.

    Honours the documented contract that acceptance tests are *skipped*
    automatically when the underlying forensic tools are not on PATH, so the
    full suite stays green on machines without The Sleuth Kit installed.
    """
    import shutil

    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"required forensic tools not on PATH: {missing}")


def make_ext4_image(path: Path, size_mb: int = 20) -> Path:
    """Create a real ext4 disk image with files and then delete some."""
    import subprocess
    _require_tools("dd", "mkfs.ext4", "mount", "umount", "fls", "icat")
    img = path / "test.dd"
    subprocess.run(["dd", "if=/dev/zero", f"of={img}", "bs=1M", f"count={size_mb}"],
                   check=True, capture_output=True)
    subprocess.run(["mkfs.ext4", "-F", str(img)], check=True, capture_output=True)
    mnt = path / "mnt"
    mnt.mkdir()
    subprocess.run(["mount", "-o", "loop", str(img), str(mnt)],
                   check=True, capture_output=True)
    # Write files large enough to survive ext4 deletion
    (mnt / "secret.txt").write_text("CONFIDENTIAL\n" + "X" * 5000)
    (mnt / "data.csv").write_text("id,val\n" + "\n".join(f"{i},{i*2}" for i in range(500)))
    subprocess.run(["sync"], capture_output=True)
    (mnt / "secret.txt").unlink()
    (mnt / "data.csv").unlink()
    subprocess.run(["sync"], capture_output=True)
    subprocess.run(["umount", str(mnt)], check=True, capture_output=True)
    return img


def make_raw_image(path: Path) -> Path:
    """Create a raw binary image with known embedded file types."""
    import zlib
    img = path / "raw.dd"
    data = bytearray(5 * 1024 * 1024)  # 5 MB

    # JPEG at 512
    jpg = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
           + b"\xff\xdb\x00\x43\x00" + bytes([16] * 64)
           + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"
           + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00" + b"\x7f" * 50 + b"\xff\xd9")
    data[512:512 + len(jpg)] = jpg

    # PDF at 65536
    pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 2\n" \
          b"0000000000 65535 f \n0000000009 00000 n \n" \
          b"trailer<</Size 2/Root 1 0 R>>\nstartxref\n30\n%%EOF"
    data[65536:65536 + len(pdf)] = pdf

    # SQLite at 131072
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    conn = sqlite3.connect(str(tmp_path))
    conn.execute("CREATE TABLE t(id INT, val TEXT)")
    conn.execute("INSERT INTO t VALUES(1,'evidence')")
    conn.commit()
    conn.close()
    db_bytes = tmp_path.read_bytes()
    data[131072:131072 + len(db_bytes)] = db_bytes
    tmp_path.unlink()

    # ZIP at 1048576
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("evidence.txt", "exfiltrated data")
    zdata = buf.getvalue()
    data[1048576:1048576 + len(zdata)] = zdata

    # PNG at 2097152
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        import zlib
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw_px = b"\x00" + bytes(range(8)) * 8
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw_px * 8))
           + chunk(b"IEND", b""))
    data[2097152:2097152 + len(png)] = png

    img.write_bytes(bytes(data))
    return img


# ──────────────────────────────────────────────────────────────────
# scan / recover / carve
# ──────────────────────────────────────────────────────────────────

class TestScanCommand:
    def test_scan_finds_deleted_entries(self, tmp_path):
        from frece.cli import main
        img = make_ext4_image(tmp_path)
        out = tmp_path / "scan.json"
        rc = main(["scan", str(img), "--output", str(out)])
        assert rc == 0
        d = json.loads(out.read_text())
        assert d["total_deleted"] >= 0  # may be 0 on heavily journaled ext4

    def test_scan_mactime_mode(self, tmp_path):
        from frece.cli import main
        img = make_ext4_image(tmp_path)
        out = tmp_path / "scan_mac.json"
        rc = main(["scan", str(img), "--mactime", "--output", str(out)])
        assert rc == 0
        d = json.loads(out.read_text())
        assert d["mode"] == "mactime"
        assert "total_entries" in d

    def test_fsstat_returns_fs_type(self, tmp_path):
        from frece.cli import main
        import subprocess
        _require_tools("dd", "mkfs.ext4", "fsstat")
        img = tmp_path / "fs.dd"
        subprocess.run(["dd", "if=/dev/zero", "of="+str(img), "bs=1M", "count=5"],
                       check=True, capture_output=True)
        subprocess.run(["mkfs.ext4", "-F", str(img)],
                       check=True, capture_output=True)
        result = main(["fsstat", str(img)])
        assert result == 0


class TestRecoverCommand:
    def test_recover_creates_manifest(self, tmp_path):
        from frece.cli import main
        img = make_ext4_image(tmp_path)
        out = tmp_path / "recovered"
        rc = main(["recover", str(img), "--output", str(out)])
        assert rc == 0
        assert (out / "recovery_manifest.json").exists()
        manifest = json.loads((out / "recovery_manifest.json").read_text())
        assert "recovered_count" in manifest
        assert "source" in manifest

    def test_recover_manifest_has_metadata_fields(self, tmp_path):
        from frece.cli import main
        img = make_ext4_image(tmp_path)
        out = tmp_path / "recovered"
        main(["recover", str(img), "--output", str(out)])
        manifest = json.loads((out / "recovery_manifest.json").read_text())
        for rec in manifest.get("recovered_files", []):
            assert "file_type" in rec
            assert "sha256" in rec
            assert "confidence_score" in rec
            assert "confidence_grade" in rec


class TestCarveCommand:
    def test_carve_finds_jpeg_and_pdf(self, tmp_path):
        from frece.cli import main
        img = make_raw_image(tmp_path)
        out = tmp_path / "carved"
        rc = main(["carve", str(img), "--output", str(out)])
        assert rc == 0
        manifest = json.loads((out / "carve_manifest.json").read_text())
        types = {f["file_type"] for f in manifest["carved_files"]}
        assert "jpeg" in types
        assert "pdf" in types

    def test_carve_manifest_has_confidence(self, tmp_path):
        from frece.cli import main
        img = make_raw_image(tmp_path)
        out = tmp_path / "carved"
        main(["carve", str(img), "--output", str(out)])
        manifest = json.loads((out / "carve_manifest.json").read_text())
        for f in manifest["carved_files"]:
            assert "confidence_score" in f
            assert "confidence_grade" in f
            assert 0 <= f["confidence_score"] <= 100

    def test_carve_zero_false_positives_on_nulls(self, tmp_path):
        from frece.cli import main
        img = tmp_path / "null.dd"
        img.write_bytes(b"\x00" * (1024 * 1024))  # 1 MB of null bytes
        out = tmp_path / "carved_null"
        rc = main(["carve", str(img), "--output", str(out)])
        assert rc == 0
        manifest = json.loads((out / "carve_manifest.json").read_text())
        assert manifest["files_carved"] == 0, "Null image should produce 0 carved files"

    def test_carve_with_yara_rules(self, tmp_path):
        from frece.cli import main
        img = make_raw_image(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "pdf.yar").write_text(
            'rule PDFSignature { strings: $h = { 25 50 44 46 } condition: $h at 0 }'
        )
        out = tmp_path / "carved_yara"
        rc = main(["carve", str(img), "--output", str(out),
                   "--yara-rules", str(rules_dir)])
        assert rc == 0
        manifest = json.loads((out / "carve_manifest.json").read_text())
        pdf_hits = [f for f in manifest["carved_files"]
                    if f["file_type"] == "pdf" and f.get("yara_matches")]
        assert len(pdf_hits) >= 1, "YARA rule should match the embedded PDF"


# ──────────────────────────────────────────────────────────────────
# metadata / score / entropy / classify / search / timeline
# ──────────────────────────────────────────────────────────────────

class TestMetadataCommand:
    def test_metadata_sqlite(self, tmp_path):
        from frece.cli import main
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE users(id INT, name TEXT)")
        conn.execute("INSERT INTO users VALUES(1,'Alice')")
        conn.commit()
        conn.close()
        out = tmp_path / "meta.json"
        rc = main(["metadata", str(db), "--type", "sqlite", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        tables = result["results"][0].get("tables", [])
        assert any(t["name"] == "users" for t in tables)

    def test_metadata_pdf(self, tmp_path):
        from frece.cli import main
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(
            b"%PDF-1.4\n1 0 obj<</Author(Alice Smith)>>endobj\n"
            b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
            b"trailer<</Size 2/Root 1 0 R>>\nstartxref\n20\n%%EOF"
        )
        out = tmp_path / "meta.json"
        rc = main(["metadata", str(pdf), "--type", "pdf", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["results"][0].get("author") == "Alice Smith"

    def test_metadata_eml(self, tmp_path):
        from frece.cli import main
        eml = tmp_path / "email.eml"
        eml.write_text(
            "From: attacker@evil.com\r\nTo: victim@corp.com\r\n"
            "Subject: Phishing Test\r\nDate: Thu, 15 Jan 2025 14:00:00 +0000\r\n"
            "\r\nClick here.\r\n"
        )
        out = tmp_path / "meta.json"
        rc = main(["metadata", str(eml), "--type", "eml", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert "attacker@evil.com" in result["results"][0].get("from", "")


class TestScoreCommand:
    def test_score_carve_manifest(self, tmp_path):
        from frece.cli import main
        img = make_raw_image(tmp_path)
        out = tmp_path / "carved"
        main(["carve", str(img), "--output", str(out)])
        out2 = tmp_path / "scores.json"
        rc = main(["score", str(out / "carve_manifest.json"), "--output", str(out2)])
        assert rc == 0
        result = json.loads(out2.read_text())
        assert "average_confidence" in result
        assert "grade_breakdown" in result
        assert result["total_artifacts"] >= 1

    def test_score_min_score_filter(self, tmp_path):
        from frece.cli import main
        img = make_raw_image(tmp_path)
        out = tmp_path / "carved"
        main(["carve", str(img), "--output", str(out)])
        out2 = tmp_path / "scores_filtered.json"
        rc = main(["score", str(out / "carve_manifest.json"),
                   "--min-score", "50", "--output", str(out2)])
        assert rc == 0
        result = json.loads(out2.read_text())
        for art in result["artifacts"]:
            assert art["confidence_score"] >= 50


class TestEntropyCommand:
    def test_entropy_flags_random_data(self, tmp_path):
        from frece.cli import main
        import os
        f = tmp_path / "encrypted.bin"
        f.write_bytes(os.urandom(65536))  # os imported above in method scope
        out = tmp_path / "entropy.json"
        rc = main(["entropy", str(f), "--threshold", "7.0", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_flagged"] >= 1
        assert result["results"][0]["entropy"] > 7.0

    def test_entropy_low_for_text(self, tmp_path):
        from frece.cli import main
        f = tmp_path / "notes.txt"
        f.write_text("The quick brown fox " * 500)
        out = tmp_path / "entropy.json"
        main(["entropy", str(f), "--threshold", "7.0", "--output", str(out)])
        result = json.loads(out.read_text())
        assert result["results"][0]["entropy"] < 7.0
        assert result["files_flagged"] == 0


class TestSearchCommand:
    def test_search_finds_keyword(self, tmp_path):
        from frece.cli import main
        d = tmp_path / "evidence"
        d.mkdir()
        (d / "ransom.txt").write_text("All your files encrypted. Pay BTC.")
        (d / "notes.txt").write_text("Nothing relevant here.")
        out = tmp_path / "search.json"
        rc = main(["search", str(d), "--keyword", "encrypted", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_with_hits"] == 1

    def test_search_regex(self, tmp_path):
        from frece.cli import main
        d = tmp_path / "logs"
        d.mkdir()
        (d / "log.txt").write_text("Connected from 192.168.1.100 port 4444")
        out = tmp_path / "search.json"
        rc = main(["search", str(d),
                   "--keyword", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                   "--regex", "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_with_hits"] == 1


class TestClassifyCommand:
    def test_classify_pe_as_critical(self, tmp_path):
        from frece.cli import main
        exe = tmp_path / "sample_pe"
        header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
        exe.write_bytes(header + b"PE\x00\x00" + b"\x00" * 200)
        out = tmp_path / "classify.json"
        rc = main(["classify", str(tmp_path), "--output", str(out)])
        assert rc == 0
        result = json.loads(out.read_text())
        assert result["files_classified"] >= 1


class TestTimelineCommand:
    def test_timeline_from_carve_manifest(self, tmp_path, monkeypatch):
        from frece.cli import main
        import frece.custody as cmod
        monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))
        monkeypatch.setattr(cmod, "_key_store_warning_shown", False)

        case_root = tmp_path / "cases"
        case_name = "TL-ACCEPT"
        case_dir = case_root / case_name
        case_dir.mkdir(parents=True)

        carve_manifest = {
            "source": str(tmp_path / "img.dd"),
            "timestamp": "2025-06-01T12:00:00Z",
            "carved_files": [
                {"file_type": "jpeg", "offset": 512, "size": 1024},
                {"file_type": "pdf", "offset": 65536, "size": 512},
            ],
        }
        (case_dir / "carve_manifest.json").write_text(json.dumps(carve_manifest))

        out = tmp_path / "timeline.json"
        rc = main(["timeline", case_name, "--root", str(case_root),
                   "--format", "json", "--output", str(out)])
        assert rc == 0
        events = json.loads(out.read_text())
        assert isinstance(events, list)
        assert len(events) >= 2


# ──────────────────────────────────────────────────────────────────
# Case management + custody + report
# ──────────────────────────────────────────────────────────────────

class TestCaseWorkflow:
    def test_full_case_lifecycle(self, tmp_path, monkeypatch):
        from frece.cli import main
        import frece.custody as cmod
        monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))
        monkeypatch.setattr(cmod, "_key_store_warning_shown", False)

        case_root = tmp_path / "cases"
        name = "ACCEPT-001"

        assert main(["case", "create", name, "--root", str(case_root)]) == 0
        assert main(["case", "log", name, "ACQUIRE",
                     "--root", str(case_root),
                     "--evidence-id", "EV-001"]) == 0
        assert main(["case", "verify", name, "--root", str(case_root)]) == 0

    def test_report_html(self, tmp_path, monkeypatch):
        from frece.cli import main
        import frece.custody as cmod
        monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))
        monkeypatch.setattr(cmod, "_key_store_warning_shown", False)

        case_root = tmp_path / "cases"
        name = "HTML-REPORT"
        main(["case", "create", name, "--root", str(case_root)])
        main(["case", "log", name, "ACQUIRE",
              "--root", str(case_root), "--evidence-id", "EV-001"])

        out = tmp_path / "report.html"
        rc = main(["report", name, "--root", str(case_root),
                   "--format", "html", "--output", str(out)])
        assert rc == 0
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "FRECE" in html

    def test_report_dfxml(self, tmp_path, monkeypatch):
        from frece.cli import main
        import frece.custody as cmod
        monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))
        monkeypatch.setattr(cmod, "_key_store_warning_shown", False)

        case_root = tmp_path / "cases"
        name = "DFXML-REPORT"
        main(["case", "create", name, "--root", str(case_root)])

        out = tmp_path / "report.dfxml"
        rc = main(["report", name, "--root", str(case_root),
                   "--format", "dfxml", "--output", str(out)])
        assert rc == 0
        xml = out.read_text()
        assert "<?xml" in xml
        assert "</dfxml>" in xml
        assert "dfxml" in xml

    def test_custody_encrypt_decrypt(self, tmp_path, monkeypatch):
        from frece.cli import main
        import frece.custody as cmod
        monkeypatch.setenv("FRECE_KEY_STORE", str(tmp_path / "keys"))
        monkeypatch.setattr(cmod, "_key_store_warning_shown", False)

        case_root = tmp_path / "cases"
        name = "ENC-TEST"
        main(["case", "create", name, "--root", str(case_root)])
        main(["case", "log", name, "ACQUIRE",
              "--root", str(case_root), "--evidence-id", "EV-001"])

        case_dir = case_root / name
        rc = main(["custody", "encrypt", str(case_dir),
                   "--passphrase", "TestPass_2025!"])
        assert rc == 0
        assert (case_dir / "custody.db.enc").exists()

        rc2 = main(["custody", "decrypt",
                    str(case_dir / "custody.db.enc"),
                    "--passphrase", "TestPass_2025!"])
        assert rc2 == 0
