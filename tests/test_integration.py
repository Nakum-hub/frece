"""Integration tests for FRECE."""

import hashlib
import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from frece.carver import StreamingCarver
from frece.custody import CustodyDatabase, create_case_secret_key
from frece.acquisition import EvidenceAcquisition
from frece.sandbox import InputValidator, SandboxedExecutor
from frece.parallel import ParallelProcessor
from frece.cli import check_tools, main
from frece.config import Config
from frece.recovery import DeletedFileRecovery
from frece.errors import FreceError, CustodyError


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_acquisition_to_carving_workflow(self, temp_dir):
        """Test complete workflow: acquire -> carve -> verify."""
        source = temp_dir / "evidence.img"
        test_data = b"\x00" * 100 + b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"\xff\xd9"
        source.write_bytes(test_data)

        acq = EvidenceAcquisition()
        output = temp_dir / "acquired.img"

        acq_metadata = acq.acquire_device(
            str(source),
            output,
            writeblock_required=False,
            force_no_writeblock=True,
        )

        assert output.exists()
        assert acq_metadata["bytes_acquired"] == len(test_data)

        config = Config()
        carver = StreamingCarver(config)

        carved_dir = temp_dir / "carved"
        manifest = carver.carve(output, carved_dir, verify=True)

        assert len(manifest.carved_files) > 0
        assert any(f.file_type == "jpeg" for f in manifest.carved_files)

        jpeg_file = next(f for f in manifest.carved_files if f.file_type == "jpeg")
        assert jpeg_file.validation_passed

    def test_custody_evidence_tracking_workflow(self, temp_dir):
        """Test complete custody workflow."""
        case_dir = temp_dir / "case1"
        case_dir.mkdir()

        secret_key = create_case_secret_key(case_dir)
        custody_db = CustodyDatabase(case_dir / "custody.db", secret_key)

        custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={
                "source": "/dev/sda1",
                "size": 1000000,
                "source_hash": "abc123def456",
            },
        )

        custody_db.log_event(
            event_type="HASH",
            evidence_id="EV001",
            operator="analyst1",
            details={"hash": "abc123def456", "algorithm": "sha256"},
        )

        custody_db.log_event(
            event_type="CARVE",
            evidence_id="EV001",
            operator="analyst1",
            details={"files_carved": 5, "total_size": 50000},
        )

        log = custody_db.get_evidence_log("EV001")
        assert len(log) == 3

        total, tampered = custody_db.verify_database()
        assert total == 3
        assert tampered == 0

        custody_db.verify_evidence_source("EV001", "abc123def456")

    def test_sandboxed_operation_with_validation(self, temp_dir):
        """Test sandboxed operations with input validation."""
        validated_path = InputValidator.validate_path("/tmp/test_case")
        assert validated_path.name == "test_case"

        validated_case = InputValidator.validate_case_name("Case-2024-001")
        assert validated_case == "Case-2024-001"

        executor = SandboxedExecutor()
        result = executor.run_command(
            [sys.executable, "-c", "print('test')"],
            timeout=10,
        )
        assert result.returncode == 0

    def test_parallel_hash_and_carve(self, temp_dir):
        """Test parallel hashing and carving operations."""
        files = []
        for i in range(3):
            f = temp_dir / f"file{i}.bin"
            f.write_bytes(b"\x00" * 1000 + b"\xff\xd8" + b"\x00" * 100)
            files.append(f)

        processor = ParallelProcessor()
        hashes = processor.hash_files_parallel(files, max_workers=2)

        assert len(hashes) == 3
        assert all(len(h) == 64 for h in hashes.values())

    def test_config_loading_and_defaults(self, temp_dir):
        """Test configuration loading and defaults."""
        config = Config()

        assert config.max_ram_per_operation == 64 * 1024 * 1024
        assert config.default_hash == "sha256"
        assert config.chunk_size == 64 * 1024 * 1024
        assert config.max_signature_length == 2048

    def test_error_propagation_with_remediation(self):
        """Test that errors include remediation hints."""
        with pytest.raises(FreceError) as exc_info:
            InputValidator.validate_path("x" * 5000)

        assert "REMEDIATION" in str(exc_info.value)

    def test_zero_silent_failures_on_carving(self, temp_dir):
        """Test that carving never silently fails."""
        config = Config()
        carver = StreamingCarver(config)

        nonexistent = temp_dir / "nonexistent.img"

        with pytest.raises(FreceError):
            carver.carve(nonexistent, temp_dir / "output")

    def test_all_timestamps_utc_iso8601(self, temp_dir):
        """Test that all timestamps use UTC ISO 8601 with Z suffix."""
        source = temp_dir / "test.img"
        source.write_bytes(b"test")

        acq = EvidenceAcquisition()
        output = temp_dir / "out.img"

        metadata = acq.acquire_device(
            str(source),
            output,
            writeblock_required=False,
            force_no_writeblock=True,
        )

        timestamp = metadata["timestamp"]
        assert timestamp.endswith("Z")
        assert "T" in timestamp

        case_dir = temp_dir / "case"
        secret_key = create_case_secret_key(case_dir)
        custody_db = CustodyDatabase(case_dir / "custody.db", secret_key)

        entry = custody_db.log_event(
            event_type="ACQUIRE",
            evidence_id="EV001",
            operator="analyst1",
            details={"test": True},
        )

        assert entry.timestamp.endswith("Z")
        assert "T" in entry.timestamp

    def test_manifest_json_format(self, temp_dir):
        """Test that manifest JSON is properly formatted."""
        source = temp_dir / "test.img"
        test_data = b"\xff\xd8" + b"\x00" * 100 + b"\xff\xd9"
        source.write_bytes(test_data)

        config = Config()
        carver = StreamingCarver(config)
        carved_dir = temp_dir / "carved"

        carver.carve(source, carved_dir, verify=False)

        manifest_file = carved_dir / "carve_manifest.json"
        assert manifest_file.exists()

        with open(manifest_file) as f:
            manifest = json.load(f)

        assert "source" in manifest
        assert "source_sha256" in manifest
        assert "timestamp" in manifest
        assert "carved_files" in manifest
        assert isinstance(manifest["carved_files"], list)

        if manifest["carved_files"]:
            file_entry = manifest["carved_files"][0]
            assert "offset" in file_entry
            assert "size" in file_entry
            assert "file_type" in file_entry
            assert "sha256" in file_entry
            assert "validation_passed" in file_entry

    def test_cli_carve_command(self, temp_dir):
        """CLI carve command must dispatch to the carver implementation."""
        source = temp_dir / "test.img"
        source.write_bytes(b"\xff\xd8" + b"\x00" * 100 + b"\xff\xd9")

        exit_code = main(
            [
                "carve",
                str(source),
                "--output",
                str(temp_dir / "carved"),
                "--no-verify",
            ]
        )

        assert exit_code == 0
        assert (temp_dir / "carved" / "carve_manifest.json").exists()

    def test_cli_case_workflow(self, temp_dir):
        """CLI case commands must create, log, and verify a case."""
        case_root = temp_dir / "cases"

        assert main(["case", "create", "Case-001", "--root", str(case_root)]) == 0
        assert (
            main(
                [
                    "case",
                    "log",
                    "Case-001",
                    "ACQUIRE",
                    "--root",
                    str(case_root),
                    "--evidence-id",
                    "EV001",
                    "--source",
                    "/dev/sda1",
                    "--size",
                    "1000",
                ]
        )
            == 0
        )
        assert main(["case", "verify", "Case-001", "--root", str(case_root)]) == 0

    def test_cli_rejects_invalid_case_name(self):
        """CLI must reject dangerous case names instead of accepting them."""
        assert main(["case", "create", "Bad|Case"]) == 1

    def test_recovery_detects_docx_container(self, sample_docx_data):
        """Recovered OOXML data must keep the Office-specific extension."""
        recovery = DeletedFileRecovery()
        assert recovery._detect_file_type(sample_docx_data) == "docx"

    def test_tool_status_propagates_failure(self, monkeypatch):
        """Tool-status must return non-zero when required tools are missing."""
        def missing_tool(*args, **kwargs):
            raise FileNotFoundError

        monkeypatch.setattr("frece.cli.subprocess.run", missing_tool)
        assert check_tools() == 1

    def test_cli_scan_command_requires_fls(self, temp_dir, monkeypatch, capsys):
        """scan command must surface fls-not-found as an error."""
        img = temp_dir / "image.dd"
        img.write_bytes(b"\x00" * 512)

        monkeypatch.setattr(
            "frece.recovery.subprocess.run",
            lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
        )

        assert main(["scan", str(img)]) == 1
        assert "fls" in capsys.readouterr().err

    def test_cli_hash_command(self, temp_dir):
        """hash command must return valid JSON with sha256."""
        evidence_file = temp_dir / "evidence.dd"
        evidence_file.write_bytes(b"test content for hash")

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            result = main(["hash", str(evidence_file)])
        finally:
            sys.stdout = old_stdout

        assert result == 0
        data = json.loads(captured.getvalue())
        assert "sha256" in data
        assert len(data["sha256"]) == 64

    def test_scan_and_recover_workflow(self, temp_dir):
        """scan output inode list must be usable as input to recover."""
        recovery = DeletedFileRecovery()
        fake_fls = "r/r * 42:\tdeleted_photo.jpg\nr/r * 99:\tdoc.pdf\n"

        with patch("frece.recovery.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=fake_fls,
                stderr="",
            )
            entries = recovery.scan_deleted(temp_dir / "img.dd")

        assert len(entries) == 2
        inode_list = [entry.inode for entry in entries]
        assert 42 in inode_list
        assert 99 in inode_list
