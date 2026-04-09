"""Tests for evidence acquisition."""

import hashlib
from pathlib import Path

import pytest

from frece.acquisition import EvidenceAcquisition, WriteBlockChecker
from frece.errors import AcquisitionError


class TestWriteBlockChecker:
    """Test write-block detection."""

    def test_writeblock_check_nonexistent_device(self):
        """Test check on non-existent device."""
        result = WriteBlockChecker.is_writeblock_enabled("/dev/nonexistent")

        assert result is False

    def test_require_writeblock_passes_on_enabled(self):
        """Test that require passes if write-block enabled."""
        try:
            WriteBlockChecker.require_writeblock("/dev/null", force=True)
        except AcquisitionError:
            pytest.fail("Should not raise when force=True")

    def test_require_writeblock_with_force(self):
        """Test force flag bypasses check."""
        try:
            WriteBlockChecker.require_writeblock("/dev/nonexistent", force=True)
        except AcquisitionError:
            pytest.fail("force=True should bypass check")

    def test_candidate_block_device_nvme_partition(self):
        """NVMe partitions must resolve to their parent block device."""
        candidates = WriteBlockChecker._candidate_block_devices("/dev/nvme0n1p1")
        assert "nvme0n1" in candidates

    def test_candidate_block_device_mmc_partition(self):
        """MMC partitions must resolve to their parent block device."""
        candidates = WriteBlockChecker._candidate_block_devices("/dev/mmcblk0p1")
        assert "mmcblk0" in candidates


class TestEvidenceAcquisition:
    """Test evidence acquisition."""

    @pytest.fixture
    def acq(self):
        """Create acquisition instance."""
        return EvidenceAcquisition()

    def test_acquire_file(self, acq, temp_dir):
        """Test acquiring a file."""
        source = temp_dir / "source.txt"
        source.write_bytes(b"test data")

        output = temp_dir / "output.img"

        metadata = acq.acquire_device(
            str(source), output, writeblock_required=False, force_no_writeblock=True
        )

        assert metadata["bytes_acquired"] == 9
        assert output.exists()
        assert len(metadata["sha256"]) == 64

    def test_acquire_preserves_content(self, acq, temp_dir):
        """Test that acquisition preserves content."""
        source = temp_dir / "source.txt"
        test_data = b"test data content"
        source.write_bytes(test_data)

        output = temp_dir / "output.img"

        metadata = acq.acquire_device(
            str(source), output, writeblock_required=False, force_no_writeblock=True
        )

        acquired_data = output.read_bytes()
        assert acquired_data == test_data

    def test_acquire_computes_hash(self, acq, temp_dir):
        """Test that acquisition computes correct hash."""
        source = temp_dir / "source.txt"
        test_data = b"test data"
        source.write_bytes(test_data)

        output = temp_dir / "output.img"

        metadata = acq.acquire_device(
            str(source), output, writeblock_required=False, force_no_writeblock=True
        )

        expected_sha256 = hashlib.sha256(test_data).hexdigest()
        assert metadata["sha256"] == expected_sha256

    def test_acquire_nonexistent_source(self, acq, temp_dir):
        """Test error on missing source."""
        output = temp_dir / "output.img"

        with pytest.raises(AcquisitionError):
            acq.acquire_device(
                str(temp_dir / "nonexistent.img"),
                output,
                writeblock_required=False,
                force_no_writeblock=True,
            )

    def test_acquire_creates_output_dir(self, acq, temp_dir):
        """Test that acquisition creates output directory."""
        source = temp_dir / "source.txt"
        source.write_bytes(b"test")

        output = temp_dir / "subdir" / "output.img"

        metadata = acq.acquire_device(
            str(source), output, writeblock_required=False, force_no_writeblock=True
        )

        assert output.exists()

    def test_acquire_metadata_has_timestamp(self, acq, temp_dir):
        """Test that metadata includes timestamp."""
        source = temp_dir / "source.txt"
        source.write_bytes(b"test")

        output = temp_dir / "output.img"

        metadata = acq.acquire_device(
            str(source), output, writeblock_required=False, force_no_writeblock=True
        )

        assert "timestamp" in metadata
        assert metadata["timestamp"].endswith("Z")

    def test_acquire_multiple_files(self, acq, temp_dir):
        """Test acquiring multiple files."""
        sources = [temp_dir / f"source{i}.txt" for i in range(3)]
        for source in sources:
            source.write_bytes(b"test data")

        output_dir = temp_dir / "output"

        metadata = acq.acquire_files(sources, output_dir)

        assert len(metadata) == 3

    def test_acquire_files_hashes(self, acq, temp_dir):
        """Test that file acquisition computes hashes."""
        source = temp_dir / "source.txt"
        test_data = b"test data"
        source.write_bytes(test_data)

        output_dir = temp_dir / "output"

        metadata = acq.acquire_files([source], output_dir)

        assert len(metadata) == 1
        assert "sha256" in list(metadata.values())[0]

    def test_acquire_directory_recursive(self, acq, temp_dir):
        """Test recursive directory acquisition."""
        source_dir = temp_dir / "source"
        source_dir.mkdir()

        file1 = source_dir / "file1.txt"
        file1.write_bytes(b"test1")

        file2 = source_dir / "subdir" / "file2.txt"
        file2.parent.mkdir()
        file2.write_bytes(b"test2")

        output_dir = temp_dir / "output"

        metadata = acq.acquire_files([source_dir], output_dir, recursive=True)

        assert len(metadata) == 2

    def test_acquire_files_returns_acquired_and_failed_keys(self, acq, temp_dir):
        source = temp_dir / "file.txt"
        source.write_bytes(b"content")

        result = acq.acquire_files([source], temp_dir / "out")

        assert "acquired" in result
        assert "failed" in result

    def test_acquire_files_no_collision_on_same_name(self, acq, temp_dir):
        dir1 = temp_dir / "d1"
        dir2 = temp_dir / "d2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "report.txt").write_bytes(b"from dir1")
        (dir2 / "report.txt").write_bytes(b"from dir2")

        out = temp_dir / "out"
        result = acq.acquire_files([dir1 / "report.txt", dir2 / "report.txt"], out)
        output_files = [value["output_file"] for value in result["acquired"].values()]

        assert len(set(output_files)) == 2

    def test_acquire_files_surfaces_failures(self, acq, temp_dir):
        missing = temp_dir / "ghost.bin"

        result = acq.acquire_files([missing], temp_dir / "out")

        assert len(result["failed"]) == 1
        assert len(result["acquired"]) == 0

    def test_hash_file_returns_sha256(self, acq, temp_dir):
        evidence_file = temp_dir / "evidence.bin"
        evidence_file.write_bytes(b"test evidence data")

        result = acq.hash_file(evidence_file)

        assert "sha256" in result
        assert len(result["sha256"]) == 64
        assert result["size_bytes"] == 18

    def test_hash_file_missing_raises(self, acq, temp_dir):
        with pytest.raises(AcquisitionError):
            acq.hash_file(temp_dir / "nonexistent.dd")
