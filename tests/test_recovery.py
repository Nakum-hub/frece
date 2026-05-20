"""Tests for DeletedFileRecovery scan + recover workflow."""

import json
from unittest.mock import MagicMock, patch

import pytest

from frece.errors import RecoveryError
from frece.recovery import DeletedFileRecovery, RecoveredFile, ScannedEntry


FLS_SAMPLE = (
    "r/r * 12345:\tDELETED_FILE.jpg\n"
    "r/r * 67890:\tpasswords.txt\n"
    "d/d * 111:\tdeleted_folder\n"
    "r/r 222:\tsecond_chance.pdf\n"
)


class TestScanDeleted:
    @pytest.fixture
    def recovery(self):
        return DeletedFileRecovery()

    def test_scan_returns_scanned_entries(self, recovery, temp_dir):
        with patch.object(
            recovery, "_iter_fls_lines", return_value=iter(FLS_SAMPLE.splitlines())
        ):
            entries = recovery.scan_deleted(temp_dir / "image.dd")

        assert len(entries) == 4
        assert all(isinstance(entry, ScannedEntry) for entry in entries)

    def test_scan_preserves_filename(self, recovery, temp_dir):
        with patch.object(
            recovery, "_iter_fls_lines", return_value=iter(FLS_SAMPLE.splitlines())
        ):
            entries = recovery.scan_deleted(temp_dir / "image.dd")

        names = {entry.name for entry in entries}
        assert "DELETED_FILE.jpg" in names
        assert "passwords.txt" in names

    def test_scan_sets_type_correctly(self, recovery, temp_dir):
        with patch.object(
            recovery, "_iter_fls_lines", return_value=iter(FLS_SAMPLE.splitlines())
        ):
            entries = recovery.scan_deleted(temp_dir / "image.dd")

        types = {entry.entry_type for entry in entries}
        assert "r" in types
        assert "d" in types

    def test_scan_marks_unallocated(self, recovery, temp_dir):
        with patch.object(
            recovery, "_iter_fls_lines", return_value=iter(FLS_SAMPLE.splitlines())
        ):
            entries = recovery.scan_deleted(temp_dir / "image.dd")

        inodes = {entry.inode: entry.allocated for entry in entries}
        assert inodes[12345] is False
        assert inodes[222] is True

    def test_scan_fls_not_found_raises(self, recovery, temp_dir):
        with patch("frece.recovery.subprocess.Popen", side_effect=FileNotFoundError()):
            with pytest.raises(RecoveryError, match="fls"):
                recovery.scan_deleted(temp_dir / "image.dd")

    def test_scan_fls_failure_raises(self, recovery, temp_dir):
        fake_proc = MagicMock()
        fake_proc.stdout = iter(())
        fake_proc.stderr.read.return_value = "cannot open image"
        fake_proc.returncode = 1
        fake_proc.wait.return_value = 1

        with patch("frece.recovery.subprocess.Popen", return_value=fake_proc):
            with pytest.raises(RecoveryError):
                recovery.scan_deleted(temp_dir / "image.dd")

    def test_scan_deduplicates_inodes(self, recovery, temp_dir):
        duplicate_fls = "r/r * 12345:\tfile1.txt\nr/r * 12345:\tfile1_copy.txt\n"
        with patch.object(
            recovery, "_iter_fls_lines", return_value=iter(duplicate_fls.splitlines())
        ):
            entries = recovery.scan_deleted(temp_dir / "image.dd")

        assert len(entries) == 1

    def test_parse_ntfs_inode_token(self, recovery, temp_dir):
        ntfs_fls = "r/r * 24-128-2:\t$UsnJrnl:$J\n"
        with patch.object(
            recovery, "_iter_fls_lines", return_value=iter(ntfs_fls.splitlines())
        ):
            entries = recovery.scan_deleted(temp_dir / "image.dd")

        assert len(entries) == 1
        assert entries[0].inode == 24
        assert entries[0].inode_token == "24-128-2"


class TestRecoverDeleted:
    @pytest.fixture
    def recovery(self):
        return DeletedFileRecovery()

    def test_recover_loop_continues_on_inode_failure(self, recovery, temp_dir):
        """One bad inode must not stop recovery of remaining inodes."""
        call_count = {"n": 0}
        entries = [
            ScannedEntry(
                inode=1, inode_token="1", entry_type="r", name="one.txt", allocated=False
            ),
            ScannedEntry(
                inode=2, inode_token="2", entry_type="r", name="two.txt", allocated=False
            ),
            ScannedEntry(
                inode=3,
                inode_token="3",
                entry_type="r",
                name="three.txt",
                allocated=False,
            ),
        ]

        def fake_extract(image_path, inode, output_dir, **kwargs):
            call_count["n"] += 1
            if inode == 2:
                raise RecoveryError("icat failed", remediation="test")
            return RecoveredFile(
                inode=inode,
                size=4,
                file_type="txt",
                sha256="a" * 64,
                output_path=str(output_dir / f"{inode}.txt"),
                verified=False,
            )

        with patch.object(recovery, "_list_deleted_entries", return_value=entries):
            with patch.object(recovery, "_extract_inode", side_effect=fake_extract):
                results = recovery.recover_deleted(
                    temp_dir / "img.dd",
                    temp_dir / "out",
                )

        assert call_count["n"] == 3
        assert len(results) == 2

    def test_recover_filters_by_inode_list(self, recovery, temp_dir):
        """--inodes filter must limit which inodes are extracted."""
        extracted = []
        entries = [
            ScannedEntry(
                inode=inode,
                inode_token=str(inode),
                entry_type="r",
                name=f"{inode}.txt",
                allocated=False,
            )
            for inode in [1, 2, 3, 4, 5]
        ]

        def fake_extract(image_path, inode, output_dir, **kwargs):
            extracted.append(inode)
            return RecoveredFile(
                inode=inode,
                size=4,
                file_type="txt",
                sha256="b" * 64,
                output_path=str(output_dir / f"{inode}.txt"),
                verified=False,
            )

        with patch.object(recovery, "_list_deleted_entries", return_value=entries):
            with patch.object(recovery, "_extract_inode", side_effect=fake_extract):
                results = recovery.recover_deleted(
                    temp_dir / "img.dd",
                    temp_dir / "out",
                    inodes=[2, 4],
                )

        assert extracted == [2, 4]
        assert len(results) == 2

    def test_recover_manifest_includes_failed_inodes(self, recovery, temp_dir):
        """Recovery manifest must list skipped inodes with reasons."""
        entries = [
            ScannedEntry(
                inode=99, inode_token="99", entry_type="r", name="a.bin", allocated=False
            ),
            ScannedEntry(
                inode=100, inode_token="100", entry_type="r", name="b.bin", allocated=False
            ),
        ]

        def fake_extract(image_path, inode, output_dir, **kwargs):
            if inode == 99:
                raise RecoveryError("icat timeout", remediation="retry")
            return RecoveredFile(
                inode=inode,
                size=4,
                file_type="bin",
                sha256="c" * 64,
                output_path=str(output_dir / f"{inode}.bin"),
                verified=False,
            )

        with patch.object(recovery, "_list_deleted_entries", return_value=entries):
            with patch.object(recovery, "_extract_inode", side_effect=fake_extract):
                recovery.recover_deleted(temp_dir / "img.dd", temp_dir / "out")

        manifest = json.loads((temp_dir / "out" / "recovery_manifest.json").read_text())
        assert manifest["failed_count"] == 1
        assert manifest["failed_inodes"][0]["inode"] == 99

    def test_recover_passes_allowed_types_and_original_names(self, recovery, temp_dir):
        """Filtering aliases and original names must be threaded into extraction."""
        entries = [
            ScannedEntry(
                inode=42,
                inode_token="42",
                entry_type="r",
                name="deleted_photo.jpg",
                allocated=False,
            )
        ]
        seen = {}

        def fake_extract(image_path, inode, output_dir, **kwargs):
            seen["allowed_types"] = kwargs["allowed_types"]
            seen["original_name"] = kwargs["original_name"]
            return None

        with patch.object(recovery, "_list_deleted_entries", return_value=entries):
            with patch.object(recovery, "_extract_inode", side_effect=fake_extract):
                recovery.recover_deleted(
                    temp_dir / "img.dd",
                    temp_dir / "out",
                    file_types=["jpg"],
                )

        assert seen["allowed_types"] == {"jpeg"}
        assert seen["original_name"] == "deleted_photo.jpg"

    def test_output_path_prefers_original_name(self, recovery, temp_dir):
        """Recovered files should use the original fls filename when available."""
        output_path = recovery._output_path_for_inode(
            temp_dir,
            inode=42,
            file_type="jpeg",
            original_name="deleted_photo.jpg",
        )

        assert output_path.name == "deleted_photo.jpg"
