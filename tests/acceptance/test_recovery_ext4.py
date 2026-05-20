"""Acceptance recovery test against a real ext4 image."""

import pytest

from frece.recovery import DeletedFileRecovery


@pytest.mark.acceptance
def test_recover_deleted_txt(sleuthkit_available, ext4_image, workspace_runtime_dir):
    recovery = DeletedFileRecovery()
    output_dir = workspace_runtime_dir / "recover-txt"
    output_dir.mkdir(parents=True, exist_ok=True)
    files = recovery.recover_deleted(ext4_image, output_dir)

    assert len(files) >= 1
    recovered_path = next(output_dir.glob("*.txt"))
    assert "hello world" in recovered_path.read_text(errors="ignore")
