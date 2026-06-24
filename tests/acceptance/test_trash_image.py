# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Acceptance test: extract freedesktop Trash from a real ext4 image (no mount)."""
import shutil
import subprocess
from pathlib import Path

import pytest

from frece.trash import TrashRecovery

pytestmark = pytest.mark.acceptance


def _require(*tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        pytest.skip(f"required tools not on PATH: {missing}")


def _debugfs(img: Path, cmd: str):
    subprocess.run(["debugfs", "-w", "-R", cmd, str(img)], check=True, capture_output=True)


def test_extract_freedesktop_trash_from_ext4_image(tmp_path):
    _require("dd", "mkfs.ext4", "debugfs", "fls", "icat")
    img = tmp_path / "trash.ext4"
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={img}", "bs=1M", "count=16"], check=True, capture_output=True
    )
    subprocess.run(["mkfs.ext4", "-F", str(img)], check=True, capture_output=True)
    for directory in (
        "/.local", "/.local/share", "/.local/share/Trash",
        "/.local/share/Trash/files", "/.local/share/Trash/info",
    ):
        _debugfs(img, f"mkdir {directory}")

    log_src = tmp_path / "hello.log"
    log_src.write_text("deleted audit log line\n")
    info_src = tmp_path / "hello.log.trashinfo"
    info_src.write_text(
        "[Trash Info]\nPath=/var/log/hello.log\nDeletionDate=2026-06-22T09:05:00\n"
    )
    _debugfs(img, f"write {log_src} /.local/share/Trash/files/hello.log")
    _debugfs(img, f"write {info_src} /.local/share/Trash/info/hello.log.trashinfo")

    tr = TrashRecovery()
    trash_dirs = tr.extract_trash_from_image(img, tmp_path / "staging")
    entries = tr.list_trashed(trash_dirs)

    assert any(e.trash_name == "hello.log" for e in entries)
    entry = next(e for e in entries if e.trash_name == "hello.log")
    assert entry.source_type == "freedesktop"
    assert entry.original_path == "/var/log/hello.log"

    out = tmp_path / "recovered"
    recovered = tr.recover(entries, output_dir=out)
    assert (out / "hello.log").read_text() == "deleted audit log line\n"
    assert len(recovered) >= 1
