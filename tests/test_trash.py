# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Unit tests for freedesktop Trash recovery (frece.trash)."""
import json
from pathlib import Path

from frece.trash import TrashRecovery, parse_trashinfo


def _make_trash(root: Path) -> Path:
    """Build a realistic freedesktop Trash directory under *root*."""
    trash = root / "Trash"
    files = trash / "files"
    info = trash / "info"
    files.mkdir(parents=True)
    info.mkdir(parents=True)

    (files / "secret.txt").write_text("CONFIDENTIAL DATA\n")
    (info / "secret.txt.trashinfo").write_text(
        "[Trash Info]\nPath=/home/alice/Documents/secret.txt\n"
        "DeletionDate=2026-06-23T10:42:11\n"
    )

    # original path with spaces -> URL-encoded per the spec
    (files / "my report.pdf").write_bytes(b"%PDF-1.4 fake")
    (info / "my report.pdf.trashinfo").write_text(
        "[Trash Info]\nPath=/home/alice/My%20Documents/my%20report.pdf\n"
        "DeletionDate=2026-06-22T09:00:00\n"
    )

    # a trashed directory
    proj = files / "proj"
    proj.mkdir()
    (proj / "a.txt").write_text("x" * 100)
    (info / "proj.trashinfo").write_text(
        "[Trash Info]\nPath=/home/alice/proj\nDeletionDate=2026-06-21T08:00:00\n"
    )

    # orphan file: present in files/ but no .trashinfo
    (files / "orphan.bin").write_bytes(b"\x00\x01\x02\x03")
    return trash


def test_parse_trashinfo_decodes_url(tmp_path):
    info = tmp_path / "x.trashinfo"
    info.write_text("[Trash Info]\nPath=/home/u/a%20b%2Fc.txt\nDeletionDate=2026-01-01T00:00:00\n")
    original, deleted = parse_trashinfo(info)
    assert original == "/home/u/a b/c.txt"
    assert deleted == "2026-01-01T00:00:00"


def test_discover_explicit_trash_dir(tmp_path):
    trash = _make_trash(tmp_path)
    dirs = TrashRecovery().discover_trash_dirs(explicit=trash)
    assert dirs == [trash]


def test_discover_from_search_root(tmp_path):
    _make_trash(tmp_path / ".local/share")
    dirs = TrashRecovery().discover_trash_dirs(explicit=tmp_path)
    assert any(d.name == "Trash" for d in dirs)


def test_list_trashed_extracts_forensic_context(tmp_path):
    trash = _make_trash(tmp_path)
    entries = {e.trash_name: e for e in TrashRecovery().list_trashed([trash])}

    assert set(entries) == {"secret.txt", "my report.pdf", "proj", "orphan.bin"}

    secret = entries["secret.txt"]
    assert secret.original_path == "/home/alice/Documents/secret.txt"
    assert secret.deletion_date == "2026-06-23T10:42:11"
    assert secret.size == len("CONFIDENTIAL DATA\n")
    assert len(secret.sha256) == 64
    assert secret.has_info is True

    report = entries["my report.pdf"]
    assert report.original_path == "/home/alice/My Documents/my report.pdf"

    proj = entries["proj"]
    assert proj.is_dir is True
    assert proj.sha256 == ""  # directories are not hashed
    assert proj.size >= 100

    orphan = entries["orphan.bin"]
    assert orphan.has_info is False
    assert orphan.original_path is None


def test_recover_forensic_copy_preserves_trash(tmp_path):
    trash = _make_trash(tmp_path)
    out = tmp_path / "recovered"
    tr = TrashRecovery()
    entries = tr.list_trashed([trash])
    recovered = tr.recover(entries, output_dir=out)

    # every entry recovered, trash left intact (evidence preserved)
    assert len(recovered) == len(entries)
    assert (trash / "files" / "secret.txt").exists()
    assert (out / "secret.txt").read_text() == "CONFIDENTIAL DATA\n"
    # original name (with space) is used when known
    assert (out / "my report.pdf").exists()
    # directory recovered recursively
    assert (out / "proj" / "a.txt").exists()


def test_recover_to_original_moves_and_clears_info(tmp_path):
    trash = tmp_path / "Trash"
    files = trash / "files"
    info = trash / "info"
    files.mkdir(parents=True)
    info.mkdir(parents=True)
    dest = tmp_path / "restored_here"
    (files / "doc.txt").write_text("payload")
    (info / "doc.txt.trashinfo").write_text(
        f"[Trash Info]\nPath={dest}/doc.txt\nDeletionDate=2026-06-23T10:00:00\n"
    )

    tr = TrashRecovery()
    entries = tr.list_trashed([trash])
    recovered = tr.recover(entries, to_original=True)

    assert len(recovered) == 1
    assert (dest / "doc.txt").read_text() == "payload"
    assert not (files / "doc.txt").exists()              # moved out of trash
    assert not (info / "doc.txt.trashinfo").exists()     # info record cleared


def test_cli_trash_list_and_recover(tmp_path, capsys):
    from frece.cli import main

    trash = _make_trash(tmp_path)
    report_path = tmp_path / "trash.json"
    rc = main(["trash", "list", "--path", str(trash), "--output", str(report_path)])
    assert rc == 0
    report = json.loads(report_path.read_text())
    assert report["total"] == 4
    names = {e["trash_name"] for e in report["entries"]}
    assert "secret.txt" in names

    out = tmp_path / "out"
    rc = main(["trash", "recover", "--path", str(trash), "--all", "--output", str(out)])
    assert rc == 0
    assert (out / "secret.txt").exists()
    assert (out / "trash_recovery_manifest.json").exists()


def test_cli_trash_requires_selection(tmp_path):
    from frece.cli import main

    trash = _make_trash(tmp_path)
    # recover without --all/--name must error cleanly, not crash
    rc = main(["trash", "recover", "--path", str(trash), "--output", str(tmp_path / "o")])
    assert rc == 1
