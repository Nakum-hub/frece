# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Unit tests for cross-platform Trash recovery (frece.trash)."""
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

from frece.trash import TrashRecovery, parse_trashinfo, parse_windows_index


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


# ──────────────────────────────────────────────────────────────────
# Windows $Recycle.Bin
# ──────────────────────────────────────────────────────────────────

def _filetime(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


def _make_windows_recycle(root: Path):
    sid = root / "$Recycle.Bin" / "S-1-5-21-1234567890-1-1-1001"
    sid.mkdir(parents=True)
    content = b"WINDOWS SECRET DOC CONTENT\n"
    (sid / "$RABCDEF.docx").write_bytes(content)
    original = "C:\\Users\\Bob\\Documents\\secret.docx"
    ft = _filetime(datetime(2026, 6, 23, 22, 14, 5, tzinfo=timezone.utc))
    path_bytes = original.encode("utf-16-le") + b"\x00\x00"
    index = (
        struct.pack("<QQQ", 2, len(content), ft)
        + struct.pack("<I", len(original) + 1)
        + path_bytes
    )
    (sid / "$IABCDEF.docx").write_bytes(index)
    return sid, original, content


def test_parse_windows_index_v2():
    original = "C:\\Users\\Bob\\file.txt"
    ft = _filetime(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    data = struct.pack("<QQQ", 2, 123, ft) + struct.pack("<I", len(original) + 1) + \
        original.encode("utf-16-le") + b"\x00\x00"
    meta = parse_windows_index(data)
    assert meta["original_path"] == original
    assert meta["size"] == 123
    assert meta["deletion_date"].startswith("2026-01-02T03:04:05")


def test_parse_windows_index_v1():
    original = "C:\\X\\y.txt"
    ft = _filetime(datetime(2025, 12, 31, 0, 0, 0, tzinfo=timezone.utc))
    raw = original.encode("utf-16-le")
    raw += b"\x00" * (520 - len(raw))  # fixed 260-wchar field
    data = struct.pack("<QQQ", 1, 10, ft) + raw
    meta = parse_windows_index(data)
    assert meta["original_path"] == original
    assert meta["size"] == 10


def test_list_windows_recycle_bin(tmp_path):
    sid, original, content = _make_windows_recycle(tmp_path)
    entries = TrashRecovery().list_trashed([sid])
    assert len(entries) == 1
    entry = entries[0]
    assert entry.source_type == "windows"
    assert entry.original_path == original
    assert entry.deletion_date.startswith("2026-06-23T22:14:05")
    assert entry.size == len(content)
    assert entry.has_info is True


def test_recover_windows_uses_original_name(tmp_path):
    sid, _original, content = _make_windows_recycle(tmp_path)
    tr = TrashRecovery()
    entries = tr.list_trashed([sid])
    out = tmp_path / "out"
    recovered = tr.recover(entries, output_dir=out)
    assert len(recovered) == 1
    assert (out / "secret.docx").read_bytes() == content  # $R content, original basename


# ──────────────────────────────────────────────────────────────────
# macOS Trash
# ──────────────────────────────────────────────────────────────────

def _make_macos_trash(root: Path) -> Path:
    trash = root / ".Trash"
    trash.mkdir()
    (trash / "vacation.jpg").write_bytes(b"macos-photo-bytes")
    (trash / ".DS_Store").write_bytes(b"\x00\x00")  # metadata, must be skipped
    return trash


def test_list_macos_trash(tmp_path):
    trash = _make_macos_trash(tmp_path)
    entries = TrashRecovery().list_trashed([trash])
    names = {e.trash_name for e in entries}
    assert "vacation.jpg" in names
    assert ".DS_Store" not in names
    photo = next(e for e in entries if e.trash_name == "vacation.jpg")
    assert photo.source_type == "macos"
    assert photo.deletion_date is not None
    assert len(photo.sha256) == 64


def test_discover_finds_windows_and_macos_under_root(tmp_path):
    _make_windows_recycle(tmp_path)
    _make_macos_trash(tmp_path)
    dirs = TrashRecovery().discover_trash_dirs(explicit=tmp_path)
    kinds = {TrashRecovery._trash_kind(d) for d in dirs}
    assert "windows" in kinds
    assert "macos" in kinds


def test_cli_trash_list_windows(tmp_path):
    from frece.cli import main

    sid, _original, _content = _make_windows_recycle(tmp_path)
    report_path = tmp_path / "win.json"
    rc = main(["trash", "list", "--path", str(sid), "--output", str(report_path)])
    assert rc == 0
    report = json.loads(report_path.read_text())
    assert report["total"] == 1
    assert report["entries"][0]["source_type"] == "windows"
