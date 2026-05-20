"""Acceptance-test fixtures for real forensic tools."""

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest


TOOLS = ["fls", "icat", "istat", "mmls", "dd", "mkfs.ext4", "debugfs", "parted"]
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_RUNTIME_BASE = WORKSPACE_ROOT / ".acceptance_runtime"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "acceptance: mark test as requiring installed Sleuth Kit tools",
    )


@pytest.fixture(scope="session")
def sleuthkit_available():
    missing = [tool for tool in TOOLS if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"Sleuth Kit acceptance dependencies not found: {missing}")
    return True


def _sanitize_runtime_name(name: str) -> str:
    """Normalize a pytest node id into a filesystem-safe directory name."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    return sanitized.strip("._") or "acceptance"


@pytest.fixture(scope="session", autouse=True)
def workspace_runtime_root():
    """Create a shared workspace-local root for acceptance artifacts."""
    WORKSPACE_RUNTIME_BASE.mkdir(parents=True, exist_ok=True)
    runtime_root = WORKSPACE_RUNTIME_BASE / f"run_{os.getpid()}"
    shutil.rmtree(runtime_root, ignore_errors=True)
    runtime_root.mkdir(parents=True, exist_ok=True)
    yield runtime_root
    shutil.rmtree(runtime_root, ignore_errors=True)
    try:
        WORKSPACE_RUNTIME_BASE.rmdir()
    except OSError:
        pass


@pytest.fixture
def workspace_runtime_dir(workspace_runtime_root, request):
    """Create an isolated workspace-local runtime directory per acceptance test."""
    runtime_dir = workspace_runtime_root / _sanitize_runtime_name(request.node.nodeid)
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    yield runtime_dir
    shutil.rmtree(runtime_dir, ignore_errors=True)


@pytest.fixture
def linux_runtime_dir(request):
    """Create a Linux-native scratch directory for block-image tooling."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux-native scratch space is required for acceptance fixtures")

    prefix = f"frece-{_sanitize_runtime_name(request.node.name)}-"
    with tempfile.TemporaryDirectory(prefix=prefix) as tmpdir:
        yield Path(tmpdir)


def _sample_pdf_bytes() -> bytes:
    """Return a minimal PDF payload."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n"
        b"0000000117 00000 n \ntrailer\n<< /Root 1 0 R /Size 4 >>\nstartxref\n186\n%%EOF\n"
    )


def _sample_jpeg_bytes() -> bytes:
    """Return a minimal JPEG payload."""
    return b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 64 + b"\xff\xd9"


def _sample_png_bytes() -> bytes:
    """Return a minimal PNG payload."""
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\x0dIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def _sample_docx_bytes() -> bytes:
    """Return a minimal DOCX payload."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", "<w:document/>")
    return buffer.getvalue()


@pytest.fixture
def generated_sample_files(workspace_runtime_dir):
    """Generate real sample files under the workspace for CLI validation."""
    samples_dir = workspace_runtime_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    assets = {
        "incident_log": samples_dir / "incident.log",
        "notes_txt": samples_dir / "notes.txt",
        "report_pdf": samples_dir / "report.pdf",
        "photo_jpg": samples_dir / "photo.jpg",
        "diagram_png": samples_dir / "diagram.png",
        "document_docx": samples_dir / "document.docx",
    }

    assets["incident_log"].write_text(
        "2026-04-11T12:00:00Z INFO acquisition started\n"
        "2026-04-11T12:00:01Z INFO acquisition completed\n",
        encoding="utf-8",
    )
    assets["notes_txt"].write_text("forensic notes for acceptance testing", encoding="utf-8")
    assets["report_pdf"].write_bytes(_sample_pdf_bytes())
    assets["photo_jpg"].write_bytes(_sample_jpeg_bytes())
    assets["diagram_png"].write_bytes(_sample_png_bytes())
    assets["document_docx"].write_bytes(_sample_docx_bytes())
    return assets


@pytest.fixture
def ext4_image(linux_runtime_dir, sleuthkit_available):
    """Create an ext4 image with multiple deleted files recoverable via debugfs."""
    img = linux_runtime_dir / "test.ext4"
    src_dir = linux_runtime_dir / "deleted-src"
    src_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={img}", "bs=1M", "count=20"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["mkfs.ext4", "-F", str(img)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    for directory in ("notes", "logs", "docs", "pics"):
        subprocess.run(
            ["debugfs", "-w", "-R", f"mkdir {directory}", str(img)],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    deleted_text_files = {
        "notes/hello.txt": "hello world",
        "logs/incident.log": "2026-04-11 deleted log entry\n",
    }
    for image_path, content in deleted_text_files.items():
        source_file = src_dir / Path(image_path).name
        source_file.write_text(content, encoding="utf-8")
        subprocess.run(
            ["debugfs", "-w", "-R", f"write {source_file} {image_path}", str(img)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["debugfs", "-w", "-R", f"unlink {image_path}", str(img)],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    for image_path, payload in {
        "docs/report.pdf": _sample_pdf_bytes(),
        "pics/photo.jpg": _sample_jpeg_bytes(),
    }.items():
        source_file = src_dir / Path(image_path).name
        source_file.write_bytes(payload)
        subprocess.run(
            ["debugfs", "-w", "-R", f"write {source_file} {image_path}", str(img)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["debugfs", "-w", "-R", f"unlink {image_path}", str(img)],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    return img


@pytest.fixture
def carve_source_bundle(workspace_runtime_dir, generated_sample_files):
    """Build a composite binary with multiple embedded recoverable formats."""
    source = workspace_runtime_dir / "carve-source" / "embedded.bin"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(
        b"\x00" * 512
        + generated_sample_files["photo_jpg"].read_bytes()
        + b"\x00" * 257
        + generated_sample_files["diagram_png"].read_bytes()
        + b"\x00" * 193
        + generated_sample_files["report_pdf"].read_bytes()
        + b"\x00" * 211
        + generated_sample_files["document_docx"].read_bytes()
        + b"\x00" * 128
    )
    return source


@pytest.fixture
def partitioned_disk_image(linux_runtime_dir, sleuthkit_available):
    """Create a real partitioned disk image for mmls validation."""
    image = linux_runtime_dir / "disk.dd"
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={image}", "bs=1M", "count=64"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "parted",
            "-s",
            str(image),
            "mklabel",
            "msdos",
            "mkpart",
            "primary",
            "ext4",
            "1MiB",
            "33MiB",
        ],
        check=True,
    )
    return image


def run_frece_cli(*args: object, env: dict[str, str] | None = None, timeout: int = 120):
    """Run the real FRECE CLI in a subprocess."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update({key: str(value) for key, value in env.items()})
    return subprocess.run(
        [sys.executable, "-m", "frece.cli", *[str(arg) for arg in args]],
        capture_output=True,
        text=True,
        env=merged_env,
        timeout=timeout,
        check=False,
    )
