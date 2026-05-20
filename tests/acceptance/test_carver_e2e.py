"""Acceptance carving test using a real embedded JPEG."""

import pytest

from frece.carver import StreamingCarver


@pytest.mark.acceptance
def test_carver_extracts_embedded_jpeg(workspace_runtime_dir, generated_sample_files):
    source = workspace_runtime_dir / "embedded.bin"
    source.write_bytes(
        b"\x00" * 2048
        + generated_sample_files["photo_jpg"].read_bytes()
        + b"\x00" * 512
    )

    carver = StreamingCarver()
    manifest = carver.carve(source, workspace_runtime_dir / "carved", verify=True)

    assert any(carved.file_type == "jpeg" for carved in manifest.carved_files)
