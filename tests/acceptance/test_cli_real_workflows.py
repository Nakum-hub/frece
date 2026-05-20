"""Real Linux CLI acceptance workflows using generated forensic sample data."""

import json
import zipfile

import pytest

from tests.acceptance.conftest import run_frece_cli


@pytest.mark.acceptance
def test_cli_acquire_real_file_and_rejects_special_device(
    sleuthkit_available,
    generated_sample_files,
    workspace_runtime_dir,
):
    source = generated_sample_files["incident_log"]
    output_dir = workspace_runtime_dir / "acquire"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "incident.img"

    result = run_frece_cli(
        "acquire",
        source,
        "--output",
        output_file,
        "--no-writeblock-required",
    )
    assert result.returncode == 0, result.stderr
    metadata = json.loads(result.stdout)
    assert output_file.read_bytes() == source.read_bytes()
    assert metadata["bytes_acquired"] == source.stat().st_size

    reject = run_frece_cli(
        "acquire",
        "/dev/zero",
        "--output",
        "/dev/null",
        "--no-writeblock-required",
    )
    assert reject.returncode == 1
    assert "special device" in reject.stderr


@pytest.mark.acceptance
def test_cli_carve_extracts_multiple_real_formats(
    sleuthkit_available,
    carve_source_bundle,
    workspace_runtime_dir,
):
    output_dir = workspace_runtime_dir / "carve-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    result = run_frece_cli(
        "carve",
        carve_source_bundle,
        "--output",
        output_dir,
        "--no-verify",
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads(result.stdout)
    carved_types = {entry["file_type"] for entry in manifest["carved_files"]}
    assert {"jpeg", "png", "pdf", "docx"}.issubset(carved_types)

    docx_path = next(output_dir.glob("*_docx"))
    pdf_path = next(output_dir.glob("*_pdf"))
    assert zipfile.is_zipfile(docx_path)
    assert pdf_path.read_bytes().startswith(b"%PDF")


@pytest.mark.acceptance
def test_cli_recover_filters_and_preserves_names(
    sleuthkit_available,
    ext4_image,
    workspace_runtime_dir,
):
    output_dir = workspace_runtime_dir / "recover-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    result = run_frece_cli(
        "recover",
        ext4_image,
        "--output",
        output_dir,
        "--type",
        "jpg,pdf",
    )
    assert result.returncode == 0, result.stderr

    files = sorted(path.name for path in output_dir.iterdir() if path.is_file())
    assert files == ["photo.jpg", "recovery_manifest.json", "report.pdf"]

    manifest = json.loads((output_dir / "recovery_manifest.json").read_text())
    assert manifest["recovered_count"] == 2
    assert {entry["original_name"] for entry in manifest["recovered_files"]} == {
        "docs/report.pdf",
        "pics/photo.jpg",
    }


@pytest.mark.acceptance
def test_cli_hash_case_and_report_real_workflow(
    sleuthkit_available,
    workspace_runtime_dir,
    carve_source_bundle,
    ext4_image,
):
    case_root = workspace_runtime_dir / "cases"
    case_name = "AcceptanceCase"
    case_dir = case_root / case_name
    env = {"FRECE_KEY_STORE": str(workspace_runtime_dir / "keys")}

    create_result = run_frece_cli("case", "create", case_name, "--root", case_root, env=env)
    assert create_result.returncode == 0, create_result.stderr
    assert (workspace_runtime_dir / "keys" / f"{case_name}.key").exists()
    assert not (case_dir / ".case_secret").exists()

    hash_path = case_dir / "hashes" / "source.json"
    hash_path.parent.mkdir(parents=True, exist_ok=True)
    hash_result = run_frece_cli("hash", carve_source_bundle, "--output", hash_path)
    assert hash_result.returncode == 0, hash_result.stderr
    source_hash = json.loads(hash_path.read_text())["sha256"]

    log_result = run_frece_cli(
        "case",
        "log",
        case_name,
        "ACQUIRE",
        "--root",
        case_root,
        "--evidence-id",
        "EV001",
        "--detail",
        f"source_hash={source_hash}",
        env=env,
    )
    assert log_result.returncode == 0, log_result.stderr

    carve_result = run_frece_cli(
        "carve",
        carve_source_bundle,
        "--output",
        case_dir / "carve",
        "--no-verify",
    )
    assert carve_result.returncode == 0, carve_result.stderr

    recover_result = run_frece_cli(
        "recover",
        ext4_image,
        "--output",
        case_dir / "recovery",
        "--type",
        "jpg,pdf",
    )
    assert recover_result.returncode == 0, recover_result.stderr

    report_path = case_dir / "report.json"
    report_result = run_frece_cli(
        "report",
        case_name,
        "--root",
        case_root,
        "--output",
        report_path,
        env=env,
    )
    assert report_result.returncode == 0, report_result.stderr

    report = json.loads(report_path.read_text())
    assert report["custody_entries"] == 1
    assert report["custody_verified"] is True
    assert len(report["carve_manifests"]) == 1
    assert len(report["recovery_manifests"]) == 1


@pytest.mark.acceptance
def test_cli_partitions_reports_real_offsets(
    sleuthkit_available,
    partitioned_disk_image,
):
    result = run_frece_cli("partitions", partitioned_disk_image)
    assert result.returncode == 0, result.stderr
    partitions = json.loads(result.stdout)
    assert any(partition["start_sector"] == 2048 for partition in partitions)
