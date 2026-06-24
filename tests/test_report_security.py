# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Security regression tests for the HTML report renderer (stored-XSS hardening)."""
from frece.report import render_html_report


def _report_with_type(file_type: str, category: str = "image") -> dict:
    return {
        "carve_manifests": [
            {"carved_files": [
                {"file_type": file_type, "forensic_category": category, "forensic_priority": "LOW"}
            ]}
        ],
        "recovery_manifests": [],
        "custody_verified": True,
        "generated_at": "2026-06-24T00:00:00Z",
        "custody_entries": 3,
    }


def test_html_report_escapes_malicious_file_type():
    payload = "<script>alert(1)</script>"
    out = render_html_report(_report_with_type(payload), "CASE-1")
    assert payload not in out
    assert "&lt;script&gt;" in out


def test_html_report_escapes_malicious_category():
    out = render_html_report(_report_with_type("jpeg", "img<svg/onload=alert(1)>"), "CASE-1")
    assert "<svg/onload=alert(1)>" not in out
    assert "&lt;svg" in out


def test_html_report_escapes_case_name():
    report = {
        "carve_manifests": [], "recovery_manifests": [], "custody_verified": False,
        "generated_at": "t", "custody_entries": 0,
    }
    out = render_html_report(report, "<img src=x onerror=alert(1)>")
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;img" in out
