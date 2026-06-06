# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
# ruff: noqa: E501
"""HTML report renderer for FRECE case reports."""

from frece import __version__


def render_html_report(report: dict, case_name: str) -> str:
    """Render a professional HTML case report."""
    total_carved = sum(len(m.get("carved_files", [])) for m in report["carve_manifests"])
    total_recovered = sum(
        len(m.get("recovered_files", [])) for m in report["recovery_manifests"]
    )
    custody_ok = "✅ Verified" if report.get("custody_verified") else "⚠️ Not verified"

    type_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    encrypted_count = 0

    all_artifacts = []
    for m in report["carve_manifests"]:
        all_artifacts.extend(m.get("carved_files", []))
    for m in report["recovery_manifests"]:
        all_artifacts.extend(m.get("recovered_files", []))

    for f in all_artifacts:
        ftype = f.get("file_type", "unknown")
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
        cat = f.get("forensic_category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        pri = f.get("forensic_priority", "LOW")
        priority_counts[pri] = priority_counts.get(pri, 0) + 1
        if f.get("possibly_encrypted"):
            encrypted_count += 1

    top_types = sorted(type_counts.items(), key=lambda x: -x[1])[:12]
    type_rows = "".join(f"<tr><td>{t}</td><td>{c}</td></tr>" for t, c in top_types)
    cat_rows = "".join(
        f"<tr><td>{c}</td><td>{cnt}</td></tr>"
        for c, cnt in sorted(category_counts.items(), key=lambda x: -x[1])
    )

    crit = priority_counts.get("CRITICAL", 0)
    high = priority_counts.get("HIGH", 0)
    badge_cls = "badge-ok" if report.get("custody_verified") else "badge-warn"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FRECE Case Report — {case_name}</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}}
  .header{{background:linear-gradient(135deg,#1a2332,#0f2027);padding:40px;border-bottom:3px solid #e05a00}}
  .header h1{{margin:0;font-size:2em;color:#fff;letter-spacing:2px}}
  .header p{{margin:8px 0 0;color:#8b949e;font-size:.9em}}
  .container{{max-width:1100px;margin:0 auto;padding:30px 20px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:30px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}}
  .card .num{{font-size:2.4em;font-weight:700;color:#58a6ff}}
  .card .label{{font-size:.85em;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:1px}}
  .card.critical .num{{color:#f85149}}
  .card.high .num{{color:#e3b341}}
  .card.encrypted .num{{color:#bc8cff}}
  .section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;margin-bottom:24px}}
  .section h2{{margin:0 0 16px;font-size:1.1em;color:#58a6ff;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #30363d;padding-bottom:10px}}
  table{{width:100%;border-collapse:collapse;font-size:.9em}}
  th{{background:#1c2128;color:#8b949e;text-align:left;padding:8px 12px;font-weight:600;text-transform:uppercase;font-size:.8em}}
  td{{padding:8px 12px;border-top:1px solid #21262d}}
  tr:hover td{{background:#1c2128}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.8em;font-weight:600}}
  .badge-ok{{background:#1a3a1a;color:#3fb950}}
  .badge-warn{{background:#3a1a1a;color:#f85149}}
  .footer{{text-align:center;padding:20px;color:#484f58;font-size:.8em;border-top:1px solid #21262d}}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 FRECE Forensic Investigation Report</h1>
  <p>Case: <strong>{case_name}</strong> &nbsp;·&nbsp; Generated: {report["generated_at"]} &nbsp;·&nbsp; Chain of Custody: {custody_ok}</p>
</div>
<div class="container">
  <div class="grid">
    <div class="card"><div class="num">{total_carved + total_recovered}</div><div class="label">Total Artifacts</div></div>
    <div class="card"><div class="num">{total_carved}</div><div class="label">Carved Files</div></div>
    <div class="card"><div class="num">{total_recovered}</div><div class="label">Recovered Files</div></div>
    <div class="card critical"><div class="num">{crit}</div><div class="label">Critical Priority</div></div>
    <div class="card high"><div class="num">{high}</div><div class="label">High Priority</div></div>
    <div class="card encrypted"><div class="num">{encrypted_count}</div><div class="label">Possibly Encrypted</div></div>
  </div>
  <div class="section">
    <h2>File Categories</h2>
    <table><tr><th>Category</th><th>Count</th></tr>{cat_rows}</table>
  </div>
  <div class="section">
    <h2>Top File Types</h2>
    <table><tr><th>Type</th><th>Count</th></tr>{type_rows}</table>
  </div>
  <div class="section">
    <h2>Chain of Custody</h2>
    <p>Entries: <strong>{report["custody_entries"]}</strong> &nbsp;·&nbsp; Status: <span class="badge {badge_cls}">{custody_ok}</span></p>
  </div>
</div>
<div class="footer">Generated by FRECE v{__version__} — Forensic Recovery and Evidence Carving Engine</div>
</body>
</html>"""

def render_dfxml_report(report: dict, case_name: str) -> str:
    """Render a DFXML (Digital Forensics XML) case report.

    DFXML is the court-accepted forensic XML standard used by FTK, EnCase,
    and The Sleuth Kit.  Prosecutors and defence counsel can parse DFXML
    directly.  This makes FRECE output admissible as a forensic evidence record.

    Standard: https://github.com/dfxml-working-group/dfxml_schema
    """
    from xml.sax.saxutils import escape as _xe
    import datetime as _dt

    now = _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")

    # Gather all artifacts
    all_carved: list[dict] = []
    for m in report.get("carve_manifests", []):
        all_carved.extend(m.get("carved_files", []))
    all_recovered: list[dict] = []
    for m in report.get("recovery_manifests", []):
        all_recovered.extend(m.get("recovered_files", []))

    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<dfxml version="1.2.0"',
        '  xmlns="http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML"',
        '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
        "",
        "  <!-- Generated by FRECE — Forensic Recovery and Evidence Carving Engine -->",
        f"  <!-- Version: {__version__} | Date: {now} -->",
        "",
        "  <metadata>",
        f"    <case_name>{_xe(case_name)}</case_name>",
        f"    <generated_at>{_xe(report.get('generated_at', now))}</generated_at>",
        f"    <frece_version>{_xe(__version__)}</frece_version>",
        f"    <custody_verified>{str(report.get('custody_verified', False)).lower()}</custody_verified>",
        f"    <custody_entries>{report.get('custody_entries', 0)}</custody_entries>",
        "  </metadata>",
        "",
        "  <source>",
        f"    <case_dir>{_xe(report.get('case_dir', ''))}</case_dir>",
        "  </source>",
        "",
        "  <!-- Carved files -->",
        f"  <fileobject_set type=\"carved\" count=\"{len(all_carved)}\">",
    ]

    for i, f in enumerate(all_carved):
        ftype = _xe(f.get("file_type", "unknown"))
        sha256 = _xe(f.get("sha256", ""))
        size = f.get("size", 0)
        offset = f.get("offset", 0)
        valid = str(f.get("validation_passed", False)).lower()
        score = f.get("confidence_score", 0)
        grade = _xe(f.get("confidence_grade", "UNKNOWN"))
        category = _xe(f.get("forensic_category", "unknown"))
        priority = _xe(f.get("forensic_priority", "LOW"))
        entropy = f.get("entropy", 0.0)
        yara = f.get("yara_matches", [])

        lines.extend([
            f'    <fileobject id="{i+1}">',
            f"      <filename>offset_{offset:016d}_{ftype}</filename>",
            f"      <filesize>{size}</filesize>",
            f"      <file_offset>{offset}</file_offset>",
            f"      <file_type>{ftype}</file_type>",
            f"      <forensic_category>{category}</forensic_category>",
            f"      <forensic_priority>{priority}</forensic_priority>",
            f"      <entropy>{entropy:.4f}</entropy>",
            f"      <validation_passed>{valid}</validation_passed>",
            f"      <confidence_score>{score}</confidence_score>",
            f"      <confidence_grade>{grade}</confidence_grade>",
        ])

        if sha256:
            lines.append(f'      <hashdigest type="SHA256">{sha256}</hashdigest>')

        if yara:
            lines.append("      <yara_matches>")
            for m in yara:
                lines.append(f'        <match rule="{_xe(m.get("rule",""))}" '
                             f'namespace="{_xe(m.get("namespace",""))}" />')
            lines.append("      </yara_matches>")

        # Metadata fields
        meta = f.get("artifact_metadata", {})
        if meta:
            lines.append("      <metadata>")
            for k, v in list(meta.items())[:20]:
                if v is not None and not isinstance(v, (list, dict)):
                    lines.append(f"        <{_xe(k)}>{_xe(str(v))}</{_xe(k)}>")
            lines.append("      </metadata>")

        lines.append("    </fileobject>")

    lines.extend([
        "  </fileobject_set>",
        "",
        "  <!-- Recovered deleted files -->",
        f'  <fileobject_set type="recovered" count="{len(all_recovered)}">',
    ])

    for i, f in enumerate(all_recovered):
        name = _xe(f.get("original_name") or f.get("suggested_name") or f"inode_{f.get('inode',0)}")
        ftype = _xe(f.get("file_type", "unknown"))
        sha256 = _xe(f.get("sha256", ""))
        size = f.get("size", 0)
        inode = f.get("inode", 0)
        mtime = f.get("mtime", 0)
        atime = f.get("atime", 0)
        ctime = f.get("ctime", 0)
        score = f.get("confidence_score", 0)
        grade = _xe(f.get("confidence_grade", "UNKNOWN"))
        category = _xe(f.get("forensic_category", "unknown"))

        lines.extend([
            f'    <fileobject id="{i+1}">',
            f"      <filename>{name}</filename>",
            f"      <filesize>{size}</filesize>",
            f"      <inode>{inode}</inode>",
            f"      <file_type>{ftype}</file_type>",
            f"      <forensic_category>{category}</forensic_category>",
            f"      <mtime>{mtime}</mtime>",
            f"      <atime>{atime}</atime>",
            f"      <ctime>{ctime}</ctime>",
            f"      <confidence_score>{score}</confidence_score>",
            f"      <confidence_grade>{grade}</confidence_grade>",
        ])
        if sha256:
            lines.append(f'      <hashdigest type="SHA256">{sha256}</hashdigest>')
        lines.append("    </fileobject>")

    lines.extend([
        "  </fileobject_set>",
        "",
        "</dfxml>",
    ])

    return "\n".join(lines)

