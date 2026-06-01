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
