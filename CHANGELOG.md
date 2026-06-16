# FRECE Changelog

All notable changes are documented here. Versions follow semantic versioning.

---

## Unreleased — License Change (Proprietary, All Rights Reserved)

### License
- **Relicensed from MIT to a proprietary "All Rights Reserved" license.** FRECE is
  now the proprietary and confidential property of Nakum-hub. Use, copying,
  modification, and distribution require the prior written permission of the owner.
  See `LICENSE` for the full terms.
- `pyproject.toml`: license metadata changed from `MIT` to `LicenseRef-Proprietary`;
  the OSI MIT classifier replaced with `License :: Other/Proprietary License`; author
  field updated to `Nakum-hub`.
- `README.md`: added a top-level proprietary-software notice and rewrote the License
  section; the license badge now reads `Proprietary`.
- Per-file copyright headers across the Python source files updated from
  `Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.` to
  `Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.`

> Note: Copies previously released under the MIT License remain licensed under MIT
> for those specific versions. This change applies to the current and future versions.

---

## v2.5.0 — Production Release (Copyright-Clean, Zero False Positives)

### Repository Cleanup
- Removed internal development files: `FRECE_ENGINEERING_FIX_PROMPT.md`,
  `IMPLEMENTATION_SUMMARY.md`, `PHASES_CHECKLIST.md`, `.vscode/settings.json`
- Rewrote `DEPLOYMENT.md` as professional user-facing installation guide
- Added `LICENSE` (MIT) — required for commercial distribution
- Added `THIRD_PARTY_LICENSES.md` — all runtime dependencies verified commercially safe

### Copyright Headers
All 18 Python source files now carry `Copyright (c) 2025 FRECE Contributors. Licensed under MIT.`

### Bug Fixes
- **False positives eliminated**: Removed `b'\x00\x00\x01\x00'` ICO signature — 4 bytes
  too generic, fired on every null-padded region. Carving now produces **zero false positives**
  on random/binary data (was: 5 ICO false hits per raw image).
- **Empty file skip**: `_extract_inode` now skips 0-byte recovered files.
  ext4 with journaling zeroes inode block pointers on deletion (security feature) — these
  files are truly unrecoverable via icat and were previously saved as empty `.bin` files.
- **pyproject.toml**: License field corrected from `GPL-3.0-or-later` to `MIT` to match
  the actual `LICENSE` file.
- **Version**: bumped from 2.4.0 → 2.5.0.

### Improvements
- **`_detect_file_type` expanded** from 15 → 45 type checks covering all 88 FRECE
  carving types: SQLite, PCAP, PE, ELF, EVTX, LNK, REG, PSD, VMDK, Prefetch,
  Mach-O, RTF, XML, EML variants, FLAC, OGG, GIF, BMP, TIFF, 7z, RAR, GZ, BZ2, XZ,
  Plist, MKV, FLV, CSV, script, PHP, and more.

---

## v2.4.0 — Enterprise Security & Capability Release

### Bug Fixes
- **Bug-A `sandbox.py`**: `validate_case_name` now enforces a strict regex whitelist
  `^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$` — blocks path traversal (`../`), slashes,
  null bytes, and shell metacharacters. Security audit PASS.
- **Bug-B `carver.py`**: PE/EXE/DLL carving was broken because `_quick_validate_sig`
  read only 32 bytes (PE offset field is at byte 60). Fixed to read 128 bytes.
  Windows executables now carved correctly — the #1 artifact type in IR/malware cases.
- **Bug-C `scoring.py`**: `score_batch` now passes `artifact_metadata` from the manifest
  and uses hex offset format (`:016x`) matching the carver. A carved file now receives
  identical confidence scores at carve-time and when re-run via `frece score`.
- **Bug-D `metadata.py`**: PNG metadata extractor added — IHDR dimensions (width/height/
  bit depth), `tEXt`/`iTXt` key-value chunks (Author, Creation Time, GPS, Software),
  `gAMA` (gamma), `pHYs` (DPI).

### New Features
- **E01/EWF forensic image support** (`frece/ewf.py`):
  Auto-detects `.E01/.Ex01/.AFF` by extension and magic bytes. Exports via `ewfexport`
  transparently — `frece carve/recover/scan` accept E01 images directly.
- **DFXML court-admissible output** (`frece report --format dfxml`):
  Produces Digital Forensics XML per the DFXML standard (compatible with FTK, EnCase,
  The Sleuth Kit). Includes hashes, timestamps, confidence scores, YARA matches.
- **YARA rule integration** (`frece carve --yara-rules ./rules/`):
  Compiles `.yar`/`.yara` rules at carve time. Matches flagged inline in `CarvedFile.yara_matches`.
  YARA hits auto-escalate `forensic_priority` to `CRITICAL`.
- **92 carving signatures** (was 50):
  Added: VMDK/VHD/VHDX/QCOW2/VDI virtual disks, Prefetch/`$MFT`/INDX/USNJrnl Windows
  artifacts, Mach-O (macOS), MKV/FLV video, AIFF/APE audio, MBR/GPT partition structures,
  Windows Minidump, hiberfil.sys, MDB (Access), DER certificates, mbox, `.reg` exports,
  Zstandard, LZ4, lzip compression.
- **AES-256-GCM custody database encryption at rest**:
  `frece custody encrypt/decrypt` subcommands. Key derived via scrypt(N=2²⁰, r=8, p=1)
  — GPU brute-force resistant. Wrong passphrase rejected cleanly.
- **Progress bars** (`frece carve --progress`, `frece recover --progress`):
  tqdm bars show ETA, throughput (MB/s), and file count for long operations.

---

## v2.3.0 — Forensic Audit, Metadata Extraction & Confidence Scoring

### Sandbox-Verified Bug Fixes
- **SQLite over-carve**: `_get_sqlite_size` reads `page_size × page_count` from header.
  Was: 31 MB for a 12 KB database. Now: exact 12 KB.
- **PCAP over-carve**: `_walk_pcap_size` walks packet records and stops on null padding.
  Was: 262 KB for a 142-byte capture. Now: exact 142 bytes.
- **EML/text over-carve**: `_find_text_end` stops at 8-byte null run.
  Was: 30 MB for a 58-byte email. Now: exact 58 bytes.
- **MP3 false positives eliminated**: Requires consecutive valid MPEG frame headers with
  valid version/layer/bitrate/sample-rate fields. Was: hundreds of false hits from random
  data. Now: zero.
- **MAC times always zero**: `_parse_istat_mac_times` now handles NTFS labels
  (`File Modified`, `MFT Modified`), tab-separated values, and nanosecond-precision
  timestamps. Was: `mtime=0 atime=0` for all recovered files. Now: real timestamps.
- **Carve manifest inconsistency**: On-disk `carve_manifest.json` now contains
  `manifest_path` and `files_carved` fields matching the CLI JSON output.

### New Modules
- **`frece/metadata.py`** — Deep forensic metadata extraction for 12+ types:
  JPEG (EXIF GPS, camera make/model), PDF (author, title, version), PE (compile timestamp,
  architecture, DLL/EXE/SYS), ELF (ABI, type, build-ID), SQLite (tables, row counts,
  schema version), PCAP (packet count, unique IPs, protocols, timestamps), EML (From/To/
  Subject/Date/attachments), LNK (target path, drive type, volume serial), EVTX (record
  count, dirty/full flags), ZIP/DOCX/XLSX/PPTX (file list, Office author/title/dates), RTF.
- **`frece/scoring.py`** — Recovery confidence scoring (0–100, 5 grades):
  CONFIRMED (≥90), PROBABLE (≥75), POSSIBLE (≥50), SUSPECT (≥25), REJECTED (<25).
  Four scored dimensions: structural integrity, entropy plausibility, size plausibility,
  metadata presence.

### New CLI Commands
- `frece metadata <file|dir>` — extract deep forensic metadata
- `frece score <manifest>` — compute confidence scores with grade breakdown

### Improvements
- Every `CarvedFile` and `RecoveredFile` now carries `artifact_metadata`,
  `confidence_score`, `confidence_grade`, and `suggested_name`.
- `_suggest_filename()` generates meaningful names for orphan inodes:
  `email_Subject.eml`, `db_tablename.db`, `binary_x86_64.exe`, `capture_10.0.0.1.pcap`.

---

## v2.2.0 — New Commands, 50 Signatures, HTML Reports

### New Modules
- `frece/classifier.py` — Shannon entropy analysis, forensic category, priority triage
- `frece/timeline.py` — MAC-time timeline synthesis from all case artifacts

### New CLI Commands
- `frece scan --mactime` — full MAC-time body-file scan via `fls -m`
- `frece timeline` — chronological event synthesis (text/CSV/JSON)
- `frece search` — keyword/regex search across recovered evidence
- `frece entropy` — Shannon entropy with per-file encryption detection
- `frece classify` — forensic categorisation with CRITICAL/HIGH/MEDIUM/LOW triage
- `frece fsstat` — structured filesystem statistics
- `frece report --format html` — professional dark-theme HTML case report
- `frece report --format text` — bar-chart triage priorities

### Carving Improvements
- 50 signatures (was 20): PE, ELF, EVTX, LNK, PCAP/PCAPng, RAR, 7z, HEIC, WebP,
  OLE/MSG/DOC/XLS, RTF, XML, EML, FLAC, OGG, PSD, PHP, PEM, Registry hive.
- Entropy and forensic classification on every carved file.
- `--yara-rules` flag preparation.

### Recovery Improvements
- MAC timestamps (mtime/atime/ctime/crtime) on every recovered file via `istat`.
- Forensic classification per recovered file.

---

## v2.1.0 — Bug-Fix & Hardening Release

### Bugs Fixed (10 total)
- `config.py`: tilde not expanded in `case_root` from TOML
- `config.py`: `load_config()` created `~/.frece/cases` as side-effect on every call
- `sandbox.py`: path traversal (`..`) not blocked; null bytes allowed
- `acquisition.py`: `_acquire_single_file` read source file twice (hash pass + copy pass)
- `custody.py`: FRECE_KEY_STORE warning fired on every key operation
- `custody.py`: key rotation had a non-atomic crash window
- `carver.py`: ~190 lines of duplicated validation logic
- `partition.py`: empty error message on bare filesystem images
- `cli.py`: `handle_carve` had no structured logger
- `cli.py`: `handle_report` passed wrong `case_name` to `load_custody_db`

### New Tests
16 regression tests in `tests/test_bug_fixes.py`.

---

## v2.0.0 — Initial Public Release

Core forensic platform:
- Evidence acquisition with write-block checking
- Deleted file scanning (`frece scan`)
- File recovery via `fls` + `icat`
- File carving (20 signatures)
- Chain-of-custody HMAC database
- Partitions, hash, case management
- Structured JSON logging
