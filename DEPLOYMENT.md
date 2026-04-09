# FRECE 2.0 Deployment Guide

## Status

Validated codebase. Operational deployment is gated on a Linux host where `frece tool-status` exits `0`.

## What Was Verified Locally

- Test command: `py -3.13 -m pytest -q`
- Result: `83 passed, 2 skipped`
- Defined tests: `85`
- Core CLI commands implemented: `tool-status`, `carve`, `recover`, `acquire`, `custody verify`, `case create|log|verify`

## Prerequisites

- Python 3.11+
- Linux
- The Sleuth Kit installed and on `PATH`
- `file` and `sha256sum` available on `PATH`
- `libmagic1` available to `python-magic`

Example Ubuntu install:

```bash
sudo apt-get install sleuthkit libmagic1 file coreutils
```

## Installation

```bash
cd /path/to/frece
pip install -e .
```

## Required Acceptance Checks

Run these on the actual Linux deployment host:

```bash
frece --version
frece tool-status
pytest tests/ -q
```

Deployment should be blocked unless:

- `frece --version` succeeds
- `frece tool-status` exits `0`
- the local operator accepts the test result on the target environment

## Command Reference

### Carve files

```bash
frece carve /path/to/evidence.dd --output ./carved_files
```

Produces carved artifacts and `carve_manifest.json`.

### Recover deleted files

```bash
frece recover /path/to/evidence.dd --output ./recovered_files --verify-inodes
```

Produces recovered files and `recovery_manifest.json`.

### Acquire an image

```bash
frece acquire /dev/sda --output ./evidence.img
```

Use `--force-no-writeblock` only with explicit approval if hardware write-blocking is unavailable.

### Case workflow

```bash
frece case create "Case-2024-001"
frece case log "Case-2024-001" ACQUIRE --evidence-id EV001 --source /dev/sda1 --detail source_hash=abc123
frece case verify "Case-2024-001"
```

### Direct custody verification

```bash
frece custody verify ~/.frece/cases/Case-2024-001 --evidence-id EV001 --source abc123
```

## Project Structure

```text
frece/
  __init__.py
  acquisition.py
  carver.py
  cli.py
  config.py
  custody.py
  errors.py
  logging.py
  parallel.py
  recovery.py
  sandbox.py

tests/
  conftest.py
  test_acquisition.py
  test_carver.py
  test_custody.py
  test_integration.py
  test_parallel.py
  test_sandbox.py
```

## Feature Summary

### Carving

- Signature-based scanning with overlapping chunks
- ZIP to DOCX/XLSX/PPTX disambiguation
- RIFF to WAV/AVI disambiguation
- MP4/MOV extent scanning via atoms to `mdat`
- JPEG, PNG, PDF, MP3, and SQLite secondary validation

### Recovery

- Deleted inode enumeration with `fls`
- Extraction with `icat`
- Extent-aware bad-sector filtering with `istat` plus ddrescue mapfiles
- Recovery manifests and optional post-extraction hash verification

### Custody

- Per-case secret keys generated from `os.urandom(32)`
- HMAC-SHA256 verification of custody rows
- Source-hash verification for acquired evidence

### Security

- Input validation for CLI paths, case names, and key string arguments
- Dangerous subprocess tools blocked in the sandbox wrapper
- Linux write-block checks for common block-device naming schemes

## Known Deployment Gate

This repository was verified in the current development environment, not on a Linux evidence workstation with full forensic tooling installed. The final go/no-go decision must be made after the target host passes `frece tool-status`.

## Support Data To Capture For Incidents

Include the following with any issue report:

1. `python3 --version`
2. `frece --version`
3. `frece tool-status`
4. Full stderr or traceback
5. `uname -a`

## License

GPL-3.0-or-later

## Authors

DFIR Team
