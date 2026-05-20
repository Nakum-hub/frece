# FRECE 2.0: Forensic Recovery and Evidence Collection Engine

Linux-first forensic CLI for evidence acquisition, file carving, deleted-file recovery, and custody verification.

## Scope

- Streaming carving for common binary formats, including OOXML ZIP disambiguation
- Deleted-file recovery through The Sleuth Kit (`fls`, `icat`, `istat`)
- Case-based custody logging with HMAC-SHA256 verification
- Write-block checks, subprocess hardening, and typed errors with remediation hints
- UTC ISO 8601 timestamps with `Z` suffix across manifests and custody entries

## Requirements

- Python 3.11+
- Linux
- The Sleuth Kit installed and on `PATH`
- `file` and `sha256sum` available on `PATH`
- `libmagic` / `python-magic`

## Installation

```bash
pip install -e .
```

Linux package prerequisites:

```bash
sudo apt-get install sleuthkit libmagic1 file coreutils
```

## Deployment Gate

Run these on the target Linux host before operational use:

```bash
frece --version
frece tool-status
```

`frece tool-status` must exit `0`. A non-zero result means the host is missing required forensic tooling.

## Usage

### Carve files from an image

```bash
frece carve /path/to/image.dd --output ./carved_files
```

### Recover deleted files

```bash
frece recover /path/to/image.dd --output ./recovered_files --verify-inodes
```

### Create and verify a case

```bash
frece case create "Case-2024-001"
frece case log "Case-2024-001" ACQUIRE --evidence-id EV001 --source /dev/sda1 --detail source_hash=abc123
frece case verify "Case-2024-001"
```

### Verify custody directly from a case directory

```bash
frece custody verify ~/.frece/cases/Case-2024-001 --evidence-id EV001 --source abc123
```

## Development

### Run the test suite

```bash
pytest -m "not acceptance" -q
make test-count
```

### Run code quality tools

```bash
black frece tests
ruff check frece tests
mypy frece
```

## Verified State

- Current unit-suite result: `118 passed, 1 skipped`
- CI snapshot command: `make test-count`
- Acceptance tests live under `tests/acceptance/` and run separately on a provisioned Linux host with Sleuth Kit installed
- `frece tool-status` correctly returns non-zero until required Linux tools are installed

## Core Modules

- `frece/carver.py` - streaming signature scanning, type disambiguation, carving manifests
- `frece/recovery.py` - deleted-file recovery, ddrescue map parsing, recovery manifests
- `frece/custody.py` - custody database, HMAC verification, per-case secret handling
- `frece/acquisition.py` - evidence acquisition and write-block checks
- `frece/sandbox.py` - input validation and subprocess execution guards
- `frece/parallel.py` - threaded hashing and signature-search dispatch
- `frece/cli.py` - command-line interface

## Operational Notes

- Carving writes artifacts together with validation status; operators must review validation failures before treating a carved item as evidence.
- Custody verification is HMAC-based and fails closed on tampered rows or source-hash mismatch.
- This repository is CLI-only. There is no frontend or web application in the current tree.

## License

GPL-3.0-or-later

## Authors

DFIR Team
