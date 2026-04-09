# FRECE 2.0 Implementation Summary

## Current Status

Validated codebase with implemented Linux CLI workflows for carving, recovery, acquisition, and custody verification.

## Verified Snapshot

- Verification command: `py -3.13 -m pytest -q`
- Result: `83 passed, 2 skipped`
- Defined tests: `85`
- Test modules: `6`

## Implemented Modules

- `frece/carver.py`
  - streaming signature scanning
  - OOXML ZIP disambiguation
  - RIFF disambiguation
  - MP4/MOV atom-based extent scanning
  - carving manifest output
- `frece/recovery.py`
  - deleted inode enumeration with `fls`
  - extraction with `icat`
  - extent-aware ddrescue map filtering through `istat`
  - recovery manifest output
- `frece/custody.py`
  - per-case secrets from `os.urandom(32)`
  - HMAC-SHA256 custody verification
  - SQLite read-only verification paths
- `frece/acquisition.py`
  - evidence acquisition with concurrent hashing
  - Linux write-block checks
- `frece/sandbox.py`
  - input validation
  - guarded subprocess execution
- `frece/parallel.py`
  - threaded hashing
  - corrected signature-finder dispatch for carving
- `frece/cli.py`
  - `tool-status`
  - `carve`
  - `recover`
  - `acquire`
  - `custody verify`
  - `case create|log|verify`

## Test Inventory

- `tests/test_acquisition.py` - 14 tests
- `tests/test_carver.py` - 11 tests
- `tests/test_custody.py` - 14 tests
- `tests/test_integration.py` - 14 tests
- `tests/test_parallel.py` - 9 tests
- `tests/test_sandbox.py` - 23 tests

## Important Behavioral Guarantees

- Typed exceptions are exposed for sandbox, acquisition, carve, recovery, custody, and validation failures.
- All manifests and custody entries use UTC ISO 8601 timestamps with `Z` suffix.
- Carving preserves validation status per artifact instead of silently treating every carve as trusted evidence.
- Custody verification fails closed on tampered rows and source-hash mismatch.
- `frece tool-status` now acts as a real gate: missing tools produce a non-zero exit code.

## Deployment Position

The repository is now internally consistent and the local suite is green. Final operational deployment still requires a Linux host with the forensic toolchain installed and a successful `frece tool-status` run on that host.
