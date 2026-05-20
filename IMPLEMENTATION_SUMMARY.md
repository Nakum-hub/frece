# FRECE 2.0 Implementation Summary

## Current Status

Validated codebase with implemented Linux CLI workflows for carving, recovery, acquisition, and custody verification.

## Verified Snapshot

- Current unit-suite result: `118 passed, 1 skipped`
- CI snapshot command: `make test-count`
- Acceptance suite added under `tests/acceptance/`

## Implemented Modules

- `frece/carver.py`
  - streaming signature scanning
  - OOXML ZIP disambiguation
  - RIFF disambiguation
  - MP4/MOV atom-based extent scanning
  - carving manifest output
- `frece/recovery.py`
  - streamed deleted-entry enumeration with `fls`
  - streamed extraction with `icat`
  - extent-aware ddrescue map filtering through `istat`
  - original deleted filenames preserved when safe
  - recovery manifest output
- `frece/custody.py`
  - per-case secrets from `os.urandom(32)`
  - externalized key storage via `FRECE_KEY_STORE`
  - case key rotation support
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
  - `scan`
  - `partitions`
  - `recover`
  - `acquire`
  - `custody verify`
  - `case create|log|verify|rotate-key`

## Important Behavioral Guarantees

- Typed exceptions are exposed for sandbox, acquisition, carve, recovery, custody, and validation failures.
- All manifests and custody entries use UTC ISO 8601 timestamps with `Z` suffix and fsync their on-disk JSON outputs.
- Carving preserves validation status per artifact instead of silently treating every carve as trusted evidence.
- Custody verification fails closed on tampered rows and source-hash mismatch.
- `frece tool-status` now acts as a real gate: missing tools produce a non-zero exit code and checks `mmls` plus `python-magic`.

## Deployment Position

The repository is closer to field deployment, but final operational deployment still requires a Linux host with the forensic toolchain installed plus a successful unit and acceptance run on that host.
