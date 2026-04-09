# FRECE 2.0 - Phases Checklist

## Phase 1: Carver Rebuild

- [x] Streaming chunked carving implemented
- [x] Chunk overlap uses configurable signature length
- [x] ZIP disambiguation resolves `docx`, `xlsx`, and `pptx`
- [x] RIFF disambiguation resolves `wav` and `avi`
- [x] EML false positives are rejected through RFC 2822-style header checks
- [x] MP4/MOV extent scanning follows atoms through `mdat`
- [x] JPEG, PNG, PDF, MP3, and SQLite secondary validation implemented
- [x] Carving writes `carve_manifest.json` with source hash and per-file metadata

## Phase 2: Deleted File Recovery

- [x] Deleted inodes listed through `fls`
- [x] Inodes extracted through `icat`
- [x] `icat` calls logged with return code and bytes written
- [x] Recovered files are named from detected type
- [x] `--verify-inodes` re-reads recovered files and checks hashes
- [x] ddrescue mapfiles are parsed with `-` as the bad-sector flag
- [x] Mapfile filtering is extent-aware through `istat` block-range parsing
- [x] `SECTOR_BAD` and `CUSTODY_WARNING` events are logged

## Phase 3: Chain of Custody

- [x] Custody rows are HMAC-SHA256 protected
- [x] Case secret keys are generated from `os.urandom(32)`
- [x] Case secret keys are persisted per case
- [x] `frece case verify` verifies a case database
- [x] `frece custody verify <case_dir>` verifies a custody database directly
- [x] Source-hash verification fails closed on mismatch
- [x] Read-only verification paths use SQLite read-only mode

## Phase 4: Security and Wiring

- [x] Dangerous subprocess tools are blocked by the sandbox wrapper
- [x] `run_tool()` emits correct short and long flags
- [x] CLI dispatch validates paths, case names, and key string arguments
- [x] Write-block detection handles common Linux block-device naming patterns
- [x] Parallel hashing uses threads for I/O-bound work
- [x] Parallel carving now matches the signature-finder API correctly

## Phase 5: Tests

- [x] Local verification command run: `py -3.13 -m pytest -q`
- [x] Current result: `83 passed, 2 skipped`
- [x] Defined tests: `85`
- [x] Test modules: `6`
- [x] Coverage includes CLI dispatch, custody verification, OOXML disambiguation, MP4 extent sizing, and PDF EOF carving

Per-module counts:

- [x] `tests/test_acquisition.py` - 14 tests
- [x] `tests/test_carver.py` - 11 tests
- [x] `tests/test_custody.py` - 14 tests
- [x] `tests/test_integration.py` - 14 tests
- [x] `tests/test_parallel.py` - 9 tests
- [x] `tests/test_sandbox.py` - 23 tests

## Phase 6: Packaging and Cleanup

- [x] Frontend and web files removed from the repository root
- [x] Duplicate extracted tree removed
- [x] Nested archive `frece/frece_(2).zip` removed
- [x] Canonical source tree is `frece/`
- [x] `pyproject.toml` provides the package and CLI entrypoint

## Final Verification

- [x] `frece` CLI implements the documented operational commands
- [x] Typed exception hierarchy is present for sandbox, acquisition, carve, recovery, custody, and validation failures
- [x] All timestamps remain UTC ISO 8601 with `Z` suffix
- [x] Documentation now matches the verified codebase and test state
- [ ] Target Linux host acceptance run with installed forensic tools still required before operational deployment
- [ ] `frece tool-status` must be verified on the target Linux host before field use

## Summary

- [x] Codebase cleaned to a single CLI application
- [x] Critical wiring defects fixed
- [x] Test suite green in the current verified environment
- [ ] Final deployment sign-off depends on Linux host validation, not on repository state alone
