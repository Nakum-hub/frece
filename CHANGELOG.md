# FRECE Changelog

## v2.1.0 — Bug-Fix & Hardening Release

### Bugs Fixed

**BUG-01 · `config.py` — Tilde not expanded in `case_root` from TOML**
When `case_root = "~/.frece/cases"` appeared in `config.toml`, the path was stored literally (`~/.frece/cases`) instead of resolving to the user's home directory. Added `.expanduser()` to the TOML parser.

**BUG-02 · `config.py` — `load_config()` created `~/.frece/cases` as a side-effect on every call**
Every invocation of `load_config()` — even for simple operations like `frece hash` that need no case directory — silently called `mkdir(parents=True)`. Removed the unconditional `mkdir`. Directory creation is now explicit via `config.ensure_case_root()` or `resolve_case_dir()`.

**BUG-03 · `sandbox.py` — Path traversal (`..`) not blocked**
`InputValidator.validate_path()` rejected shell-injection characters (`$`, `;`, etc.) but allowed `../` components, permitting paths like `/tmp/../etc/passwd` to pass validation. Added `..` component detection and null-byte rejection.

**BUG-04 · `acquisition.py` — `_acquire_single_file` read source file twice**
The original code performed two full sequential reads of the evidence source: once to compute the SHA-256 hash (for the output filename prefix), and again to copy the bytes to the destination. The refactored implementation hashes and copies in a single streaming pass. Output is written to a UUID-prefixed temporary file first, then renamed atomically once the hash is known, which also eliminates a parallel-acquisition filename collision bug.

**BUG-05 · `custody.py` — FRECE_KEY_STORE warning fired on every key operation**
The "FRECE_KEY_STORE not set" warning was printed to `stderr` on every call to `_key_path()`, meaning a single case operation could spam the terminal with identical warnings. Added a module-level `_key_store_warning_shown` flag so the warning fires at most once per process.

**BUG-06 · `custody.py` — Key rotation had a non-atomic crash window**
`rotate_case_secret_key()` first atomically replaced the database file (`os.replace(new_db_path, db_path)`) and then wrote the new key. A crash between those two operations left the new database on disk but pointing to the old key, making the entire case unverifiable. Fixed by writing the new key to a `.new` staging path first, then performing both `os.replace()` calls in sequence (DB → key). The `.new` suffix convention is documented for crash-recovery tooling.

**BUG-07 · `carver.py` — `_validate_file` and `_validate_output_file` were identical (~190 lines duplicated)**
Both methods implemented the same per-type validation logic (JPEG, PNG, BMP, PDF, GIF, TIFF, MP3, SQLite). The authoritative copy is now `_validate_output_file`, which reads only structurally-necessary prefix/suffix bytes from disk and streams for content-search types (PDF). `_validate_file` is a thin wrapper that writes bytes to a temp file and delegates, keeping the API stable for existing callers and tests.

**BUG-08 · `partition.py` — Empty error message when `mmls` fails on a bare filesystem image**
When `frece partitions` was run on a raw ext2/NTFS image without a partition table, `mmls` failed with empty stderr, resulting in the message `"mmls failed: "` with no useful guidance. The error now includes an explanation and remediation pointing users to `frece scan`/`frece recover` for raw filesystem images.

**BUG-09 · `cli.py` — `frece carve` had no structured logger**
`handle_carve()` constructed a `StreamingCarver` without setting up the `frece.carve` logger, meaning carving operations produced no audit trail. A `setup_logging()` call and a `CARVE_COMPLETE` structured event were added.

**BUG-10 · `cli.py` — `handle_report` loaded custody DB without `case_name`**
`load_custody_db(case_dir)` was called without passing `args.case_name`, causing `get_case_secret_key()` to fall back to `case_dir.name`. While equivalent in most deployments, it produced inconsistent key-lookup behaviour when `FRECE_KEY_STORE` was in use and the case directory name differed from the logical case name.

### New Tests (16 regression tests in `tests/test_bug_fixes.py`)
Every bug above is covered by a dedicated, deterministic regression test that will catch regressions in future patches.

### Version
`frece/__init__.py`, `pyproject.toml`: `2.0.0` → `2.1.0`
