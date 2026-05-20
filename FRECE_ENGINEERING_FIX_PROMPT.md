# FRECE v2.0 — Full Engineering Fix Prompt
## Senior Review Team: MIT/IIT Forensic Engineering Squad

**Status at intake:** `NOT DEPLOYABLE` — viable prototype, green test suite, but P0
evidence-destruction risk, broken legacy installer, no Linux E2E coverage, and
multiple forensic-correctness bugs. The goal of this document is to specify every
change needed to reach a `DEPLOYABLE` state, ordered by severity, with exact file
locations and precise instructions a developer can execute without ambiguity.

---

## Part 0 — Orientation: What the Tool Is and What It Must Become

FRECE is a Python 3.11+ CLI (`frece/`) that wraps The Sleuth Kit (`fls`, `icat`,
`istat`) for deleted-file recovery and provides its own signature-based carver,
evidence acquisition layer, and HMAC chain-of-custody database. The `pyproject.toml`
build and `frece.cli:main` entrypoint are the *only* supported paths. The stale
`frece.py` / `setup.py` / `install.sh` root files must be treated as toxic waste.

The tool must satisfy the following invariants before field deployment:

1. **Evidence integrity** — no write operation may touch the source device; outputs
   must be deterministic, fsync'd, and manifest-consistent.
2. **Correctness** — type filtering happens *before* writing artifacts to disk.
3. **Safety** — dangerous acquisition targets are rejected before any I/O.
4. **Custody security** — HMAC keys must never live next to the database they protect.
5. **Streaming** — no operation may buffer an entire disk image in RAM.
6. **Deployability** — one install path, reproducible packaging, CI-green.

---

## Part 1 — P0: Evidence-Destruction Risk (`acquisition.py` + `cli.py`)

### 1.1 Problem
`acquire_device()` at `acquisition.py:152` opens any output path for write without
checking whether:
- output == source (same path or same inode/device pair)
- output is a block device
- output path is a symlink pointing at the source

`validate_cli_args()` in `cli.py:98-99` only validates the character set of the
path strings — it never resolves them.

### 1.2 Required Fix — `frece/acquisition.py`

Add a new static method `_assert_safe_output_target(source: str, output: Path)`
and call it at the top of `acquire_device()` before any I/O:

```python
import os, stat

@staticmethod
def _assert_safe_output_target(source: str, output_path: Path) -> None:
    """Raise AcquisitionError for any dangerous source/output combination."""
    # 1. Resolve symlinks on both sides
    try:
        resolved_source = Path(source).resolve()
    except OSError:
        resolved_source = Path(source)
    try:
        resolved_output = output_path.resolve()
    except OSError:
        resolved_output = output_path

    # 2. Reject same-path
    if resolved_source == resolved_output:
        raise AcquisitionError(
            "Output path is the same file as the source",
            remediation="Choose a different output location.",
        )

    # 3. Reject same inode/device pair (catches hard-links across names)
    try:
        src_stat = os.stat(source)
        if resolved_output.exists():
            out_stat = os.stat(resolved_output)
            if (src_stat.st_ino == out_stat.st_ino and
                    src_stat.st_dev == out_stat.st_dev):
                raise AcquisitionError(
                    "Output is a hard-link alias of the source",
                    remediation="Choose a different output location.",
                )
    except OSError:
        pass

    # 4. Reject block-device outputs
    if resolved_output.exists() and stat.S_ISBLK(resolved_output.stat().st_mode):
        raise AcquisitionError(
            f"Output path {output_path} is a block device",
            remediation="Specify a regular file path for the output image.",
        )

    # 5. Reject if output's parent is on the same device as source (warn only)
    # (optional – log a prominent warning; do not hard-fail for file-to-file)
```

After the write loop completes, add `dst.flush(); os.fsync(dst.fileno())` before
closing the destination file.

Similarly, `hash_file()` must `fsync` its output JSON if writing to disk (handled
in `handle_hash` in `cli.py` — add `output.write_text(output_str)` followed by an
explicit `os.fsync` on the file descriptor, or use `output.open('w')` and fsync).

### 1.3 Required Fix — `frece/cli.py` `validate_cli_args`

Replace the character-only path validation for the `acquire` command with full
semantic validation:

```python
if args.command == "acquire":
    src_str = str(args.source)
    out_path = InputValidator.validate_path(str(args.output))
    # Resolve *before* storing so downstream code works with resolved paths
    args.source = src_str           # keep as string (may be /dev/sdX)
    args.output = out_path
    EvidenceAcquisition._assert_safe_output_target(src_str, out_path)
    return
```

---

## Part 2 — P0: Remove / Quarantine the Legacy Install Path

### 2.1 Files to delete or isolate
- `frece.py` (root-level interactive script — conflicts with package import)
- `setup.py` (points `frece` entrypoint to `frece:main` which does not exist in
  the package `__init__.py`)
- `install.sh` (line 235 downloads `foremost` over plain HTTP with no checksum;
  line 378 copies the stale `frece.py` not the package)

### 2.2 Action
```bash
git rm frece.py setup.py install.sh
git commit -m "chore: remove stale legacy install path (audit P0)"
```

If any of these files must be preserved for historical reference, move them to
`legacy/` with a `README.legacy.md` that states they are NOT supported and must
not be used.

---

## Part 3 — P1: Recovery Correctness — Filter Before Write (`recovery.py`)

### 3.1 Problem
In `recover_deleted()`, `_extract_inode()` writes each recovered file to disk at
`recovery.py:418` (`output_path.write_bytes(file_data)`). The `file_types` filter
loop runs **after** all inodes have been written, at `recovery.py:176`. Unwanted
artifacts therefore accumulate on the output partition and appear inconsistently in
the manifest (they are removed from the returned list but the files remain on disk).

### 3.2 Required Fix — `frece/recovery.py`

Pass `file_types` into `_extract_inode()` and apply the filter *before* writing:

```python
def _extract_inode(
    self,
    image_path: Path,
    inode: int,
    output_dir: Path,
    image_offset: int = 0,
    mapfile: Optional[list[tuple[int, int, str]]] = None,
    verify: bool = False,
    allowed_types: Optional[set[str]] = None,   # NEW PARAMETER
) -> Optional[RecoveredFile]:
    ...
    file_data = result.stdout
    file_type = self._detect_file_type(file_data)

    # --- FILTER BEFORE WRITE ---
    if allowed_types is not None and file_type.lower() not in allowed_types:
        self.logger.debug(
            json.dumps({"event": "TYPE_FILTERED", "inode": inode, "type": file_type})
        )
        return None   # do NOT write anything
    # ---------------------------

    output_path = self._output_path_for_inode(output_dir, inode, file_type)
    output_path.write_bytes(file_data)
    ...
```

In `recover_deleted()`, build `allowed_types` once and pass it down, removing the
post-loop filter entirely:

```python
allowed_types: Optional[set[str]] = None
if file_types is not None:
    file_type_aliases = {"jpg": "jpeg"}
    allowed_types = {
        file_type_aliases.get(ft.lower().lstrip("."), ft.lower().lstrip("."))
        for ft in file_types
    }

for inode in deleted_inodes:
    recovered = self._extract_inode(
        ...,
        allowed_types=allowed_types,
    )
```

Remove the post-loop filter block that currently starts at `recovery.py:176`.

### 3.3 Preserve Original Names from fls

`_output_path_for_inode()` currently produces `inode_<N>.<ext>`.
The fls line already contains the original filename. Thread it through:

- Add `original_name: Optional[str] = None` to `RecoveredFile`.
- In `_list_deleted_inodes`, switch to returning `list[ScannedEntry]` (it already
  has `.name`) instead of `list[int]`.
- Rename internal method to `_list_deleted_entries()` and refactor to avoid
  code duplication with `scan_deleted()` (both call `fls -r -d` identically).
- In `_extract_inode`, accept `original_name: Optional[str]` and use it for the
  output filename when available, falling back to `inode_<N>.<ext>`.

---

## Part 4 — P1: Chain-of-Custody Key Co-location (`custody.py`)

### 4.1 Problem
`.case_secret` lives at `<case_dir>/.case_secret` — the same directory as
`custody.db`. Anyone with write access to the case directory can replace both
the DB and the key, making HMAC verification meaningless.

### 4.2 Required Fix

Introduce an environment variable `FRECE_KEY_STORE` (path to a directory outside
the case dir — e.g., `/etc/frece/keys` or a USB-mounted path). If the variable is
set, keys are stored under `$FRECE_KEY_STORE/<case_name>.key`. If not set, fall
back to the current behaviour but emit a **loud WARNING** to stderr:

```python
import os, sys

KEY_STORE_ENV = "FRECE_KEY_STORE"

def _key_path(case_dir: Path, case_name: Optional[str] = None) -> Path:
    key_store = os.environ.get(KEY_STORE_ENV)
    if key_store:
        ks = Path(key_store)
        ks.mkdir(parents=True, exist_ok=True)
        name = case_name or case_dir.name
        return ks / f"{name}.key"
    # Fallback — warn operator
    print(
        f"WARNING: FRECE_KEY_STORE not set. HMAC key stored beside custody DB "
        f"at {case_dir}. Set FRECE_KEY_STORE to an independent secure path.",
        file=sys.stderr,
    )
    return case_dir / ".case_secret"
```

Update `get_case_secret_key()` and `create_case_secret_key()` to call `_key_path()`.
Update `handle_case` in `cli.py` to pass `case_name` through.

### 4.3 Key Rotation Support (P2 — schedule after P1)

Add `frece case rotate-key <case_name>` subcommand that:
1. Reads all existing entries from the DB.
2. Generates a new key.
3. Re-HMACs every row with the new key.
4. Atomically replaces the DB (write to `.new`, fsync, rename).
5. Writes the new key.

---

## Part 5 — P1: Stream `icat` Output to Disk (`recovery.py`)

### 5.1 Problem
`_extract_inode()` uses `capture_output=True` which buffers the entire icat stdout
in memory. For a 4 GB video inode this allocates 4 GB of RAM.

### 5.2 Required Fix

Pipe `icat` stdout directly to the output file:

```python
output_path = self._output_path_for_inode(output_dir, inode, "bin")
# Use a temp name then rename to avoid partial writes appearing as complete
tmp_path = output_path.with_suffix(".tmp")

sha256 = hashlib.sha256()
size = 0

with open(tmp_path, "wb") as out_f:
    proc = subprocess.Popen(
        command,
        stdout=out_f,         # direct to file — no memory buffer
        stderr=subprocess.PIPE,
        timeout=None,         # manage timeout externally if needed
    )
    # Stream-hash via a tee approach is not possible with Popen(stdout=file)
    # so re-read for hashing after write (two-pass, but bounded RAM)

returncode = proc.wait()
if returncode != 0:
    tmp_path.unlink(missing_ok=True)
    raise RecoveryError(...)

# Now detect type from header bytes only (first 4 KB — no full load)
with open(tmp_path, "rb") as f:
    header = f.read(4096)
file_type = self._detect_file_type(header)

# Apply type filter here (before the expensive hash pass)
if allowed_types is not None and file_type.lower() not in allowed_types:
    tmp_path.unlink()
    return None

# Hash by streaming — not full load
sha256 = hashlib.sha256()
size = 0
with open(tmp_path, "rb") as f:
    while chunk := f.read(1024 * 1024):
        sha256.update(chunk)
        size += len(chunk)

final_path = self._output_path_for_inode(output_dir, inode, file_type)
tmp_path.rename(final_path)
```

This limits RAM usage to the subprocess pipe buffer (a few KB) regardless of
inode size.

---

## Part 6 — P1: Stream fls / istat for Large Images (`recovery.py`)

### 6.1 Problem
`fls` with `capture_output=True` and `timeout=300` will OOM on a device with
hundreds of thousands of deleted files, and hard-timeout on slow media.

### 6.2 Required Fix — Streaming fls parser

```python
def _iter_fls_lines(
    self, image_path: Path, image_offset: int
) -> Generator[str, None, None]:
    """Yield fls output lines without buffering the full output."""
    command = ["fls", "-r", "-d"]
    if image_offset:
        command.extend(["-o", str(image_offset)])
    command.append(str(image_path))

    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    ) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line
        proc.wait()
        if proc.returncode != 0:
            err = proc.stderr.read().strip() if proc.stderr else ""
            raise RecoveryError(
                f"fls failed: {err}",
                remediation="Check image format and filesystem offset",
            )
```

Update `scan_deleted()` and `_list_deleted_entries()` to consume this generator
instead of buffering `result.stdout`.

Remove the 300-second hard timeout from all Sleuth Kit `subprocess.run` calls.
For long-running operations, expose a `--timeout` CLI flag (default 0 = unlimited)
and pass it to `Popen` via a `threading.Timer` that calls `proc.kill()`.

---

## Part 7 — P1: Carver Memory Safety (`carver.py`)

### 7.1 Problem A — `_extract_file()` loads whole files into RAM
`_extract_file()` calls `f.read(size)` at the end, loading the full carved artifact
into memory. For a 500 MB ZIP inside a large disk image this is 500 MB per artifact.

### 7.2 Required Fix — Chunked write for `_extract_file`

Return a file-like context manager instead of bytes. Write in 4 MB chunks:

```python
def _write_carved_file(
    self, source_path: Path, offset: int, size: int, output_file: Path
) -> tuple[str, int]:
    """Stream-copy <size> bytes from offset in source to output_file.
    Returns (sha256_hex, actual_bytes_written).
    """
    sha256 = hashlib.sha256()
    written = 0
    chunk_size = 4 * 1024 * 1024

    with open(source_path, "rb") as src, open(output_file, "wb") as dst:
        src.seek(offset)
        remaining = size
        while remaining > 0:
            to_read = min(chunk_size, remaining)
            chunk = src.read(to_read)
            if not chunk:
                break
            dst.write(chunk)
            sha256.update(chunk)
            written += len(chunk)
        dst.flush()
        os.fsync(dst.fileno())

    return sha256.hexdigest(), written
```

Remove `file_data, actual_size = self._extract_file(...)` from `carve()` and
replace with a call to `_write_carved_file()`.

### 7.3 Problem B — Triple-pass on source file
The current `carve()` loop does:
1. A full SHA256 hash pass (`_hash_file`).
2. A full chunk-scan pass for signatures.
3. Re-opens source for each `_extract_file` call.

### 7.4 Required Fix — Combine passes 1 and 2

Compute the source SHA256 *while* scanning for signatures:

```python
def _scan_and_hash(
    self, source_path: Path
) -> tuple[str, dict[int, list[str]]]:
    """Single pass: compute SHA256 and collect all signature positions."""
    sha256 = hashlib.sha256()
    found_sigs: dict[int, list[str]] = {}
    chunk_offset = 0
    previous_overlap = b""

    with open(source_path, "rb") as f:
        while True:
            chunk = f.read(self.chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            combined = previous_overlap + chunk
            abs_offset = chunk_offset - len(previous_overlap)
            for sig_offset, sig_type in SignatureDatabase.find_signatures(combined, abs_offset):
                found_sigs.setdefault(sig_offset, []).append(sig_type)
            chunk_offset += len(chunk)
            previous_overlap = chunk[-self.max_sig_len:]

    return sha256.hexdigest(), found_sigs
```

### 7.5 Problem C — Unbounded MP4 fallback size
`_get_mp4_size()` falls back to `source_size - offset` (the entire remaining image)
when no `mdat` box is found. For a false-positive MP4 signature near the start of a
10 GB image this carves 10 GB.

### 7.6 Required Fix
If `max_video_size > 0`, cap the fallback:
```python
fallback_size = source_size - offset
if self.max_video_size > 0:
    fallback_size = min(fallback_size, self.max_video_size)
```
Expose `max_video_size` in `Config` (already present) and wire it through the
`carve` CLI flag `--max-video-size`.

---

## Part 8 — P1: Sandbox Path Validator Rejects Legitimate Paths (`sandbox.py`)

### 8.1 Problem
`DANGEROUS_CHARS` includes `(` and `)`. Linux filenames and package paths
legitimately contain parentheses (e.g., `/mnt/evidence/file (copy).jpg`).
The validator silently rejects these but does NOT block actual dangerous paths like
`/dev/sda` as an acquisition output.

### 8.2 Required Fix

Remove `(` and `)` from `DANGEROUS_CHARS`. Add device-output rejection directly
in `_assert_safe_output_target()` (already designed in Part 1). The shell-injection
protection only matters for values interpolated into shell strings — FRECE never
uses `shell=True`, so `(` and `)` carry no risk in a list-based `subprocess.run`.

```python
# sandbox.py
DANGEROUS_CHARS = {"<", ">", "|", "&", ";", "`", "$", "{", "}"}
# Removed: "(", ")"
```

Add a unit test `test_sandbox.py::test_parentheses_in_path_allowed` to prevent
regression.

---

## Part 9 — P1: Partition Discovery & Filesystem Auto-Detection (NEW MODULE)

### 9.1 Gap
Operators must know byte offsets in advance. No MBR/GPT parsing exists.

### 9.2 Required New Module — `frece/partition.py`

```python
"""Partition table discovery using mmls (Sleuth Kit)."""

import subprocess, re
from dataclasses import dataclass
from pathlib import Path
from frece.errors import RecoveryError


@dataclass
class Partition:
    slot: str
    start_sector: int
    end_sector: int
    length_sectors: int
    description: str


def list_partitions(image_path: Path) -> list[Partition]:
    """Run mmls on image_path and return discovered partitions."""
    try:
        result = subprocess.run(
            ["mmls", str(image_path)],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as exc:
        raise RecoveryError(
            "Tool not found: mmls",
            remediation="Install The Sleuth Kit: apt-get install sleuthkit",
        ) from exc

    if result.returncode != 0:
        raise RecoveryError(
            f"mmls failed: {result.stderr.strip()}",
            remediation="Verify image path and format",
        )

    partitions = []
    for line in result.stdout.splitlines():
        # mmls output: "000:  Meta   0000000000   0000000000   0000000001   ..."
        m = re.match(
            r"^\s*(\d+):\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)",
            line,
        )
        if m:
            partitions.append(Partition(
                slot=m.group(1),
                start_sector=int(m.group(2)),
                end_sector=int(m.group(3)),
                length_sectors=int(m.group(4)),
                description=m.group(5).strip(),
            ))

    return partitions
```

### 9.3 CLI Integration

Add a `partitions` subcommand to `cli.py`:

```
frece partitions <image>
```

Output: JSON array of partition descriptors with `start_sector` so the operator
can pipe `start_sector` directly into `--offset` of `frece recover` or `frece scan`.

Add `mmls` to the `check_tools()` tool map.

---

## Part 10 — P1: Real Linux Acceptance Tests

### 10.1 Gap
All 109 tests mock subprocess calls. No test exercises a real `fls`/`icat` binary
against a real filesystem image.

### 10.2 Required: `tests/acceptance/` directory

Create `tests/acceptance/conftest.py`:

```python
import pytest, subprocess, shutil

TOOLS = ["fls", "icat", "istat", "mmls"]

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "acceptance: mark test as requiring installed Sleuth Kit tools"
    )

@pytest.fixture(scope="session")
def sleuthkit_available():
    missing = [t for t in TOOLS if shutil.which(t) is None]
    if missing:
        pytest.skip(f"Sleuth Kit tools not found: {missing}")
    return True

@pytest.fixture(scope="session")
def ext4_image(tmp_path_factory):
    """Create a minimal ext4 test image with a known deleted file."""
    img = tmp_path_factory.mktemp("images") / "test.ext4"
    subprocess.run(["dd", "if=/dev/zero", f"of={img}", "bs=1M", "count=10"], check=True)
    subprocess.run(["mkfs.ext4", "-F", img], check=True)
    mnt = tmp_path_factory.mktemp("mnt")
    subprocess.run(["mount", "-o", "loop", str(img), str(mnt)], check=True)
    (mnt / "hello.txt").write_text("hello world")
    subprocess.run(["rm", str(mnt / "hello.txt")], check=True)
    subprocess.run(["umount", str(mnt)], check=True)
    return img
```

Create `tests/acceptance/test_recovery_ext4.py`:

```python
import pytest
from frece.recovery import DeletedFileRecovery

@pytest.mark.acceptance
def test_recover_deleted_txt(sleuthkit_available, ext4_image, tmp_path):
    r = DeletedFileRecovery()
    files = r.recover_deleted(ext4_image, tmp_path)
    assert len(files) >= 1
    recovered_text = (tmp_path / files[0].output_path).read_text(errors="ignore")
    assert "hello world" in recovered_text
```

Create `tests/acceptance/test_carver_e2e.py` — create a binary file containing
an embedded JPEG, run `StreamingCarver.carve()`, assert the JPEG is extracted and
validates.

Add to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = ["acceptance: requires installed Sleuth Kit tools"]
```

Run unit tests with `pytest -m "not acceptance"` in CI and acceptance tests
separately on a provisioned Linux runner with `sleuthkit` installed.

---

## Part 11 — P2: Config Uniformity (`config.py` + `cli.py` + `acquisition.py`)

### 11.1 Problem
`acquisition.py` ignores `Config.chunk_size`; it hardcodes `chunk_size = 1024 * 1024`
in `acquire_device()` and `_acquire_single_file()`. The `carver` correctly reads
config, but `recovery.py` never loads config at all.

### 11.2 Required Fix

In `acquisition.py`:
- Inject `config: Config` via `__init__` (already takes `logger`).
- Use `self.config.chunk_size` for read/write loops.

In `recovery.py`:
- Add optional `config: Config = None` to `DeletedFileRecovery.__init__()`.
- Use `config.max_icat_timeout` (new config field) when present.

In `config.py`, add:
```python
max_icat_timeout: int = 0      # seconds; 0 = no timeout
max_fls_timeout: int = 0
```

In `cli.py` `handle_acquire()`:
```python
config = load_config()
acquisition = EvidenceAcquisition(setup_logging(name="frece.acquire"), config=config)
```

---

## Part 12 — P2: Manifest fsync + Silent-Failure Fix (`cli.py`)

### 12.1 Problem
At `cli.py:555` and `cli.py:561`, manifest parse failures in `handle_report()` are
silently swallowed with bare `except Exception: pass`.

### 12.2 Required Fix

```python
for manifest_path in sorted(case_dir.rglob("carve_manifest.json")):
    try:
        report["carve_manifests"].append(json.loads(manifest_path.read_text()))
    except Exception as exc:
        report.setdefault("manifest_errors", []).append(
            {"path": str(manifest_path), "error": str(exc)}
        )
```

### 12.3 fsync manifests

In `carver.py` after writing `carve_manifest.json`:

```python
with open(manifest_path, "w") as f:
    json.dump(manifest.to_dict(), f, indent=2)
    f.flush()
    os.fsync(f.fileno())
```

Same pattern in `recovery.py` `export_recovery_manifest()`.

---

## Part 13 — P2: Documentation + Test Count Sync

The following docs claim `83 passed, 2 skipped` / `85 tests` and must be updated to
reflect the current `109 passed, 1 skipped`:

- `README.md:85`
- `DEPLOYMENT.md:10`
- `IMPLEMENTATION_SUMMARY.md:10`
- `PHASES_CHECKLIST.md:47`

Add a CI step that runs `pytest -q` and pipes its summary line to a badge or
Makefile target so this count cannot silently drift again.

---

## Part 14 — P2: Packaging Cleanup

### 14.1 Add a GitHub Actions / GitLab CI workflow

`.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: pytest -q -m "not acceptance"
      - run: ruff check frece/
      - run: mypy frece/ --ignore-missing-imports
```

### 14.2 Add `python-magic` to `tool-status` check

In `cli.py` `check_tools()`, after the binary checks:

```python
try:
    import magic
    print(f"{'python-magic':20} OK")
except ImportError:
    print(f"{'python-magic':20} NOT FOUND - pip install python-magic")
    all_found = False
```

### 14.3 Lock `libmagic` version

`python-magic` requires the native `libmagic` shared library. Add installation
instructions to `DEPLOYMENT.md`:

```
apt-get install libmagic1        # Debian/Ubuntu
dnf install file-libs            # RHEL/Fedora
```

---

## Part 15 — Extended File Type Support Roadmap (P3)

These are not blocking deployment but are needed for full forensic coverage.

| Priority | Feature | Module | Notes |
|---|---|---|---|
| P3 | XFS support | `partition.py` + `recovery.py` | mmls detects XFS; fls supports it natively — test required |
| P3 | Btrfs support | Same as above | Sleuth Kit has partial Btrfs support in recent versions |
| P3 | exFAT / FAT32 explicit tests | `tests/acceptance/` | FAT images trivially created with `mkfs.vfat` |
| P3 | NTFS MFT orphan traversal | `recovery.py` (new method) | Use `fls -p` to include orphan entries |
| P3 | Journal-aware ext4 recovery | `recovery.py` | Use `extundelete` or `debugfs` for journal scan |
| P3 | Slack-space carving | `carver.py` | After primary recovery, carve unallocated clusters |
| P3 | Metadata reconstruction | `recovery.py` | Use `istat` to extract atime/mtime/ctime and store in manifest |
| P3 | Preview/triage UI | `cli.py` or web layer | `frece triage` command: hex dump + type + carved thumbnails |

---

## Part 16 — Complete Priority Summary

| ID | Severity | File(s) | Change Summary |
|---|---|---|---|
| F-01 | P0 | `acquisition.py`, `cli.py` | Add `_assert_safe_output_target`; fsync outputs |
| F-02 | P0 | `frece.py`, `setup.py`, `install.sh` | Delete legacy files |
| F-03 | P1 | `recovery.py` | Filter by type BEFORE write; streaming icat; streaming fls |
| F-04 | P1 | `custody.py`, `cli.py` | Externalize HMAC key via `FRECE_KEY_STORE` |
| F-05 | P1 | `recovery.py` | Preserve original filenames from fls |
| F-06 | P1 | `carver.py` | Chunked extraction; single-pass hash+scan; cap MP4 fallback |
| F-07 | P1 | `sandbox.py` | Remove `(` `)` from DANGEROUS_CHARS |
| F-08 | P1 | `frece/partition.py` (NEW) | mmls wrapper + `frece partitions` CLI command |
| F-09 | P1 | `tests/acceptance/` (NEW) | Real Sleuth Kit E2E tests on ext4/NTFS/FAT images |
| F-10 | P2 | `config.py`, `acquisition.py`, `recovery.py` | Uniform config injection |
| F-11 | P2 | `cli.py` | Surface manifest parse errors; fsync manifests |
| F-12 | P2 | All docs | Sync test counts; update deployment instructions |
| F-13 | P2 | `.github/workflows/ci.yml` (NEW) | CI pipeline; ruff; mypy; python-magic check |
| F-14 | P3 | `recovery.py`, `tests/acceptance/` | XFS, Btrfs, NTFS MFT orphan, journal, metadata |

---

## Part 17 — Verification Checklist (Definition of Done)

Before marking the tool deployable, every item below must be ✅:

- [ ] `pytest -q -m "not acceptance"` → `109 passed, 0 failed` (no new regressions)
- [ ] `pytest -q -m acceptance` on a Linux runner with `sleuthkit` → all pass
- [ ] `frece acquire /dev/zero --output /dev/null` → rejects with P0 error
- [ ] `frece acquire /tmp/img.dd --output /tmp/img.dd` → rejects same-file
- [ ] `frece recover test.ext4 --output /tmp/out --type jpg` → only JPEG files in output dir (no other files present)
- [ ] `frece acquire` with a 1 GB file stays under 100 MB RSS (streaming verified with `valgrind --tool=massif` or `memray`)
- [ ] `frece carve` on a 2 GB image stays under `chunk_size` + 20 MB RSS
- [ ] `FRECE_KEY_STORE=/tmp/keys frece case create test` → key written to `/tmp/keys/test.key`, not to case dir
- [ ] `frece partitions test.dd` → returns correct partition offsets matching `mmls` output
- [ ] `frece tool-status` checks `mmls` and `python-magic`
- [ ] `ruff check frece/` → 0 errors
- [ ] `mypy frece/ --ignore-missing-imports` → 0 errors on typed paths
- [ ] `frece --version` → `2.0.0`
- [ ] No `setup.py`, `frece.py`, or `install.sh` in repo root

---

## Appendix A — Quick File-by-File Change Index

| File | Parts |
|---|---|
| `frece/acquisition.py` | 1, 10, 11 |
| `frece/carver.py` | 7, 12 |
| `frece/cli.py` | 1, 8, 9, 11, 12, 13 |
| `frece/config.py` | 11 |
| `frece/custody.py` | 4 |
| `frece/errors.py` | (no change) |
| `frece/logging.py` | (no change) |
| `frece/parallel.py` | (no change) |
| `frece/recovery.py` | 3, 5, 6, 11, 12 |
| `frece/sandbox.py` | 8 |
| `frece/partition.py` | 9 (NEW) |
| `tests/acceptance/` | 10 (NEW directory) |
| `.github/workflows/ci.yml` | 14 (NEW) |
| `frece.py` | DELETE |
| `setup.py` | DELETE |
| `install.sh` | DELETE |
| `README.md`, `DEPLOYMENT.md`, `IMPLEMENTATION_SUMMARY.md`, `PHASES_CHECKLIST.md` | 13 |

---

*Prepared by the FRECE Senior Engineering Review Team — MIT/IIT Forensic Systems Division.*
*Document version: 1.0 — April 2026.*
