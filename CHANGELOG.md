# FRECE Changelog

All notable changes are documented here. Versions follow [semantic versioning](https://semver.org/).

---

## v1.0.0 — Initial Release

The first public release of **FRECE — Forensic Recovery and Evidence Carving
Engine**: a complete command-line digital-forensics platform for evidence
recovery, file carving, chain-of-custody, timeline analysis, and
threat-intelligence scanning.

### Installation
- **One-command installer** (`install.sh`): installs the external forensic tools
  (The Sleuth Kit, ewf-tools, libmagic, YARA) **and** the FRECE CLI in a single
  step. Uses `pipx` for an isolated install, so it works cleanly on
  externally-managed Python environments (Kali, Debian 12+, Ubuntu 23.04+) — no
  more `externally-managed-environment` (PEP 668) errors.

### Recovery & acquisition
- Evidence acquisition with write-block checking (`frece acquire`) and
  multi-algorithm hashing — SHA-256/SHA-512/MD5/BLAKE2b (`frece hash`).
- Deleted-file scanning via `fls` (`frece scan`, `--mactime` for full MAC-time
  body files), partition tables (`frece partitions`), and filesystem statistics
  (`frece fsstat`).
- File recovery through `fls` + `icat` with real MAC timestamps and orphan-inode
  filename suggestion (`frece recover`).

### Carving
- **88 carving signatures** across images, documents, Office formats, archives,
  audio, video, executables, Windows artifacts, databases, network captures,
  email, crypto material, and virtual-disk formats.
- Exact carved-file sizing (SQLite, PCAP, EML walk to true EOF) and structural
  validation for 46 types — designed for **zero false positives** on random data.
- Optional inline **YARA** threat scanning at carve time
  (`frece carve --yara-rules ./rules/`) and a live progress display
  (`--progress`) with ETA and throughput.

### Forensic analysis
- Deep metadata extraction for 12+ types — EXIF GPS, PE compile timestamps,
  ELF build-IDs, SQLite tables, PCAP IPs, EML headers, LNK targets, and more
  (`frece metadata`).
- 0–100 confidence scoring with five grades — CONFIRMED / PROBABLE / POSSIBLE /
  SUSPECT / REJECTED (`frece score`).
- Shannon-entropy / encryption detection (`frece entropy`), forensic
  categorisation and CRITICAL/HIGH triage (`frece classify`), keyword & regex
  search (`frece search`), and MAC-time timeline synthesis (`frece timeline`).

### Image format support
- Raw images (`.dd/.img/.bin/.raw`) natively; EnCase EWF (`.E01`/`.Ex01`), Smart
  EWF (`.S01`), and AFF via `ewf-tools`.

### Chain of custody & reporting
- Tamper-evident **HMAC-SHA256** custody log with key rotation
  (`frece case create/log/verify/rotate-key`).
- **AES-256-GCM** encryption of the custody database at rest, with scrypt key
  derivation (`frece custody encrypt/decrypt`).
- Reporting in JSON, human-readable text, dark-theme HTML, and court-admissible
  **DFXML** (`frece report`).

### License
- Released as **proprietary, all-rights-reserved** software. Use, copying,
  modification, and distribution require the prior written permission of the
  owner. See [`LICENSE`](LICENSE) for the full terms and
  [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) for dependency licenses.
