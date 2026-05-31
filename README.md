# FRECE — Forensic Recovery and Evidence Carving Engine

> A professional, court-admissible CLI forensic toolkit for evidence recovery, file carving, chain-of-custody and timeline analysis.

[![Tests](https://img.shields.io/badge/tests-174%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![Version](https://img.shields.io/badge/version-2.2.0-orange)]()

---

## Overview

FRECE is a complete command-line digital forensics platform built on The Sleuth Kit. It performs non-destructive evidence acquisition, deleted-file recovery, binary file carving, chain-of-custody logging with HMAC integrity, forensic timeline synthesis, and entropy-based encryption detection — everything a field investigator or lab analyst needs in a single, auditable tool.

### Why FRECE?

| Feature | FRECE | Autopsy | Volatility | Foremost |
|---------|-------|---------|------------|---------|
| File carving (40+ types) | ✅ | ✅ | ❌ | ✅ |
| HMAC chain-of-custody | ✅ | ❌ | ❌ | ❌ |
| Entropy / encryption detection | ✅ | ❌ | ❌ | ❌ |
| Timeline synthesis | ✅ | ✅ | Partial | ❌ |
| Keyword search in artifacts | ✅ | ✅ | ❌ | ❌ |
| Forensic classification | ✅ | Partial | ❌ | ❌ |
| HTML + JSON + CSV output | ✅ | HTML | ❌ | ❌ |
| CLI-first / scriptable | ✅ | GUI | ✅ | ✅ |
| No GUI required | ✅ | ❌ | ✅ | ✅ |

---

## Installation

```bash
# Install The Sleuth Kit and libmagic
apt-get install -y sleuthkit libmagic1

# Install FRECE
pip install -e ".[dev]"
```

Verify:
```bash
frece tool-status
```

---

## Commands

```
frece tool-status           Check all required tools
frece acquire               Acquire evidence from device/file
frece hash                  Hash evidence for chain-of-custody
frece scan                  List deleted files (no extraction)
frece scan --mactime        List with MAC timestamps
frece recover               Extract deleted files with icat
frece carve                 File carving (40+ types + entropy)
frece partitions            List partition table
frece fsstat                Filesystem metadata and statistics
frece classify              Categorise files by forensic type
frece entropy               Shannon entropy analysis
frece search                Keyword/regex search in artifacts
frece timeline              MAC-time forensic timeline
frece case create/log/verify/rotate-key   Case management
frece custody verify        Verify chain-of-custody integrity
frece report                HTML/text/JSON case report
```

---

## Walkthrough

### 1 — Create a case and acquire evidence
```bash
export FRECE_KEY_STORE=/secure/keystore/path

frece case create CASE-2025-001
frece hash /dev/sda --algorithms sha256,sha512,md5

frece case log CASE-2025-001 ACQUIRE \
  --evidence-id EV-001 \
  --detail source=/dev/sda \
  --detail sha256=$(frece hash /dev/sda 2>/dev/null | jq -r .sha256)
```

### 2 — Scan for deleted files
```bash
# Standard scan (fast)
frece scan evidence.dd --output scan.json

# With MAC timestamps (NTFS preserves names; ext2/4 may show OrphanFile-N)
frece scan evidence.dd --mactime --output scan_mactime.json
```

### 3 — Recover deleted files
```bash
frece recover evidence.dd \
  --output ./recovered \
  --type jpg,pdf,docx,sqlite
```

### 4 — Carve files from raw image
```bash
frece carve evidence.dd --output ./carved
# Supports: JPEG, PNG, GIF, BMP, TIFF, PSD, WebP, HEIC,
#           PDF, RTF, XML, HTML, DOC, XLS, PPT, MSG, OLE,
#           ZIP, 7z, RAR, GZ, BZ2, XZ,
#           MP3, WAV, FLAC, OGG, MP4, MOV, AVI,
#           PE (EXE/DLL), ELF, script, PHP, PEM,
#           EVTX, LNK, Registry hive,
#           SQLite, PCAP, PCAPng, EML
```

### 5 — Entropy and encryption detection
```bash
# Flag files that may be encrypted (entropy > 7.0)
frece entropy ./carved --threshold 7.0 --output entropy.json

# Forensic classification with priority triage
frece classify ./recovered --priority HIGH
```

### 6 — Keyword search in artifacts
```bash
frece search ./recovered --keyword "password" --output hits.json
frece search ./recovered --keyword "\d{3}-\d{2}-\d{4}" --regex  # SSN pattern
```

### 7 — Build forensic timeline
```bash
frece timeline CASE-2025-001 --format text
frece timeline CASE-2025-001 --format csv --output timeline.csv
```

### 8 — Generate case report
```bash
# HTML report (recommended for presentation)
frece report CASE-2025-001 --format html --output report.html

# Text summary
frece report CASE-2025-001 --format text

# Full structured JSON
frece report CASE-2025-001 --format json --output report.json
```

---

## Carving — Supported File Types (v2.2.0)

| Category | Types |
|----------|-------|
| Images | JPEG, PNG, GIF, BMP, TIFF, PSD, WebP, HEIC/HEIF |
| Documents | PDF, RTF, XML, HTML |
| Office | DOC, XLS, PPT, DOCX, XLSX, PPTX, MSG (OLE compound) |
| Archives | ZIP, 7z, RAR 4.x/5.x, GZ, BZ2, XZ |
| Audio | MP3, WAV, FLAC, OGG |
| Video | MP4, MOV, AVI (via RIFF) |
| Executables | PE (EXE/DLL/SYS), ELF, scripts (Python/Bash/PHP/Perl/Ruby) |
| Windows artifacts | EVTX (Event Log), LNK (Shell Link), Registry hive |
| Databases | SQLite |
| Network | PCAP, PCAPng |
| Email | EML (RFC-822) |
| Crypto | PEM certificates/keys |

---

## Chain of Custody

FRECE uses HMAC-SHA256 to create a tamper-evident audit log for every case:

```bash
# All events are HMAC-signed; tampering is detected immediately
frece case verify CASE-2025-001

# Store keys securely away from case data
export FRECE_KEY_STORE=/encrypted/partition/frece-keys
```

---

## Forensic Classification

Every recovered or carved file is automatically classified:

- **Category**: `document`, `image`, `video`, `audio`, `archive`, `executable`, `database`, `network`, `email`, `system`, `crypto`
- **Priority**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (based on forensic relevance)
- **Entropy**: Shannon entropy (0–8 bits/byte); ≥7.5 flagged as possibly encrypted
- **Encryption flag**: Files with high entropy and unknown type are marked `possibly_encrypted`

---

## Architecture

```
frece/
├── cli.py          — CLI entrypoint (15 commands)
├── acquisition.py  — Evidence acquisition with progress
├── carver.py       — Streaming file carver (40+ types)
├── classifier.py   — Entropy + forensic categorisation
├── custody.py      — HMAC chain-of-custody DB
├── recovery.py     — Deleted file recovery (fls + icat)
├── timeline.py     — MAC-time forensic timeline
├── partition.py    — Partition table analysis
├── config.py       — Configuration loading
├── sandbox.py      — Input validation + path safety
├── logging.py      — Structured JSON audit logging
└── errors.py       — Typed error hierarchy
```

---

## Supported Filesystems

| Filesystem | Name recovery on delete | MAC timestamps | Notes |
|-----------|------------------------|----------------|-------|
| NTFS | ✅ Full | ✅ | Best recovery |
| ext4 | Partial (journal) | ✅ | Names often lost post-delete |
| ext2/3 | ❌ (dir entry zeroed) | ✅ | Use `frece carve` as complement |
| FAT32 | ✅ (partial) | ✅ | Via TSK |
| exFAT | ✅ (partial) | ✅ | Via TSK |

---

## Requirements

- Python 3.11+
- The Sleuth Kit (`fls`, `icat`, `istat`, `mmls`, `fsstat`, `ils`)
- `libmagic` / python-magic
- GNU coreutils (`sha256sum`)

---

## License

Proprietary. All rights reserved. Contact for commercial licensing.

