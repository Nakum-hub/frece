# FRECE — Forensic Recovery and Evidence Carving Engine

> Production-grade CLI forensic platform for evidence recovery, file carving,
> chain-of-custody, timeline analysis, and threat-intelligence scanning.

[![CI](https://github.com/Nakum-hub/frece/actions/workflows/ci.yml/badge.svg)](https://github.com/Nakum-hub/frece/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.5.0-orange)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-226%20passing-brightgreen)](tests/)

---

## What is FRECE?

FRECE is a complete command-line digital forensics platform that helps investigators,
incident-response teams, and forensic laboratories:

- **Recover** deleted files from NTFS, ext2/3/4, FAT32 disk images
- **Carve** 88 file types from raw/unallocated binary data
- **Extract** deep forensic metadata (EXIF GPS, PE timestamps, SQLite tables, PCAP IPs)
- **Score** every artifact with a 0–100 confidence grade (CONFIRMED / PROBABLE / POSSIBLE)
- **Detect** encrypted and high-entropy files automatically
- **Scan** with YARA rules for threat intelligence inline at carve time
- **Build** MAC-time forensic timelines from all case artifacts
- **Generate** court-admissible DFXML reports and HTML case summaries
- **Protect** chain-of-custody with HMAC-signed databases and AES-256-GCM encryption

---

## Why FRECE?

| Capability | PhotoRec | Foremost | Scalpel | **FRECE** |
|---|:---:|:---:|:---:|:---:|
| File carving (88 types) | ✅ | ✅ | ✅ | ✅ |
| Exact carved-file size | ⚠️ | ❌ | ❌ | ✅ |
| Structural validation per type | ❌ | ❌ | ❌ | ✅ 46 types |
| Confidence scoring (0–100) | ❌ | ❌ | ❌ | ✅ |
| Deep metadata extraction | ❌ | ❌ | ❌ | ✅ 12 types |
| YARA rule scanning at carve time | ❌ | ❌ | ❌ | ✅ |
| E01/EWF image format support | ❌ | ❌ | ❌ | ✅ |
| DFXML court-admissible output | ❌ | ❌ | ❌ | ✅ |
| HMAC chain-of-custody | ❌ | ❌ | ❌ | ✅ |
| AES-256-GCM DB encryption | ❌ | ❌ | ❌ | ✅ |
| MAC-time timeline synthesis | ❌ | ❌ | ❌ | ✅ |
| Entropy / encryption detection | ❌ | ❌ | ❌ | ✅ |
| Orphan filename suggestion | ❌ | ❌ | ❌ | ✅ |
| Forensic triage priority | ❌ | ❌ | ❌ | ✅ |
| JSON / CSV / HTML / DFXML output | ❌ | ❌ | ❌ | ✅ |

---

## Installation

### Prerequisites

```bash
# The Sleuth Kit — required for filesystem-based recovery
sudo apt-get install -y sleuthkit

# EWF/E01 image format support
sudo apt-get install -y ewf-tools

# libmagic — file type detection
sudo apt-get install -y libmagic1

# YARA — optional, for threat-intelligence scanning
sudo apt-get install -y yara
```

### Install FRECE

```bash
pip install frece
```

### From source

```bash
git clone https://github.com/Nakum-hub/frece.git
cd frece
pip install -e .
```

### Verify

```bash
frece --version        # 2.5.0
frece tool-status      # checks all required external tools
```

---

## Quick Start

```bash
# Set up secure key storage (recommended)
export FRECE_KEY_STORE=/secure/partition/frece-keys

# Create a case
frece case create CASE-2025-001

# Hash the evidence before any operation
frece hash /dev/sda --algorithms sha256,sha512
# or for E01 images:
frece hash evidence.E01 --algorithms sha256

# Log the acquisition
frece case log CASE-2025-001 ACQUIRE \
    --evidence-id EV-001 \
    --detail "source=/dev/sda" \
    --operator "j.smith"

# Scan for deleted files
frece scan evidence.dd

# Recover deleted files
frece recover evidence.dd --output ./recovered

# Carve from raw/unallocated space
frece carve evidence.dd --output ./carved

# Carve with YARA threat scanning
frece carve evidence.dd --output ./carved --yara-rules ./rules/

# Extract deep metadata from artifacts
frece metadata ./carved

# Score all carved artifacts (0-100 confidence)
frece score ./carved/carve_manifest.json

# Build a MAC-time forensic timeline
frece timeline CASE-2025-001 --format text

# Search recovered evidence
frece search ./recovered --keyword "password"
frece search ./recovered --keyword "\d{3}-\d{2}-\d{4}" --regex  # SSN

# Detect encrypted files
frece entropy ./carved --threshold 7.0

# Classify by forensic category
frece classify ./recovered --priority HIGH

# Generate HTML report
frece report CASE-2025-001 --format html --output report.html

# Generate court-admissible DFXML
frece report CASE-2025-001 --format dfxml --output report.dfxml

# Encrypt custody database at rest (enterprise)
frece custody encrypt /path/to/CASE-2025-001 --passphrase "your-passphrase"

# Verify chain of custody
frece case verify CASE-2025-001
```

---

## All Commands

```
frece tool-status                   Check all required tools
frece --version                     Show version

Evidence Acquisition:
  frece acquire <source> --output   Acquire evidence with write-block check
  frece hash <file>                 Compute SHA-256/SHA-512/MD5/BLAKE2b

Case Management:
  frece case create <name>          Create a new investigation case
  frece case log <name> <event>     Log a custody event (ACQUIRE, EXAMINE, …)
  frece case verify <name>          Verify HMAC chain-of-custody integrity
  frece case rotate-key <name>      Rotate HMAC secret key
  frece custody verify <dir>        Verify a case directory
  frece custody encrypt <dir>       AES-256-GCM encrypt custody.db at rest
  frece custody decrypt <file>      Decrypt a custody.db.enc file

File System Analysis:
  frece scan <image>                List deleted files (fls-based)
  frece scan <image> --mactime      List with MAC timestamps
  frece partitions <image>          Show partition table (mmls)
  frece fsstat <image>              Filesystem metadata and statistics

Recovery & Carving:
  frece recover <image>             Recover deleted files with icat
  frece carve <image>               Carve 88 file types from raw/unallocated
  frece carve <image> --yara-rules  Carve with inline YARA threat scanning
  frece carve <image> --progress    Show real-time ETA + throughput

Forensic Analysis:
  frece metadata <file|dir>         Deep metadata (EXIF GPS, PE ts, SQLite tables…)
  frece score <manifest>            0-100 confidence scores with grade breakdown
  frece entropy <file|dir>          Shannon entropy + encryption detection
  frece classify <dir>              Forensic category + CRITICAL/HIGH triage
  frece search <dir> --keyword      Keyword / regex search in artifacts
  frece timeline <case>             MAC-time forensic timeline (text/CSV/JSON)

Reporting:
  frece report <case> --format json    Full JSON case report
  frece report <case> --format text    Human-readable text with bar charts
  frece report <case> --format html    Dark-theme HTML for presentation
  frece report <case> --format dfxml   Court-admissible DFXML XML
```

---

## Carving — Supported File Types (v2.5.0, 88 signatures)

| Category | Types |
|---|---|
| Images | JPEG, PNG, GIF, BMP, TIFF, PSD, WebP, HEIC/HEIF |
| Documents | PDF, RTF, XML, HTML |
| Office | DOCX, XLSX, PPTX, DOC, XLS, PPT, MSG (OLE compound) |
| Archives | ZIP, 7z, RAR 4.x/5.x, GZ, BZ2, XZ, Zstandard, LZ4 |
| Audio | MP3, WAV, FLAC, OGG, AIFF, APE, AMR |
| Video | MP4, MOV, AVI, MKV/WebM, FLV |
| Executables | PE (EXE/DLL/SYS), ELF, Mach-O (macOS), scripts |
| Windows artifacts | EVTX, LNK, Registry hive, Prefetch, $MFT, $INDEX |
| Databases | SQLite, MDB (Access) |
| Network | PCAP, PCAPng |
| Email | EML, mbox |
| Crypto | PEM certificates/keys, Bitcoin wallet hints |
| Virtual disks | VMDK, VHD, VHDX, QCOW2, VDI |
| Mobile/Apple | HEIC, binary plist, Mach-O fat binary |
| System | Windows Minidump, hiberfil.sys, DER certificates |

---

## Forensic Metadata Extraction (`frece metadata`)

| File Type | Extracted Fields |
|---|---|
| JPEG | EXIF GPS (latitude/longitude/altitude), camera make/model, datetime original |
| PNG | Width, height, bit depth, `tEXt` author/timestamp/GPS, DPI |
| PDF | Author, title, creator, version, creation date, encryption flag |
| PE | Compile timestamp, architecture (x86/x64/ARM64), EXE/DLL/SYS, subsystem |
| ELF | Architecture, ABI, type (executable/shared/core), build-ID |
| SQLite | Table names, row counts, column names, schema version, page size |
| PCAP | Packet count, unique src/dst IPs, protocols (TCP/UDP/ICMP), timestamps |
| EML | From, To, CC, Subject, Date, Message-ID, attachment names |
| LNK | Target path, drive type, volume serial, creation/access/write times |
| EVTX | Record count estimate, dirty/full flags |
| ZIP/DOCX/XLSX/PPTX | File listing, Office author/title/creation date |
| RTF | Author, company, creation date |

---

## Confidence Scoring (`frece score`)

Every carved and recovered artifact receives a 0–100 confidence score:

| Grade | Range | Meaning |
|---|---|---|
| **CONFIRMED** | 90–100 | Court-presentable, all checks passed |
| **PROBABLE** | 75–89 | Strong evidence, minor anomalies |
| **POSSIBLE** | 50–74 | Partial evidence, manual review recommended |
| **SUSPECT** | 25–49 | Structural issues, low reliability |
| **REJECTED** | 0–24 | Likely false positive, do not present |

Four scored dimensions: structural integrity (header/footer), entropy plausibility,
size plausibility, and metadata presence.

---

## Supported Image Formats

| Format | Extension | Support |
|---|---|---|
| Raw disk image | `.dd`, `.img`, `.bin`, `.raw` | Native |
| EnCase EWF | `.E01`, `.Ex01`, `.E01x` | Via ewf-tools |
| Smart/Solo EWF | `.S01` | Via ewf-tools |
| AFF | `.aff`, `.afd`, `.afm` | Via ewf-tools |

---

## Chain of Custody

FRECE uses HMAC-SHA256 to create a tamper-evident audit log:

```bash
# Verify integrity at any time
frece case verify CASE-2025-001

# Encrypt the custody database at rest (enterprise compliance)
export FRECE_KEY_STORE=/encrypted/partition/frece-keys
frece custody encrypt /path/to/case --passphrase "strong-passphrase"
```

DFXML output embeds all custody information in a court-accepted XML format.

---

## Filesystem Behaviour

| Filesystem | Name Recovery on Delete | MAC Timestamps | Notes |
|---|:---:|:---:|---|
| NTFS | ✅ Full | ✅ | Best recovery — `$MFT` entry preserved |
| ext2/3 (no journal) | ✅ Partial | ✅ | Directory entries sometimes survive |
| ext4 (with journal) | ⚠️ Orphan | ✅ | Journal zeroes inode block pointers; use `frece carve` for content |
| FAT32/exFAT | ✅ Partial | ✅ | Via The Sleuth Kit |

---

## Requirements

- Python 3.11+
- The Sleuth Kit (`fls`, `icat`, `istat`, `mmls`, `fsstat`)
- `libmagic` / `python-magic`
- GNU coreutils (`sha256sum`)
- Optional: `ewf-tools` for E01/EWF images
- Optional: `yara` for threat-intelligence scanning

---

## License

MIT License — see [LICENSE](LICENSE)

Third-party dependency licenses: see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.
