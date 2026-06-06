# FRECE — Deployment Guide

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+) | Ubuntu 22.04 LTS |
| Python | 3.11 | 3.12 |
| RAM | 512 MB | 4 GB+ |
| Disk | 1 GB | 10 GB+ (for evidence storage) |
| CPU | 2 cores | 8 cores |

## Prerequisites

```bash
# The Sleuth Kit (fls, icat, istat, mmls, fsstat)
apt-get install -y sleuthkit

# EWF/E01 image support
apt-get install -y ewf-tools

# libmagic
apt-get install -y libmagic1

# YARA (optional — for threat-intelligence scanning)
apt-get install -y yara
```

## Installation

### From PyPI (recommended)
```bash
pip install frece
```

### From source
```bash
git clone https://github.com/Nakum-hub/frece.git
cd frece
pip install -e .
```

### Verify installation
```bash
frece tool-status
frece --version
```

## First Use

```bash
# Create a case and set secure key store
export FRECE_KEY_STORE=/secure/path/frece-keys

frece case create CASE-2025-001
frece hash /dev/sda --algorithms sha256,sha512
frece case log CASE-2025-001 ACQUIRE --evidence-id EV-001
```

## Security Configuration

### HMAC Key Store (required for production)
```bash
# Store keys on a separate encrypted volume
export FRECE_KEY_STORE=/encrypted/partition/frece-keys
```

### Encrypt custody database at rest
```bash
frece custody encrypt /path/to/case/dir --passphrase "strong-passphrase"
```

## Supported Evidence Formats

| Format | Extension | Notes |
|--------|-----------|-------|
| Raw disk image | .dd, .img, .bin, .raw | Direct support |
| EnCase EWF | .E01, .Ex01, .E01x | Via ewf-tools |
| Smart EWF | .S01 | Via ewf-tools |
| AFF | .aff, .afd, .afm | Via ewf-tools |

## Filesystem Support

| Filesystem | Name Recovery | MAC Times |
|-----------|--------------|-----------|
| NTFS | ✅ Full | ✅ |
| ext2/3/4 | ⚠️ Orphan fallback | ✅ |
| FAT32/exFAT | ✅ Partial | ✅ |

## Uninstall
```bash
pip uninstall frece
```
