# Third-Party Licenses

FRECE depends on the following open-source components. All licenses are compatible
with commercial distribution when FRECE is distributed as a complete application.

## Runtime Dependencies

### yara-python
- License: Apache License 2.0
- URL: https://github.com/VirusTotal/yara-python
- Use: YARA rule scanning of carved artifacts
- Commercial use: ✅ Permitted

### tqdm
- License: Mozilla Public License 2.0 AND MIT License
- URL: https://github.com/tqdm/tqdm
- Use: Progress bar display
- Commercial use: ✅ Permitted

### cryptography
- License: Apache License 2.0 OR BSD 3-Clause License
- URL: https://cryptography.io
- Use: AES-256-GCM custody database encryption
- Commercial use: ✅ Permitted

### python-magic
- License: MIT License
- URL: https://github.com/ahupp/python-magic
- Use: File type detection
- Commercial use: ✅ Permitted

## System Dependencies (not bundled — must be installed separately)

### The Sleuth Kit (TSK)
- License: Common Public License 1.0 (CPL-1.0)
- URL: https://www.sleuthkit.org
- Use: Filesystem analysis (fls, icat, istat, mmls, fsstat)
- Note: TSK is invoked as an external tool via subprocess. FRECE does not
  link against or distribute TSK code. Users must install TSK independently.
- Commercial use: ✅ Permitted for use as an external tool

### libewf / ewf-tools
- License: LGPL v3+
- URL: https://github.com/libyal/libewf-legacy
- Use: EWF/E01 forensic image reading via ewfexport CLI
- Note: ewf-tools is invoked as an external tool. FRECE does not link against
  or distribute libewf code. Users must install ewf-tools independently.
- Commercial use: ✅ Permitted for use as an external tool

### libmagic
- License: BSD-2-Clause
- URL: https://www.darwinsys.com/file/
- Use: File type identification
- Commercial use: ✅ Permitted

## Summary

All runtime Python dependencies use Apache 2.0, MIT, MPL 2.0, or BSD licenses.
All system tools are invoked as external processes and are not bundled.
FRECE itself is proprietary software — All Rights Reserved, Copyright (c) 2025 Nakum-hub (see LICENSE file).
