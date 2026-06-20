# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
"""Deep forensic metadata extraction.

Extracts structured, court-admissible metadata from recovered and carved
artifacts — far beyond simple MIME type detection.

Supported types and what is extracted:
  jpeg   : EXIF GPS coordinates, camera make/model, datetime original
  pdf    : Author, Title, Creator, Producer, creation/modification dates
  pe     : Compile timestamp, architecture (x86/x64), subsystem, type (EXE/DLL/SYS)
  elf    : Architecture, ABI, entry point, type (executable/shared/core)
  sqlite : Table names, row counts, schema version, page size
  pcap   : Total packets, unique source IPs, unique destination IPs, protocols
  eml    : From, To, CC, Subject, Date, Message-ID, attachment names
  lnk    : Target path, drive type, volume serial, creation/access/write times
  evtx   : Event count hint (header-based), computer name, first/last chunk
  zip    : File listing with names, sizes and compression methods
  rtf    : Author name (from RTF info group)
"""

from __future__ import annotations

import struct
import re
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class MetadataError(Exception):
    """Raised when metadata extraction fails for a specific type."""


def extract(file_path: Path, file_type: str) -> dict[str, Any]:
    """Extract forensic metadata from *file_path*.

    Args:
        file_path: Path to the carved / recovered artifact on disk.
        file_type: Canonical FRECE type string (e.g. 'jpeg', 'pe', …).

    Returns:
        Dictionary of extracted fields.  Never raises — errors are captured
        under the key ``extraction_error``.
    """
    extractors: dict[str, Any] = {
        "jpeg": _jpeg,
        "jpg": _jpeg,
        "png": _png,
        "pdf": _pdf,
        "pe": _pe,
        "elf": _elf,
        "sqlite": _sqlite,
        "pcap": _pcap,
        "eml": _eml,
        "lnk": _lnk,
        "evtx": _evtx,
        "zip": _zip,
        "docx": _zip,
        "xlsx": _zip,
        "pptx": _zip,
        "rtf": _rtf,
    }

    fn = extractors.get(file_type.lower())
    result: dict[str, Any] = {"file_type": file_type, "file_path": str(file_path)}

    if fn is None:
        result["extraction_error"] = f"No extractor for type '{file_type}'"
        return result

    try:
        result.update(fn(file_path))
    except Exception as exc:  # noqa: BLE001
        result["extraction_error"] = str(exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# JPEG / EXIF
# ─────────────────────────────────────────────────────────────────────────────

def _jpeg(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {}

    # Walk APP markers
    pos = 2  # skip SOI
    while pos + 4 < len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9):
            pos += 2
            continue
        if pos + 4 > len(data):
            break
        seg_len = struct.unpack_from(">H", data, pos + 2)[0]
        seg_data = data[pos + 4: pos + 2 + seg_len]

        if marker == 0xE1 and seg_data[:6] == b"Exif\x00\x00":
            result.update(_parse_exif(seg_data[6:]))

        if marker == 0xC0 and len(seg_data) >= 5:
            result["image_height"] = struct.unpack_from(">H", seg_data, 1)[0]
            result["image_width"] = struct.unpack_from(">H", seg_data, 3)[0]

        pos += 2 + seg_len

    return result


def _parse_exif(tiff: bytes) -> dict[str, Any]:
    if len(tiff) < 8:
        return {}

    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return {}

    result: dict[str, Any] = {}
    ifd_offset = struct.unpack_from(f"{endian}I", tiff, 4)[0]

    tags = _read_ifd(tiff, ifd_offset, endian)

    # Tag IDs we care about
    tag_map = {
        0x010F: "camera_make",
        0x0110: "camera_model",
        0x0132: "datetime_modified",
        0x013B: "artist",
        0x8769: "_exif_ifd_offset",   # ExifIFD pointer
        0x8825: "_gps_ifd_offset",    # GPS IFD pointer
        0x9003: "datetime_original",
        0x9004: "datetime_digitized",
        0xA430: "camera_owner",
    }

    for tag_id, value in tags.items():
        name = tag_map.get(tag_id)
        if name and name.startswith("_"):
            continue
        if name:
            result[name] = value

    # ExifIFD
    if 0x8769 in tags:
        exif_tags = _read_ifd(tiff, tags[0x8769], endian)
        for tag_id, value in exif_tags.items():
            name = tag_map.get(tag_id)
            if name:
                result[name] = value

    # GPS IFD
    if 0x8825 in tags:
        gps_tags = _read_ifd(tiff, tags[0x8825], endian)
        lat = _gps_coord(gps_tags.get(2), gps_tags.get(1))
        lon = _gps_coord(gps_tags.get(4), gps_tags.get(3))
        if lat is not None:
            result["gps_latitude"] = lat
        if lon is not None:
            result["gps_longitude"] = lon
        if 6 in gps_tags:
            result["gps_altitude_m"] = gps_tags[6]

    return result


def _read_ifd(tiff: bytes, offset: int, endian: str) -> dict[int, Any]:
    if offset + 2 > len(tiff):
        return {}
    count = struct.unpack_from(f"{endian}H", tiff, offset)[0]
    tags: dict[int, Any] = {}
    for i in range(count):
        entry_off = offset + 2 + i * 12
        if entry_off + 12 > len(tiff):
            break
        tag_id, type_id, n_vals = struct.unpack_from(f"{endian}HHI", tiff, entry_off)
        val = _read_tag_value(tiff, entry_off + 8, type_id, n_vals, endian)
        if val is not None:
            tags[tag_id] = val
    return tags


def _read_tag_value(
    tiff: bytes, value_offset: int, type_id: int, n_vals: int, endian: str
) -> Any:
    type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 9: 4, 10: 8}
    size = type_sizes.get(type_id, 0)
    if size == 0:
        return None
    total = size * n_vals
    if total <= 4:
        raw = tiff[value_offset: value_offset + total]
    else:
        ptr = struct.unpack_from(f"{endian}I", tiff, value_offset)[0]
        raw = tiff[ptr: ptr + total]

    if type_id == 2:  # ASCII
        return raw.rstrip(b"\x00").decode("latin-1", errors="replace").strip()
    if type_id in (3,):  # SHORT
        if n_vals == 1:
            return struct.unpack_from(f"{endian}H", raw)[0]
    if type_id in (4, 9):  # LONG / SLONG
        if n_vals == 1:
            return struct.unpack_from(f"{endian}I", raw)[0]
    if type_id == 5:  # RATIONAL (num/den pairs)
        rationals = []
        for i in range(n_vals):
            num, den = struct.unpack_from(f"{endian}II", raw, i * 8)
            rationals.append(num / den if den else 0)
        return rationals[0] if n_vals == 1 else rationals
    return None


def _gps_coord(
    dms: Any, ref: Any
) -> float | None:
    if not isinstance(dms, list) or len(dms) < 3:
        if not isinstance(dms, float):
            return None
    try:
        if isinstance(dms, list):
            deg, mn, sec = dms[0], dms[1], dms[2]
        else:
            return None
        coord = deg + mn / 60.0 + sec / 3600.0
        if isinstance(ref, str) and ref in ("S", "W"):
            coord = -coord
        return float(round(coord, 6))
    except (TypeError, IndexError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# PDF
# ─────────────────────────────────────────────────────────────────────────────

def _pdf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    text = data.decode("latin-1", errors="replace")
    result: dict[str, Any] = {}

    # PDF version
    m = re.search(r"%PDF-(\d+\.\d+)", text)
    if m:
        result["pdf_version"] = m.group(1)

    # Info dictionary — extract common fields
    info_re = re.findall(
        r"/(?:Author|Title|Subject|Creator|Producer|CreationDate|ModDate)\s*\(([^)]{0,200})\)",
        text,
    )
    field_names = re.findall(
        r"/(Author|Title|Subject|Creator|Producer|CreationDate|ModDate)\s*\(",
        text,
    )
    for name, value in zip(field_names, info_re):
        key = name.lower().replace("date", "_date")
        result[key] = _decode_pdf_string(value)

    # Page count hint
    m = re.search(r"/Count\s+(\d+)", text)
    if m:
        result["page_count"] = int(m.group(1))

    # Encrypted?
    result["encrypted"] = "/Encrypt" in text

    return result


def _decode_pdf_string(s: str) -> str:
    # Handle PDF date format: D:YYYYMMDDHHmmSSOHH'mm
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", s)
    if m:
        y, mo, d, h, mn, sec = m.groups()
        return f"{y}-{mo}-{d}T{h}:{mn}:{sec}Z"
    return s.strip()


# ─────────────────────────────────────────────────────────────────────────────
# PE (Windows executable / DLL / driver)
# ─────────────────────────────────────────────────────────────────────────────

def _pe(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {}

    if data[:2] != b"MZ":
        raise MetadataError("Not a PE file")

    pe_offset = struct.unpack_from("<I", data, 60)[0]
    if pe_offset + 248 > len(data):
        return result

    if data[pe_offset: pe_offset + 4] != b"PE\x00\x00":
        return result

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    machines = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "ARM64", 0x1C0: "ARM"}
    result["architecture"] = machines.get(machine, f"0x{machine:04x}")

    compile_ts = struct.unpack_from("<I", data, pe_offset + 8)[0]
    if compile_ts > 0:
        try:
            dt = datetime.fromtimestamp(compile_ts, tz=timezone.utc)
            result["compile_timestamp"] = dt.isoformat().replace("+00:00", "Z")
        except (OSError, OverflowError):
            result["compile_timestamp"] = f"0x{compile_ts:08x}"

    characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
    result["is_dll"] = bool(characteristics & 0x2000)
    result["is_system_file"] = bool(characteristics & 0x1000)

    opt_magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    result["pe_format"] = {0x10B: "PE32", 0x20B: "PE32+"}.get(opt_magic, "unknown")

    if opt_magic in (0x10B, 0x20B):
        subsystem_off = pe_offset + 24 + (68 if opt_magic == 0x10B else 84)
        if subsystem_off + 2 <= len(data):
            subsystem = struct.unpack_from("<H", data, subsystem_off)[0]
            subsystems = {
                1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
                5: "OS2_CUI", 7: "POSIX_CUI", 14: "WINDOWS_CE_GUI",
            }
            result["subsystem"] = subsystems.get(subsystem, f"0x{subsystem:04x}")

    file_type = "DLL" if result["is_dll"] else ("SYS" if result["is_system_file"] else "EXE")
    result["file_class"] = file_type

    return result


# ─────────────────────────────────────────────────────────────────────────────
# PNG
# ─────────────────────────────────────────────────────────────────────────────

def _png(path: Path) -> dict[str, Any]:
    """Extract metadata from PNG files — IHDR dimensions + tEXt/iTXt chunks."""
    result: dict[str, Any] = {}

    with path.open("rb") as fh:
        sig = fh.read(8)
        if sig != b"\x89PNG\r\n\x1a\n":
            raise MetadataError("Not a PNG file")

        while True:
            hdr = fh.read(8)
            if len(hdr) < 8:
                break
            chunk_len = struct.unpack(">I", hdr[:4])[0]
            chunk_type = hdr[4:8].decode("ascii", errors="replace")
            chunk_data = fh.read(chunk_len)
            fh.read(4)  # CRC

            if chunk_type == "IHDR" and len(chunk_data) >= 13:
                result["width"] = struct.unpack(">I", chunk_data[0:4])[0]
                result["height"] = struct.unpack(">I", chunk_data[4:8])[0]
                result["bit_depth"] = chunk_data[8]
                color_types = {0: "greyscale", 2: "RGB", 3: "indexed",
                               4: "greyscale+alpha", 6: "RGBA"}
                result["color_type"] = color_types.get(chunk_data[9], str(chunk_data[9]))
                result["interlaced"] = bool(chunk_data[12])

            elif chunk_type == "tEXt":
                # tEXt: keyword\x00text
                nul = chunk_data.find(b"\x00")
                if nul > 0:
                    key = chunk_data[:nul].decode("latin-1", errors="replace")
                    val = chunk_data[nul+1:].decode("latin-1", errors="replace")
                    result[f"text_{key.lower().replace(' ','_')}"] = val[:256]

            elif chunk_type == "iTXt":
                # iTXt: keyword NUL compressed_flag NUL method NUL lang NUL xlated NUL text
                nul = chunk_data.find(b"\x00")
                if nul > 0:
                    key = chunk_data[:nul].decode("utf-8", errors="replace")
                    rest = chunk_data[nul+1:]
                    # Skip compression flag, method, lang, translated key
                    parts = rest.split(b"\x00", 4)
                    if len(parts) >= 5:
                        val = parts[4].decode("utf-8", errors="replace")
                        result[f"itxt_{key.lower().replace(' ','_')}"] = val[:256]

            elif chunk_type == "gAMA":
                if len(chunk_data) == 4:
                    gamma = struct.unpack(">I", chunk_data)[0] / 100000.0
                    result["gamma"] = gamma

            elif chunk_type == "pHYs" and len(chunk_data) >= 9:
                x_ppu = struct.unpack(">I", chunk_data[0:4])[0]
                y_ppu = struct.unpack(">I", chunk_data[4:8])[0]
                unit = chunk_data[8]
                if unit == 1:  # metres
                    result["dpi_x"] = round(x_ppu * 0.0254)
                    result["dpi_y"] = round(y_ppu * 0.0254)

            elif chunk_type == "IEND":
                break

            if chunk_len > 64 * 1024 * 1024:
                break  # Skip suspiciously large chunks

    return result


# ─────────────────────────────────────────────────────────────────────────────
# ELF
# ─────────────────────────────────────────────────────────────────────────────

def _elf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise MetadataError("Not an ELF file")

    result: dict[str, Any] = {}
    ei_class = data[4]
    ei_data = data[5]

    result["bits"] = {1: 32, 2: 64}.get(ei_class, 0)
    result["endianness"] = {1: "little", 2: "big"}.get(ei_data, "unknown")

    endian = "<" if ei_data == 1 else ">"
    e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
    types = {1: "relocatable", 2: "executable", 3: "shared_object", 4: "core_dump"}
    result["elf_type"] = types.get(e_type, f"0x{e_type:04x}")

    e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
    machines = {3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64", 8: "MIPS"}
    result["architecture"] = machines.get(e_machine, f"0x{e_machine:04x}")

    # Look for build-id note
    build_id_re = re.search(rb"GNU\x00\x00\x00\x00(.{20})", data)
    if build_id_re:
        result["build_id"] = build_id_re.group(1).hex()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# SQLite
# ─────────────────────────────────────────────────────────────────────────────

def _quote_sql_identifier(name: str) -> str:
    """Safely quote a SQL identifier (table/view name) for SQLite.

    SQLite (and standard SQL) escapes a double-quote inside a quoted
    identifier by doubling it: ``"`` -> ``""``. Without this, a forensic
    evidence file containing a table literally named e.g.
    ``evil"; DROP TABLE x; --`` could break out of the quoted identifier
    and inject arbitrary SQL when read by ``frece metadata``.

    This function eliminates that injection vector. The resulting string
    is safe to interpolate directly into a SQL statement as an identifier
    (identifiers cannot be supplied via parameter placeholders in SQLite).
    """
    return '"' + name.replace('"', '""') + '"'


def _sqlite(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
        )
        tables = cursor.fetchall()
        table_info = []
        for row in tables:
            name = row["name"]
            if name.startswith("sqlite_"):
                continue

            safe_name = _quote_sql_identifier(name)
            try:
                # safe_name is a properly-escaped SQL identifier (see
                # _quote_sql_identifier); identifiers cannot use ? placeholders.
                count_row = conn.execute(
                    f"SELECT COUNT(*) FROM {safe_name}"  # nosec B608
                ).fetchone()
                count = count_row[0] if count_row else 0
            except Exception:
                count = -1

            cols = conn.execute(
                f"PRAGMA table_info({safe_name})"  # nosec B608
            ).fetchall()
            col_names = [c["name"] for c in cols]
            table_info.append({
                "name": name,
                "type": row["type"],
                "row_count": count,
                "columns": col_names,
            })

        result["tables"] = table_info
        result["table_count"] = len(table_info)

        # Schema version
        ver = conn.execute("PRAGMA schema_version").fetchone()
        if ver:
            result["schema_version"] = ver[0]

        # User version
        uver = conn.execute("PRAGMA user_version").fetchone()
        if uver:
            result["user_version"] = uver[0]

        # Page size and count
        ps = conn.execute("PRAGMA page_size").fetchone()
        pc = conn.execute("PRAGMA page_count").fetchone()
        if ps and pc:
            result["page_size"] = ps[0]
            result["page_count"] = pc[0]
            result["database_size_bytes"] = ps[0] * pc[0]

        conn.close()
    except sqlite3.Error as exc:
        result["extraction_error"] = str(exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# PCAP
# ─────────────────────────────────────────────────────────────────────────────

def _pcap(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    data = path.read_bytes()
    if len(data) < 24:
        raise MetadataError("PCAP too small")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise MetadataError("Invalid PCAP magic")

    link_type = struct.unpack_from(f"{endian}I", data, 20)[0]
    result["link_type"] = link_type

    pos = 24
    packet_count = 0
    src_ips: set[str] = set()
    dst_ips: set[str] = set()
    protocols: dict[str, int] = {}
    first_ts = last_ts = 0

    while pos + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(f"{endian}IIII", data, pos)
        pos += 16
        if incl_len > 65535 or pos + incl_len > len(data):
            break

        pkt = data[pos: pos + incl_len]
        pos += incl_len
        packet_count += 1

        if first_ts == 0:
            first_ts = ts_sec
        last_ts = ts_sec

        # Ethernet → IP parsing (link_type=1)
        if link_type == 1 and len(pkt) >= 34:
            eth_type = struct.unpack_from(">H", pkt, 12)[0]
            if eth_type == 0x0800 and len(pkt) >= 34:  # IPv4
                proto = pkt[23]
                src_ip = ".".join(str(b) for b in pkt[26:30])
                dst_ip = ".".join(str(b) for b in pkt[30:34])
                src_ips.add(src_ip)
                dst_ips.add(dst_ip)
                proto_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
                pname = proto_names.get(proto, str(proto))
                protocols[pname] = protocols.get(pname, 0) + 1

    result["packet_count"] = packet_count
    result["unique_src_ips"] = sorted(src_ips)
    result["unique_dst_ips"] = sorted(dst_ips)
    result["protocols"] = protocols

    if first_ts:
        result["first_packet"] = datetime.fromtimestamp(
            first_ts, tz=timezone.utc
        ).isoformat().replace("+00:00", "Z")
    if last_ts:
        result["last_packet"] = datetime.fromtimestamp(
            last_ts, tz=timezone.utc
        ).isoformat().replace("+00:00", "Z")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# EML (RFC-822 / MIME email)
# ─────────────────────────────────────────────────────────────────────────────

def _eml(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    result: dict[str, Any] = {}

    headers_end = text.find("\r\n\r\n")
    if headers_end == -1:
        headers_end = text.find("\n\n")
    header_block = text[:headers_end] if headers_end > 0 else text[:2048]

    for field in ("From", "To", "CC", "Subject", "Date", "Message-ID", "Reply-To"):
        m = re.search(
            rf"^{field}:\s*(.+?)(?=\r?\n[^\s]|\Z)",
            header_block,
            re.MULTILINE | re.IGNORECASE | re.DOTALL,
        )
        if m:
            result[field.lower().replace("-", "_")] = (
                m.group(1).replace("\r\n ", " ").replace("\n ", " ").strip()[:256]
            )

    # MIME attachments
    attachments = re.findall(
        r'Content-Disposition:\s*attachment;\s*filename[*]?="?([^"\r\n]+)"?',
        text,
        re.IGNORECASE,
    )
    if attachments:
        result["attachments"] = attachments

    # Content type
    m = re.search(r"Content-Type:\s*([^;\r\n]+)", header_block, re.IGNORECASE)
    if m:
        result["content_type"] = m.group(1).strip()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# LNK (Windows Shell Link)
# ─────────────────────────────────────────────────────────────────────────────

def _lnk(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {}

    if len(data) < 76:
        raise MetadataError("LNK file too small")

    if data[:4] != b"\x4C\x00\x00\x00":
        raise MetadataError("Invalid LNK header")

    # Timestamps at offsets 28, 36, 44 (FILETIME = 100ns intervals from 1601-01-01)
    def filetime_to_iso(offset: int) -> str:
        try:
            ft = struct.unpack_from("<Q", data, offset)[0]
            if ft == 0:
                return ""
            # Convert Windows FILETIME to Unix epoch
            unix_ts = (ft - 116444736000000000) / 10_000_000
            return datetime.fromtimestamp(
                unix_ts, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z")
        except (struct.error, OSError, OverflowError):
            return ""

    result["creation_time"] = filetime_to_iso(28)
    result["access_time"] = filetime_to_iso(36)
    result["write_time"] = filetime_to_iso(44)

    # File size and attributes
    result["target_file_size"] = struct.unpack_from("<I", data, 52)[0]
    attrs = struct.unpack_from("<I", data, 24)[0]
    attr_flags = []
    if attrs & 0x01:
        attr_flags.append("READONLY")
    if attrs & 0x02:
        attr_flags.append("HIDDEN")
    if attrs & 0x04:
        attr_flags.append("SYSTEM")
    if attrs & 0x10:
        attr_flags.append("DIRECTORY")
    if attrs & 0x20:
        attr_flags.append("ARCHIVE")
    result["file_attributes"] = attr_flags

    # Link flags
    link_flags = struct.unpack_from("<I", data, 20)[0]
    result["has_link_target_id"] = bool(link_flags & 0x01)
    result["has_link_info"] = bool(link_flags & 0x02)
    result["has_name"] = bool(link_flags & 0x04)

    # Try to extract target path from StringData
    # Walk past IDList if present
    pos = 76
    if link_flags & 0x01:  # HasLinkTargetIDList
        if pos + 2 <= len(data):
            idlist_size = struct.unpack_from("<H", data, pos)[0]
            pos += 2 + idlist_size

    # LinkInfo block
    if link_flags & 0x02 and pos + 28 <= len(data):
        li_size = struct.unpack_from("<I", data, pos)[0]
        vol_flags = struct.unpack_from("<I", data, pos + 8)[0]
        drive_types = {0: "UNKNOWN", 1: "NO_ROOT", 2: "REMOVABLE",
                       3: "FIXED", 4: "REMOTE", 5: "CDROM", 6: "RAMDISK"}
        drive_type = struct.unpack_from("<I", data, pos + 12)[0]
        result["drive_type"] = drive_types.get(drive_type, str(drive_type))
        vol_serial = struct.unpack_from("<I", data, pos + 16)[0]
        result["volume_serial"] = f"{vol_serial:08X}"

        # Local base path offset
        if vol_flags & 0x01:
            lbp_offset = struct.unpack_from("<I", data, pos + 20)[0]
            path_start = pos + lbp_offset
            path_end = data.find(b"\x00", path_start)
            if path_end > path_start:
                result["target_path"] = data[path_start:path_end].decode("latin-1")

        pos += li_size

    return result


# ─────────────────────────────────────────────────────────────────────────────
# EVTX (Windows Event Log)
# ─────────────────────────────────────────────────────────────────────────────

def _evtx(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {}

    if data[:8] != b"ElfFile\x00":
        raise MetadataError("Not an EVTX file")

    # File header fields (offsets from EVTX specification)
    result["header_size"] = struct.unpack_from("<I", data, 8)[0]
    next_record_id = struct.unpack_from("<Q", data, 24)[0]
    result["next_record_id"] = next_record_id
    result["estimated_record_count"] = max(0, next_record_id - 1)

    oldest_chunk = struct.unpack_from("<Q", data, 16)[0]
    newest_chunk = struct.unpack_from("<Q", data, 32)[0]
    result["oldest_chunk"] = int(oldest_chunk)
    result["newest_chunk"] = int(newest_chunk)

    file_flags = struct.unpack_from("<I", data, 40)[0]
    result["is_dirty"] = bool(file_flags & 0x01)
    result["is_full"] = bool(file_flags & 0x02)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# ZIP / DOCX / XLSX / PPTX
# ─────────────────────────────────────────────────────────────────────────────

def _zip(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            entries = zf.infolist()
            result["file_count"] = len(entries)
            result["files"] = [
                {
                    "name": e.filename,
                    "compressed_size": e.compress_size,
                    "uncompressed_size": e.file_size,
                    "method": {0: "store", 8: "deflate", 12: "bzip2", 14: "lzma"}.get(
                        e.compress_type, str(e.compress_type)
                    ),
                    "modified": (
                        datetime(*e.date_time).isoformat() if e.date_time else None
                    ),
                    "is_encrypted": bool(e.flag_bits & 0x1),
                }
                for e in entries[:100]  # cap at 100 entries
            ]
            result["has_encrypted_entries"] = any(
                bool(e.flag_bits & 0x1) for e in entries
            )

            # Try to extract Office metadata
            if "docProps/core.xml" in zf.namelist():
                try:
                    core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                    dc_fields = ("dc:creator", "dc:title", "dcterms:created", "dcterms:modified")
                    for field in dc_fields:
                        pat = rf"<{re.escape(field)}>([^<]+)</{re.escape(field)}>"
                        m = re.search(pat, core_xml)
                        if m:
                            clean_field = field.replace("dc:", "").replace("dcterms:", "")
                            result[clean_field] = m.group(1).strip()
                except Exception:
                    pass
    except zipfile.BadZipFile as exc:
        raise MetadataError(f"Bad ZIP: {exc}") from exc

    return result


# ─────────────────────────────────────────────────────────────────────────────
# RTF
# ─────────────────────────────────────────────────────────────────────────────

def _rtf(path: Path) -> dict[str, Any]:
    with path.open("rb") as _fh:
        data = _fh.read(65536)
    text = data.decode("latin-1", errors="replace")
    result: dict[str, Any] = {}

    patterns = {
        "author": r"\\author\s+([^\\}]+)",
        "company": r"\\company\s+([^\\}]+)",
        "operator": r"\\operator\s+([^\\}]+)",
        "title": r"\\title\s+([^\\}]+)",
        "subject": r"\\subject\s+([^\\}]+)",
        "creatim": r"\\creatim\\yr(\d+)\\mo(\d+)\\dy(\d+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            if key == "creatim":
                y, mo, d = m.group(1), m.group(2).zfill(2), m.group(3).zfill(2)
                result["creation_date"] = f"{y}-{mo}-{d}"
            else:
                result[key] = m.group(1).strip()[:256]

    return result
