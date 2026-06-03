"""FRECE CLI entrypoint."""

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from frece import __version__
from frece.acquisition import EvidenceAcquisition
from frece.carver import StreamingCarver
from frece.classifier import classify_file, shannon_entropy
from frece.config import load_config
from frece.custody import (
    CustodyDatabase,
    create_case_secret_key,
    get_case_secret_key,
    rotate_case_secret_key,
)
from frece.errors import AcquisitionError, CustodyError, FreceError, RecoveryError
from frece.logging import setup_logging
from frece.partition import list_partitions
from frece.recovery import DeletedFileRecovery
from frece.sandbox import InputValidator
from frece.metadata import extract as extract_metadata
from frece.report import render_html_report
from frece.scoring import score_batch
from frece.timeline import (
    build_timeline,
    events_to_csv,
    events_to_json,
    events_to_text,
)


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args, extras = parser.parse_known_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if extras and not (args.command == "case" and args.case_command == "log"):
        print(f"Unknown arguments: {' '.join(extras)}", file=sys.stderr)
        return 2

    try:
        validate_cli_args(args)
        if args.command == "tool-status":
            return check_tools()
        if args.command == "carve":
            return handle_carve(args)
        if args.command == "scan":
            return handle_scan(args)
        if args.command == "hash":
            return handle_hash(args)
        if args.command == "partitions":
            return handle_partitions(args)
        if args.command == "recover":
            return handle_recover(args)
        if args.command == "acquire":
            return handle_acquire(args)
        if args.command == "report":
            return handle_report(args)
        if args.command == "custody":
            return handle_custody(args)
        if args.command == "case":
            return handle_case(args, extras)
        if args.command == "timeline":
            return handle_timeline(args)
        if args.command == "search":
            return handle_search(args)
        if args.command == "entropy":
            return handle_entropy(args)
        if args.command == "fsstat":
            return handle_fsstat(args)
        if args.command == "classify":
            return handle_classify(args)
        if args.command == "metadata":
            return handle_metadata(args)
        if args.command == "score":
            return handle_score(args)
    except FreceError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1


def validate_cli_args(args: argparse.Namespace) -> None:
    """Validate CLI arguments before dispatch."""
    if args.command == "carve":
        args.source = InputValidator.validate_path(str(args.source))
        args.output = InputValidator.validate_path(str(args.output))
        return

    if args.command == "recover":
        args.image = InputValidator.validate_path(str(args.image))
        args.output = InputValidator.validate_path(str(args.output))
        if args.mapfile is not None:
            args.mapfile = InputValidator.validate_path(str(args.mapfile))
        if args.log_dir is not None:
            args.log_dir = InputValidator.validate_path(str(args.log_dir))
        return

    if args.command == "scan":
        args.image = InputValidator.validate_path(str(args.image))
        if args.output is not None:
            args.output = InputValidator.validate_path(str(args.output))
        return

    if args.command == "partitions":
        args.image = InputValidator.validate_path(str(args.image))
        return

    if args.command == "hash":
        args.source = InputValidator.validate_path(str(args.source))
        if args.output is not None:
            args.output = InputValidator.validate_path(str(args.output))
        return

    if args.command == "acquire":
        source_str = str(args.source)
        # Validate source path for injection characters but keep as str
        # (EvidenceAcquisition.acquire_device expects str for block-device paths)
        InputValidator.validate_path(source_str)
        output_path = InputValidator.validate_path(str(args.output))
        args.source = source_str
        args.output = output_path
        EvidenceAcquisition._assert_safe_output_target(source_str, output_path)
        return

    if args.command == "report":
        args.case_name = InputValidator.validate_case_name(args.case_name)
        if getattr(args, "root", None) is not None:
            args.root = InputValidator.validate_path(str(args.root))
        if getattr(args, "output", None) is not None:
            args.output = InputValidator.validate_path(str(args.output))
        return

    if args.command == "custody" and args.custody_command == "verify":
        args.case_dir = InputValidator.validate_path(str(args.case_dir))
        if args.evidence_id is not None:
            args.evidence_id = InputValidator.validate_string_arg(
                args.evidence_id,
                arg_name="evidence_id",
            )
        if args.source is not None:
            args.source = InputValidator.validate_string_arg(
                args.source,
                arg_name="source",
            )
        return

    if args.command == "case":
        if getattr(args, "case_name", None):
            args.case_name = InputValidator.validate_case_name(args.case_name)
        if getattr(args, "root", None) is not None:
            args.root = InputValidator.validate_path(str(args.root))
        if getattr(args, "event_type", None):
            args.event_type = InputValidator.validate_string_arg(
                args.event_type,
                arg_name="event_type",
            )
        if getattr(args, "operator", None):
            args.operator = InputValidator.validate_string_arg(
                args.operator,
                arg_name="operator",
            )
        if getattr(args, "evidence_id", None):
            args.evidence_id = InputValidator.validate_string_arg(
                args.evidence_id,
                arg_name="evidence_id",
            )
        if getattr(args, "details", None):
            args.details = InputValidator.validate_string_arg(
                args.details,
                arg_name="details",
            )
        if getattr(args, "source", None):
            args.source = InputValidator.validate_string_arg(
                args.source,
                arg_name="source",
            )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="frece",
        description="FRECE - Forensic Recovery and Evidence Collection Engine",
    )
    parser.add_argument("--version", action="version", version=__version__)

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "tool-status",
        help="Check if required forensic tools are available",
    )

    carve_parser = subparsers.add_parser(
        "carve",
        help="Carve files from a forensic image",
    )
    carve_parser.add_argument("source", type=Path)
    carve_parser.add_argument("--output", required=True, type=Path)
    carve_parser.add_argument("--no-verify", action="store_true")
    carve_parser.add_argument("--chunk-size", type=int)
    carve_parser.add_argument("--max-signature-length", type=int)
    carve_parser.add_argument("--max-video-size", type=int)

    scan_parser = subparsers.add_parser(
        "scan",
        help="List deleted files in a forensic image (read-only, no extraction)",
    )
    scan_parser.add_argument("image", type=Path, help="Path to forensic image or device")
    scan_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Filesystem byte offset in sectors",
    )
    scan_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write scan results to JSON file",
    )
    scan_parser.add_argument(
        "--type",
        dest="filter_type",
        default=None,
        help="Filter by fls entry type: r=regular, d=directory",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout in seconds for Sleuth Kit commands (0 = unlimited)",
    )
    scan_parser.add_argument(
        "--mactime",
        action="store_true",
        default=False,
        help="Include MAC timestamps (mtime/atime/ctime/crtime) via fls -m",
    )
    scan_parser.add_argument(
        "--all",
        dest="all_entries",
        action="store_true",
        default=False,
        help="Include all entries, not just deleted ones (use with --mactime)",
    )

    partitions_parser = subparsers.add_parser(
        "partitions",
        help="List partition offsets from an image with mmls",
    )
    partitions_parser.add_argument("image", type=Path, help="Path to forensic image")

    hash_parser = subparsers.add_parser(
        "hash",
        help="Hash an evidence file for chain-of-custody",
    )
    hash_parser.add_argument("source", type=Path, help="File to hash")
    hash_parser.add_argument(
        "--algorithms",
        default="sha256,sha1,md5",
        help="Comma-separated list of algorithms (default: sha256,sha1,md5)",
    )
    hash_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write hash result to JSON file",
    )

    recover_parser = subparsers.add_parser(
        "recover",
        help="Recover deleted files with The Sleuth Kit",
    )
    recover_parser.add_argument("image", type=Path)
    recover_parser.add_argument("--output", required=True, type=Path)
    recover_parser.add_argument("--offset", type=int, default=0)
    recover_parser.add_argument("--mapfile", type=Path)
    recover_parser.add_argument("--verify-inodes", action="store_true")
    recover_parser.add_argument("--log-dir", type=Path)
    recover_parser.add_argument(
        "--inodes",
        default=None,
        help="Comma-separated inode numbers to recover (default: all deleted)",
    )
    recover_parser.add_argument(
        "--type",
        dest="filter_type",
        default=None,
        help="Comma-separated file types to keep, e.g. jpg,pdf,docx",
    )
    recover_parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout in seconds for Sleuth Kit commands (0 = unlimited)",
    )

    acquire_parser = subparsers.add_parser(
        "acquire",
        help="Acquire evidence from a device or file",
    )
    acquire_parser.add_argument("source")
    acquire_parser.add_argument("--output", required=True, type=Path)
    acquire_parser.add_argument("--force-no-writeblock", action="store_true")
    acquire_parser.add_argument("--no-writeblock-required", action="store_true")

    custody_parser = subparsers.add_parser(
        "custody",
        help="Verify chain-of-custody integrity",
    )
    custody_subparsers = custody_parser.add_subparsers(dest="custody_command")
    custody_verify = custody_subparsers.add_parser(
        "verify",
        help="Verify a custody database in a case directory",
    )
    custody_verify.add_argument("case_dir", type=Path)
    custody_verify.add_argument("--evidence-id")
    custody_verify.add_argument("--source")

    case_parser = subparsers.add_parser(
        "case",
        help="Manage FRECE investigation cases",
    )
    case_subparsers = case_parser.add_subparsers(dest="case_command")

    case_create = case_subparsers.add_parser("create", help="Create a case directory")
    case_create.add_argument("case_name")
    case_create.add_argument("--root", type=Path)

    case_log = case_subparsers.add_parser("log", help="Log an event to a case")
    case_log.add_argument("case_name")
    case_log.add_argument("event_type")
    case_log.add_argument("--root", type=Path)
    case_log.add_argument("--operator")
    case_log.add_argument("--evidence-id")
    case_log.add_argument("--details")
    case_log.add_argument("--detail", action="append", default=[])

    case_verify = case_subparsers.add_parser("verify", help="Verify a case database")
    case_verify.add_argument("case_name")
    case_verify.add_argument("--root", type=Path)
    case_verify.add_argument("--evidence-id")
    case_verify.add_argument("--source")

    case_rotate = case_subparsers.add_parser("rotate-key", help="Rotate a case HMAC key")
    case_rotate.add_argument("case_name")
    case_rotate.add_argument("--root", type=Path)

    report_parser = subparsers.add_parser(
        "report",
        help="Generate a consolidated case investigation report",
    )
    report_parser.add_argument("case_name", help="Case name to report on")
    report_parser.add_argument("--root", type=Path, default=None, help="Case root directory")
    report_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write report to this JSON file (default: stdout)",
    )
    report_parser.add_argument(
        "--format",
        choices=["json", "text", "html"],
        default="json",
        dest="report_format",
    )

    # ── timeline ─────────────────────────────────────────────────────────────
    timeline_parser = subparsers.add_parser(
        "timeline",
        help="Synthesise a MAC-time forensic timeline for a case",
    )
    timeline_parser.add_argument("case_name", help="Case name")
    timeline_parser.add_argument("--root", type=Path, default=None)
    timeline_parser.add_argument(
        "--format",
        choices=["json", "csv", "text"],
        default="text",
        dest="timeline_format",
    )
    timeline_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write timeline to file (default: stdout)",
    )
    timeline_parser.add_argument(
        "--mactime-file",
        type=Path,
        default=None,
        dest="mactime_file",
        help="Supplemental fls -m body file to merge into the timeline",
    )

    # ── search ────────────────────────────────────────────────────────────────
    search_parser = subparsers.add_parser(
        "search",
        help="Keyword / regex search across recovered or carved files",
    )
    search_parser.add_argument(
        "directory",
        type=Path,
        help="Directory of recovered/carved files to search",
    )
    search_parser.add_argument(
        "--keyword",
        required=True,
        help="Search string or regular expression",
    )
    search_parser.add_argument(
        "--regex",
        action="store_true",
        default=False,
        help="Treat --keyword as a Python regular expression",
    )
    search_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write search results to JSON file",
    )
    search_parser.add_argument(
        "--context-lines",
        type=int,
        default=1,
        dest="context_lines",
        help="Number of context lines around each hit (default: 1)",
    )

    # ── entropy ───────────────────────────────────────────────────────────────
    entropy_parser = subparsers.add_parser(
        "entropy",
        help="Compute Shannon entropy for a file or directory of files",
    )
    entropy_parser.add_argument(
        "source",
        type=Path,
        help="File or directory to analyse",
    )
    entropy_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write results to JSON file",
    )
    entropy_parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
        help="Entropy threshold above which files are flagged (default: 7.0)",
    )

    # ── fsstat ────────────────────────────────────────────────────────────────
    fsstat_parser = subparsers.add_parser(
        "fsstat",
        help="Show filesystem metadata and statistics for a forensic image",
    )
    fsstat_parser.add_argument("image", type=Path, help="Path to forensic image")
    fsstat_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Sector offset for the filesystem (default: 0)",
    )

    # ── classify ─────────────────────────────────────────────────────────────
    classify_parser = subparsers.add_parser(
        "classify",
        help="Classify files in a directory by forensic category and entropy",
    )
    classify_parser.add_argument(
        "directory",
        type=Path,
        help="Directory to classify",
    )
    classify_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write classification results to JSON file",
    )
    classify_parser.add_argument(
        "--priority",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Show only files at this priority level or above",
    )

    # ── metadata ─────────────────────────────────────────────────────────────
    metadata_parser = subparsers.add_parser(
        "metadata",
        help="Extract deep forensic metadata (EXIF GPS, PE timestamps, SQLite tables, PCAP IPs…)",
    )
    metadata_parser.add_argument("source", type=Path, help="File or directory to analyse")
    metadata_parser.add_argument("--type", dest="file_type", default=None,
        help="Force file type (jpeg/pe/sqlite/pcap/…). Auto-detected if omitted.")
    metadata_parser.add_argument("--output", type=Path, default=None,
        help="Write JSON results to file")

    # ── score ─────────────────────────────────────────────────────────────────
    score_parser = subparsers.add_parser(
        "score",
        help="Compute recovery confidence scores for carved/recovered artifacts",
    )
    score_parser.add_argument("manifest", type=Path,
        help="Path to carve_manifest.json or recovery_manifest.json")
    score_parser.add_argument("--output", type=Path, default=None,
        help="Write scored manifest to JSON file")
    score_parser.add_argument("--min-score", type=int, default=0, dest="min_score",
        help="Only show artifacts with score >= this value")
    score_parser.add_argument("--grade", default=None,
        choices=["CONFIRMED","PROBABLE","POSSIBLE","SUSPECT","REJECTED"],
        help="Filter by confidence grade")

    return parser


def _write_text_output(output_path: Path, output_str: str, error_cls, context: str) -> None:
    """Write text output atomically enough for forensic logs and manifests."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", encoding="utf-8") as handle:
            handle.write(output_str)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise error_cls(
            f"Cannot write {context}: {output_path}",
            remediation="Check output directory permissions and disk space",
        ) from exc


def check_tools() -> int:
    """Check availability of required tools."""
    tools_to_check = {
        "fls": (["fls", "-V"], "The Sleuth Kit"),
        "icat": (["icat", "-V"], "The Sleuth Kit"),
        "istat": (["istat", "-V"], "The Sleuth Kit"),
        "mmls": (["mmls", "-V"], "The Sleuth Kit"),
        "file": (["file", "--version"], "file utility"),
        "sha256sum": (["sha256sum", "--version"], "GNU coreutils"),
    }

    print("Checking required tools...")
    all_found = True

    for tool, (command, package) in tools_to_check.items():
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                print(f"{tool:20} OK ({package})")
            else:
                print(f"{tool:20} FAILED")
                all_found = False
        except FileNotFoundError:
            print(f"{tool:20} NOT FOUND - install {package}")
            all_found = False
        except subprocess.TimeoutExpired:
            print(f"{tool:20} TIMEOUT")
            all_found = False

    try:
        import magic  # noqa: F401

        print(f"{'python-magic':20} OK")
    except ImportError:
        print(f"{'python-magic':20} NOT FOUND - pip install python-magic")
        all_found = False

    if all_found:
        print("\nAll required tools found!")
        return 0

    print("\nSome tools are missing. Install The Sleuth Kit and GNU file/coreutils.")
    return 1


def handle_carve(args: argparse.Namespace) -> int:
    """Handle the carve command."""
    logger = setup_logging(name="frece.carve")
    config = load_config()
    if args.chunk_size is not None:
        config.chunk_size = args.chunk_size
    if args.max_signature_length is not None:
        config.max_signature_length = args.max_signature_length
    if args.max_video_size is not None:
        config.max_video_size = args.max_video_size

    carver = StreamingCarver(config)
    manifest = carver.carve(args.source, args.output, verify=not args.no_verify)

    output = manifest.to_dict()
    output["manifest_path"] = str(args.output / "carve_manifest.json")
    output["files_carved"] = len(manifest.carved_files)
    logger.info(
        json.dumps(
            {
                "event": "CARVE_COMPLETE",
                "source": str(args.source),
                "files_carved": len(manifest.carved_files),
            }
        )
    )
    print(json.dumps(output, indent=2))
    return 0


def handle_recover(args: argparse.Namespace) -> int:
    """Handle the recover command."""
    logger = setup_logging(args.log_dir, name="frece.recovery")
    config = load_config()
    recovery = DeletedFileRecovery(logger, config=config, timeout=args.timeout)

    inodes = None
    if args.inodes:
        try:
            inodes = [int(inode.strip()) for inode in args.inodes.split(",")]
        except ValueError:
            print("--inodes must be comma-separated integers", file=sys.stderr)
            return 1

    file_types = None
    if args.filter_type:
        file_types = [file_type.strip() for file_type in args.filter_type.split(",")]

    recovered = recovery.recover_deleted(
        args.image,
        args.output,
        image_offset=args.offset,
        mapfile_path=args.mapfile,
        verify=args.verify_inodes,
        inodes=inodes,
        file_types=file_types,
    )

    print(
        json.dumps(
            {
                "source": str(args.image),
                "recovered_files": len(recovered),
                "manifest_path": str(args.output / "recovery_manifest.json"),
            },
            indent=2,
        )
    )
    return 0


def handle_acquire(args: argparse.Namespace) -> int:
    """Handle the acquire command."""
    config = load_config()
    acquisition = EvidenceAcquisition(setup_logging(name="frece.acquire"), config=config)
    metadata = acquisition.acquire_device(
        args.source,
        args.output,
        writeblock_required=not args.no_writeblock_required,
        force_no_writeblock=args.force_no_writeblock,
    )
    print(json.dumps(metadata, indent=2))
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    """Handle the scan command - list deleted files, no extraction."""
    logger = setup_logging(name="frece.scan")
    config = load_config()
    recovery = DeletedFileRecovery(logger, config=config, timeout=args.timeout)

    all_entries_flag = getattr(args, "all_entries", False)
    use_mactime = getattr(args, "mactime", False)

    if use_mactime:
        entries = recovery.scan_mactime(
            args.image,
            image_offset=args.offset,
            deleted_only=not all_entries_flag,
        )
        if args.filter_type:
            ft = args.filter_type.lower()
            entries = [e for e in entries if e.entry_type == ft]

        data = {
            "source": str(args.image),
            "timestamp": _utc_now_iso(),
            "mode": "mactime",
            "total_entries": len(entries),
            "entries": [
                {
                    "inode": e.inode,
                    "inode_token": e.inode_token,
                    "type": e.entry_type,
                    "name": e.name,
                    "size": e.size,
                    "mtime": e.mtime,
                    "atime": e.atime,
                    "ctime": e.ctime,
                    "crtime": e.crtime,
                }
                for e in entries
            ],
        }
    else:
        entries = recovery.scan_deleted(args.image, image_offset=args.offset)
        if args.filter_type:
            filter_type = args.filter_type.lower()
            entries = [entry for entry in entries if entry.entry_type == filter_type]

        data = {
            "source": str(args.image),
            "timestamp": _utc_now_iso(),
            "mode": "standard",
            "total_deleted": len(entries),
            "entries": [
                {
                    "inode": entry.inode,
                    "inode_token": entry.inode_token,
                    "type": entry.entry_type,
                    "name": entry.name,
                    "reallocated": entry.allocated,
                }
                for entry in entries
            ],
        }

    output_str = json.dumps(data, indent=2)
    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "scan output")
        print(f"Scan saved to {args.output} ({len(entries)} entries)")
    else:
        print(output_str)

    return 0


def handle_hash(args: argparse.Namespace) -> int:
    """Handle the hash command."""
    acquisition = EvidenceAcquisition(setup_logging(name="frece.hash"))
    algorithms = tuple(
        algorithm.strip() for algorithm in args.algorithms.split(",") if algorithm.strip()
    )
    result = acquisition.hash_file(args.source, algorithms=algorithms)
    output_str = json.dumps(result, indent=2)

    if args.output:
        _write_text_output(args.output, output_str, AcquisitionError, "hash output")
        print(f"Hash written to {args.output}")
    else:
        print(output_str)

    return 0


def handle_partitions(args: argparse.Namespace) -> int:
    """Handle the partitions command."""
    partitions = [asdict(partition) for partition in list_partitions(args.image)]
    print(json.dumps(partitions, indent=2))
    return 0


def handle_custody(args: argparse.Namespace) -> int:
    """Handle custody subcommands."""
    if args.custody_command != "verify":
        raise CustodyError(
            "Missing custody subcommand",
            remediation="Use 'frece custody verify <case_dir>'",
        )

    return verify_custody_case(args.case_dir, args.evidence_id, args.source)


def handle_case(args: argparse.Namespace, extras: list[str]) -> int:
    """Handle case subcommands."""
    if args.case_command == "create":
        case_dir = resolve_case_dir(args.case_name, args.root)
        create_case_secret_key(case_dir, case_name=args.case_name)
        CustodyDatabase(
            case_dir / "custody.db",
            get_case_secret_key(case_dir, case_name=args.case_name),
        )
        print(json.dumps({"case_dir": str(case_dir)}, indent=2))
        return 0

    if args.case_command == "log":
        case_dir = resolve_case_dir(args.case_name, args.root)
        custody_db = load_custody_db(case_dir, case_name=args.case_name)
        details = parse_case_details(args.details, args.detail, extras)
        entry = custody_db.log_event(
            event_type=args.event_type,
            evidence_id=args.evidence_id or args.case_name,
            operator=args.operator or getpass.getuser(),
            details=details,
        )
        print(json.dumps(asdict(entry), indent=2))
        return 0

    if args.case_command == "verify":
        case_dir = resolve_case_dir(args.case_name, args.root)
        return verify_custody_case(case_dir, args.evidence_id, args.source)

    if args.case_command == "rotate-key":
        case_dir = resolve_case_dir(args.case_name, args.root)
        key_path = rotate_case_secret_key(case_dir, case_name=args.case_name)
        print(json.dumps({"case_dir": str(case_dir), "key_path": str(key_path)}, indent=2))
        return 0

    raise CustodyError(
        "Missing case subcommand",
        remediation="Use 'frece case create|log|verify|rotate-key ...'",
    )


def handle_report(args: argparse.Namespace) -> int:
    """Handle the report command — consolidated case summary."""
    case_dir = resolve_case_dir(args.case_name, args.root)
    if not case_dir.exists():
        print(f"Case directory not found: {case_dir}", file=sys.stderr)
        return 1

    report: dict = {
        "case_name": args.case_name,
        "case_dir": str(case_dir),
        "generated_at": _utc_now_iso(),
        "custody_entries": 0,
        "custody_verified": False,
        "carve_manifests": [],
        "recovery_manifests": [],
    }

    db_path = case_dir / "custody.db"
    if db_path.exists():
        try:
            custody_db = load_custody_db(case_dir, case_name=args.case_name)
            total, _ = custody_db.verify_database()
            report["custody_entries"] = total
            report["custody_verified"] = True
        except Exception as exc:
            report["custody_verified"] = False
            report["custody_error"] = str(exc)

    for manifest_path in sorted(case_dir.rglob("carve_manifest.json")):
        try:
            report["carve_manifests"].append(json.loads(manifest_path.read_text()))
        except Exception as exc:
            report.setdefault("manifest_errors", []).append(
                {"path": str(manifest_path), "error": str(exc)}
            )

    for manifest_path in sorted(case_dir.rglob("recovery_manifest.json")):
        try:
            report["recovery_manifests"].append(json.loads(manifest_path.read_text()))
        except Exception as exc:
            report.setdefault("manifest_errors", []).append(
                {"path": str(manifest_path), "error": str(exc)}
            )

    if args.report_format == "html":
        output_str = _render_html_report(report, args.case_name)
    elif args.report_format == "text":
        output_str = _render_text_report(report)
    else:
        output_str = json.dumps(report, indent=2)

    if args.output:
        _write_text_output(args.output, output_str, CustodyError, "report output")
        print(f"Report written to {args.output}")
    else:
        print(output_str)

    return 0


def _render_text_report(report: dict) -> str:
    """Render a human-readable text report."""
    lines = [
        "=" * 70,
        "  FRECE FORENSIC INVESTIGATION REPORT",
        "=" * 70,
        f"Case Name    : {report['case_name']}",
        f"Case Dir     : {report['case_dir']}",
        f"Generated    : {report['generated_at']}",
        f"Custody OK   : {report['custody_verified']}",
        f"Custody Entries: {report['custody_entries']}",
        "-" * 70,
    ]

    total_carved = sum(
        len(m.get("carved_files", [])) for m in report["carve_manifests"]
    )
    total_recovered = sum(
        len(m.get("recovered_files", [])) for m in report["recovery_manifests"]
    )

    lines.append(f"Carved Files   : {total_carved}")
    lines.append(f"Recovered Files: {total_recovered}")
    lines.append("")

    # File-type breakdown across all artifacts
    type_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for m in report["carve_manifests"]:
        for f in m.get("carved_files", []):
            ftype = f.get("file_type", "unknown")
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
            cat = f.get("forensic_category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            pri = f.get("forensic_priority", "LOW")
            priority_counts[pri] = priority_counts.get(pri, 0) + 1

    for m in report["recovery_manifests"]:
        for f in m.get("recovered_files", []):
            ftype = f.get("file_type", "unknown")
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
            cat = f.get("forensic_category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            pri = f.get("forensic_priority", "LOW")
            priority_counts[pri] = priority_counts.get(pri, 0) + 1

    lines.append("TRIAGE PRIORITIES:")
    for pri in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = priority_counts.get(pri, 0)
        bar = "█" * min(count, 40)
        lines.append(f"  {pri:<10} {count:>5}  {bar}")

    lines.append("")
    lines.append("FILE CATEGORIES:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        lines.append(f"  {cat:<15} {count:>5}  {bar}")

    lines.append("")
    lines.append("FILE TYPES (top 15):")
    for ftype, count in sorted(type_counts.items(), key=lambda x: -x[1])[:15]:
        lines.append(f"  {ftype:<15} {count:>5}")

    lines.append("=" * 70)
    return "\n".join(lines)


def _render_html_report(report: dict, case_name: str) -> str:
    """Delegate to report.py (HTML kept in dedicated module for line-length compliance)."""
    return render_html_report(report, case_name)

def handle_timeline(args: argparse.Namespace) -> int:
    """Handle the timeline command."""
    case_dir = resolve_case_dir(args.case_name, args.root)
    if not case_dir.exists():
        print(f"Case directory not found: {case_dir}", file=sys.stderr)
        return 1

    mactime_file = getattr(args, "mactime_file", None)
    events = build_timeline(case_dir, mactime_file=mactime_file)

    fmt = args.timeline_format
    if fmt == "json":
        output_str = events_to_json(events)
    elif fmt == "csv":
        output_str = events_to_csv(events)
    else:
        output_str = events_to_text(events)

    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "timeline output")
        print(f"Timeline written to {args.output} ({len(events)} events)")
    else:
        print(output_str)

    return 0


def handle_search(args: argparse.Namespace) -> int:
    """Handle the search command — keyword/regex search in recovered files."""
    directory = args.directory
    if not directory.exists():
        print(f"Directory not found: {directory}", file=sys.stderr)
        return 1

    keyword = args.keyword
    use_regex = args.regex
    context_lines = args.context_lines

    try:
        pattern = re.compile(keyword, re.IGNORECASE) if use_regex else None
    except re.error as exc:
        print(f"Invalid regex: {exc}", file=sys.stderr)
        return 1

    results = []
    text_extensions = {
        ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".rtf",
        ".eml", ".md", ".py", ".sh", ".js", ".php", ".sql", ".conf", ".ini",
        ".yaml", ".yml",
    }

    for filepath in sorted(directory.rglob("*")):
        if not filepath.is_file():
            continue
        too_large = filepath.stat().st_size > 4 * 1024 * 1024
        if filepath.suffix.lower() not in text_extensions and too_large:
            continue

        try:
            content = filepath.read_bytes()
            # Try UTF-8 first, then latin-1 as fallback
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = content.decode("latin-1", errors="replace")
        except OSError:
            continue

        lines = text.splitlines()
        file_hits = []

        for line_num, line in enumerate(lines, 1):
            if pattern:
                match = pattern.search(line)
                hit = bool(match)
            else:
                hit = keyword.lower() in line.lower()

            if hit:
                start = max(0, line_num - 1 - context_lines)
                end = min(len(lines), line_num + context_lines)
                context = lines[start:end]
                file_hits.append({
                    "line": line_num,
                    "match": line.strip()[:200],
                    "context": [ctx_l.strip()[:200] for ctx_l in context],
                })

        if file_hits:
            results.append({
                "file": str(filepath),
                "hits": len(file_hits),
                "matches": file_hits[:50],  # cap per-file to 50
            })

    output = {
        "keyword": keyword,
        "regex": use_regex,
        "directory": str(directory),
        "files_searched": sum(1 for _ in directory.rglob("*") if _.is_file()),
        "files_with_hits": len(results),
        "results": results,
    }

    output_str = json.dumps(output, indent=2)
    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "search output")
        print(f"Search complete: {len(results)} file(s) matched. Results in {args.output}")
    else:
        print(output_str)

    return 0


def handle_entropy(args: argparse.Namespace) -> int:
    """Handle the entropy command — Shannon entropy analysis."""
    source = args.source
    threshold = args.threshold

    if source.is_file():
        targets = [source]
    elif source.is_dir():
        targets = sorted(f for f in source.rglob("*") if f.is_file())
    else:
        print(f"Source not found: {source}", file=sys.stderr)
        return 1

    results = []
    flagged = 0

    for filepath in targets:
        try:
            with filepath.open("rb") as fh:
                sample = fh.read(65536)
            entropy = shannon_entropy(sample)
            size = filepath.stat().st_size
            is_flagged = entropy >= threshold

            if is_flagged:
                flagged += 1

            results.append({
                "file": str(filepath),
                "entropy": round(entropy, 4),
                "size": size,
                "flagged": is_flagged,
                "label": (
                    "ENCRYPTED/COMPRESSED" if entropy >= 7.5
                    else "HIGH" if entropy >= 6.5
                    else "MEDIUM" if entropy >= 3.0
                    else "LOW"
                ),
            })
        except OSError:
            continue

    output = {
        "source": str(source),
        "threshold": threshold,
        "files_analysed": len(results),
        "files_flagged": flagged,
        "results": sorted(results, key=lambda r: -r["entropy"]),
    }

    output_str = json.dumps(output, indent=2)
    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "entropy output")
        print(f"Entropy analysis: {flagged}/{len(results)} files above threshold {threshold}")
    else:
        print(output_str)

    return 0


def handle_fsstat(args: argparse.Namespace) -> int:
    """Handle the fsstat command — show filesystem metadata."""
    command = ["fsstat"]
    if args.offset:
        command.extend(["-o", str(args.offset)])
    command.append(str(args.image))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        print("fsstat not found — install The Sleuth Kit", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"fsstat failed: {result.stderr.strip()}", file=sys.stderr)
        return 1

    # Parse key fields into structured JSON
    fs_info: dict = {"image": str(args.image), "raw": result.stdout}
    for line in result.stdout.splitlines():
        line = line.strip()
        for key, pattern in (
            ("fs_type", r"^File System Type:\s+(.+)"),
            ("volume_name", r"^Volume Name:\s+(.+)"),
            ("volume_id", r"^Volume ID:\s+(.+)"),
            ("last_written", r"^Last Written at:\s+(.+)"),
            ("last_checked", r"^Last Checked at:\s+(.+)"),
            ("block_size", r"^Block Size:\s+(\d+)"),
            ("total_inodes", r"^Inode Range:\s+\d+\s*-\s*(\d+)"),
            ("total_blocks", r"^Block Range:\s+\d+\s*-\s*(\d+)"),
            ("free_blocks", r"^Free Blocks:\s+(\d+)"),
            ("free_inodes", r"^Free Inodes:\s+(\d+)"),
        ):
            m = re.match(pattern, line)
            if m:
                fs_info[key] = m.group(1).strip()

    print(json.dumps(fs_info, indent=2))
    return 0


def _detect_type_for_classify(filepath: Path) -> str:
    """Best-effort file type detection for classify command.

    Priority: 1) carved-output suffix pattern (_jpeg / _pdf), 2) file extension,
    3) python-magic MIME type.
    """
    # FRECE carver output filenames end with _<type>  e.g. 00000200_jpeg
    name = filepath.name
    if "_" in name:
        suffix = name.rsplit("_", 1)[-1].lower()
        if re.match(r"^[a-z0-9]{1,10}$", suffix):
            return suffix

    ext = filepath.suffix.lstrip(".").lower()
    if ext:
        # normalise common variants
        return {"jpg": "jpeg", "tif": "tiff"}.get(ext, ext)

    try:
        import magic as _magic
        mime = _magic.from_file(str(filepath), mime=True) or ""
        # e.g. "image/jpeg" → "jpeg"
        return mime.split("/")[-1].split(";")[0].strip()
    except Exception:
        return "bin"


def handle_classify(args: argparse.Namespace) -> int:
    """Handle the classify command — forensic categorisation of a directory."""
    directory = args.directory
    if not directory.is_dir():
        print(f"Not a directory: {directory}", file=sys.stderr)
        return 1

    priority_filter = args.priority
    priority_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_rank = priority_rank.get(priority_filter, 0) if priority_filter else 0

    files = sorted(f for f in directory.rglob("*") if f.is_file())
    results = []

    for filepath in files:
        ftype = _detect_type_for_classify(filepath)

        try:
            cls = classify_file(filepath, ftype)
            rank = priority_rank.get(cls.forensic_priority, 1)
            if rank < min_rank:
                continue
            results.append({
                "file": str(filepath),
                "file_type": ftype,
                "category": cls.category.value,
                "priority": cls.forensic_priority,
                "entropy": cls.entropy,
                "entropy_label": cls.entropy_label,
                "possibly_encrypted": cls.possibly_encrypted,
                "notes": cls.notes,
                "size": filepath.stat().st_size,
            })
        except Exception:
            continue

    results.sort(key=lambda r: -priority_rank.get(r["priority"], 0))

    output = {
        "directory": str(directory),
        "files_classified": len(results),
        "critical": sum(1 for r in results if r["priority"] == "CRITICAL"),
        "high": sum(1 for r in results if r["priority"] == "HIGH"),
        "encrypted_suspected": sum(1 for r in results if r["possibly_encrypted"]),
        "results": results,
    }

    output_str = json.dumps(output, indent=2)
    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "classify output")
        print(
            f"Classified {len(results)} files: "
            f"{output['critical']} CRITICAL, {output['high']} HIGH, "
            f"{output['encrypted_suspected']} possibly encrypted"
        )
    else:
        print(output_str)

    return 0



def handle_metadata(args: argparse.Namespace) -> int:
    """Handle the metadata command — deep forensic metadata extraction."""
    source = args.source
    forced_type = getattr(args, "file_type", None)

    if source.is_file():
        targets = [(source, forced_type)]
    elif source.is_dir():
        targets = [(f, None) for f in sorted(source.rglob("*")) if f.is_file()]
    else:
        print(f"Source not found: {source}", file=sys.stderr)
        return 1

    results = []
    for filepath, ftype in targets:
        if ftype is None:
            # Auto-detect: use extension or filename suffix pattern
            name = filepath.name
            if "_" in name:
                ftype = name.rsplit("_", 1)[-1].lower()
                if not re.match(r"^[a-z0-9]{1,10}$", ftype):
                    ftype = filepath.suffix.lstrip(".").lower() or "bin"
            else:
                ftype = filepath.suffix.lstrip(".").lower() or "bin"

        meta = extract_metadata(filepath, ftype)
        results.append(meta)

    output = {
        "source": str(source),
        "files_analysed": len(results),
        "results": results,
    }
    output_str = json.dumps(output, indent=2)

    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "metadata output")
        print(f"Metadata extracted for {len(results)} file(s) → {args.output}")
    else:
        print(output_str)
    return 0


def handle_score(args: argparse.Namespace) -> int:
    """Handle the score command — recovery confidence scoring."""
    manifest_path = args.manifest
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Cannot read manifest: {exc}", file=sys.stderr)
        return 1

    base_dir = manifest_path.parent

    # Support both carve_manifest and recovery_manifest
    artifacts = manifest.get("carved_files") or manifest.get("recovered_files") or []
    if not artifacts:
        print("No artifacts found in manifest", file=sys.stderr)
        return 1

    scored = score_batch(artifacts, base_dir)

    # Apply filters
    min_score = getattr(args, "min_score", 0)
    grade_filter = getattr(args, "grade", None)
    if min_score:
        scored = [a for a in scored if a.get("confidence_score", 0) >= min_score]
    if grade_filter:
        scored = [a for a in scored if a.get("confidence_grade") == grade_filter]

    # Summary stats
    grade_counts: dict[str, int] = {}
    for a in scored:
        g = a.get("confidence_grade", "UNKNOWN")
        grade_counts[g] = grade_counts.get(g, 0) + 1

    avg_score = (
        sum(a.get("confidence_score", 0) for a in scored) / len(scored)
        if scored else 0
    )

    output = {
        "manifest": str(manifest_path),
        "total_artifacts": len(artifacts),
        "filtered_artifacts": len(scored),
        "average_confidence": round(avg_score, 1),
        "grade_breakdown": grade_counts,
        "artifacts": scored,
    }

    output_str = json.dumps(output, indent=2)
    if args.output:
        _write_text_output(args.output, output_str, RecoveryError, "score output")
        print(
            f"Scored {len(scored)} artifacts: avg={avg_score:.0f} "
            f"CONFIRMED={grade_counts.get('CONFIRMED',0)} "
            f"PROBABLE={grade_counts.get('PROBABLE',0)} "
            f"POSSIBLE={grade_counts.get('POSSIBLE',0)} "
            f"SUSPECT={grade_counts.get('SUSPECT',0)} "
            f"REJECTED={grade_counts.get('REJECTED',0)}"
        )
    else:
        print(output_str)
    return 0

def resolve_case_dir(case_name: str, root: Path | None) -> Path:
    """Resolve the case directory from the configured case root."""
    config = load_config()
    case_root = root if root is not None else config.case_root
    case_root.mkdir(parents=True, exist_ok=True)
    return case_root / case_name


def load_custody_db(case_dir: Path, case_name: str | None = None) -> CustodyDatabase:
    """Load an existing custody database for a case."""
    db_path = case_dir / "custody.db"
    if not db_path.exists():
        raise CustodyError(
            f"Case database missing: {db_path}",
            remediation="Create the case first or restore the custody database.",
        )

    secret_key = get_case_secret_key(case_dir, case_name=case_name, create=False)
    return CustodyDatabase(db_path, secret_key, initialize=False)


def verify_custody_case(
    case_dir: Path,
    evidence_id: str | None,
    source_hash: str | None,
) -> int:
    """Verify custody integrity for an existing case directory."""
    custody_db = load_custody_db(case_dir, case_name=case_dir.name)
    total, tampered = custody_db.verify_database()

    result = {
        "case_dir": str(case_dir),
        "entries": total,
        "tampered": tampered,
    }

    if source_hash is not None:
        if not evidence_id:
            raise CustodyError(
                "Evidence ID required when verifying a source hash",
                remediation="Pass --evidence-id together with --source",
            )
        custody_db.verify_evidence_source(evidence_id, source_hash)
        result["source_verified"] = True
        result["evidence_id"] = evidence_id

    print(json.dumps(result, indent=2))
    return 0


def parse_case_details(
    details_json: str | None,
    repeated_details: list[str],
    extras: list[str],
) -> dict:
    """Parse JSON, repeated --detail, and passthrough --key value arguments."""
    details = {}

    if details_json:
        try:
            details.update(json.loads(details_json))
        except json.JSONDecodeError as exc:
            raise CustodyError(
                "Invalid JSON supplied to --details",
                remediation="Pass valid JSON such as --details '{\"source\": \"/dev/sda\"}'",
            ) from exc

    for item in repeated_details:
        InputValidator.validate_string_arg(item, arg_name="detail")
        if "=" not in item:
            raise CustodyError(
                f"Invalid --detail value: {item}",
                remediation="Use --detail key=value",
            )
        key, value = item.split("=", 1)
        details[key] = value

    index = 0
    while index < len(extras):
        token = extras[index]
        InputValidator.validate_string_arg(token, arg_name="detail flag")
        if not token.startswith("--"):
            raise CustodyError(
                f"Unexpected case detail token: {token}",
                remediation="Use --key value pairs after 'frece case log ...'",
            )

        key = token[2:].replace("-", "_")
        if index + 1 < len(extras) and not extras[index + 1].startswith("--"):
            details[key] = InputValidator.validate_string_arg(
                extras[index + 1],
                arg_name=key,
            )
            index += 2
            continue

        details[key] = True
        index += 1

    return details


if __name__ == "__main__":
    sys.exit(main())
