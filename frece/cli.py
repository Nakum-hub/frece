"""FRECE CLI entrypoint."""

import argparse
import json
import getpass
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from frece import __version__
from frece.acquisition import EvidenceAcquisition
from frece.carver import StreamingCarver
from frece.config import load_config
from frece.custody import CustodyDatabase, create_case_secret_key, get_case_secret_key
from frece.errors import CustodyError, FreceError
from frece.logging import setup_logging
from frece.recovery import DeletedFileRecovery
from frece.sandbox import InputValidator


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

    if args.command == "hash":
        args.source = InputValidator.validate_path(str(args.source))
        if args.output is not None:
            args.output = InputValidator.validate_path(str(args.output))
        return

    if args.command == "acquire":
        args.source = str(InputValidator.validate_path(args.source))
        args.output = InputValidator.validate_path(str(args.output))
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
        choices=["json", "text"],
        default="json",
        dest="report_format",
    )

    return parser


def check_tools() -> int:
    """Check availability of required tools."""
    tools_to_check = {
        "fls": (["fls", "-V"], "The Sleuth Kit"),
        "icat": (["icat", "-V"], "The Sleuth Kit"),
        "istat": (["istat", "-V"], "The Sleuth Kit"),
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

    if all_found:
        print("\nAll required tools found!")
        return 0

    print("\nSome tools are missing. Install The Sleuth Kit and GNU file/coreutils.")
    return 1


def handle_carve(args: argparse.Namespace) -> int:
    """Handle the carve command."""
    config = load_config()
    if args.chunk_size is not None:
        config.chunk_size = args.chunk_size
    if args.max_signature_length is not None:
        config.max_signature_length = args.max_signature_length

    carver = StreamingCarver(config)
    manifest = carver.carve(args.source, args.output, verify=not args.no_verify)

    output = manifest.to_dict()
    output["manifest_path"] = str(args.output / "carve_manifest.json")
    output["files_carved"] = len(manifest.carved_files)
    print(json.dumps(output, indent=2))
    return 0


def handle_recover(args: argparse.Namespace) -> int:
    """Handle the recover command."""
    logger = setup_logging(args.log_dir, name="frece.recovery")
    recovery = DeletedFileRecovery(logger)

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
    acquisition = EvidenceAcquisition(setup_logging(name="frece.acquire"))
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
    recovery = DeletedFileRecovery(logger)
    entries = recovery.scan_deleted(args.image, image_offset=args.offset)

    if args.filter_type:
        filter_type = args.filter_type.lower()
        entries = [entry for entry in entries if entry.entry_type == filter_type]

    data = {
        "source": str(args.image),
        "timestamp": _utc_now_iso(),
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
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_str)
        print(f"Scan saved to {args.output} ({len(entries)} deleted entries)")
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
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_str)
        print(f"Hash written to {args.output}")
    else:
        print(output_str)

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
        create_case_secret_key(case_dir)
        CustodyDatabase(case_dir / "custody.db", get_case_secret_key(case_dir))
        print(json.dumps({"case_dir": str(case_dir)}, indent=2))
        return 0

    if args.case_command == "log":
        case_dir = resolve_case_dir(args.case_name, args.root)
        custody_db = load_custody_db(case_dir)
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

    raise CustodyError(
        "Missing case subcommand",
        remediation="Use 'frece case create|log|verify ...'",
    )


def handle_report(args: argparse.Namespace) -> int:
    """Handle the report command - consolidated case summary."""
    case_dir = resolve_case_dir(args.case_name, args.root)
    if not case_dir.exists():
        print(f"Case directory not found: {case_dir}", file=sys.stderr)
        return 1

    report: dict = {
        "case_name": args.case_name,
        "case_dir": str(case_dir),
        "generated_at": _utc_now_iso(),
        "custody_entries": 0,
        "carve_manifests": [],
        "recovery_manifests": [],
    }

    db_path = case_dir / "custody.db"
    if db_path.exists():
        try:
            custody_db = load_custody_db(case_dir)
            total, _ = custody_db.verify_database()
            report["custody_entries"] = total
            report["custody_verified"] = True
        except Exception as exc:
            report["custody_verified"] = False
            report["custody_error"] = str(exc)

    for manifest_path in sorted(case_dir.rglob("carve_manifest.json")):
        try:
            report["carve_manifests"].append(json.loads(manifest_path.read_text()))
        except Exception:
            pass

    for manifest_path in sorted(case_dir.rglob("recovery_manifest.json")):
        try:
            report["recovery_manifests"].append(json.loads(manifest_path.read_text()))
        except Exception:
            pass

    if args.report_format == "text":
        lines = [
            f"Case Report: {args.case_name}",
            f"Generated:   {report['generated_at']}",
            f"Case dir:    {report['case_dir']}",
            f"Custody entries: {report['custody_entries']}",
            f"Carve manifests: {len(report['carve_manifests'])}",
            f"Recovery manifests: {len(report['recovery_manifests'])}",
        ]
        for carve_manifest in report["carve_manifests"]:
            carved = carve_manifest.get("carved_files", [])
            lines.append(
                f"  Carve: {carve_manifest.get('source', '?')} -> {len(carved)} files"
            )
        for recovery_manifest in report["recovery_manifests"]:
            recovered = recovery_manifest.get("recovered_files", [])
            lines.append(
                f"  Recovery: {recovery_manifest.get('source', '?')} -> {len(recovered)} files"
            )
        output_str = "\n".join(lines)
    else:
        output_str = json.dumps(report, indent=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_str)
        if args.report_format == "text":
            print(f"Report written to {args.output}")
        else:
            print(f"Report written to {args.output}")
    else:
        print(output_str)

    return 0


def resolve_case_dir(case_name: str, root: Path | None) -> Path:
    """Resolve the case directory from the configured case root."""
    config = load_config()
    case_root = root if root is not None else config.case_root
    return case_root / case_name


def load_custody_db(case_dir: Path) -> CustodyDatabase:
    """Load an existing custody database for a case."""
    db_path = case_dir / "custody.db"
    if not db_path.exists():
        raise CustodyError(
            f"Case database missing: {db_path}",
            remediation="Create the case first or restore the custody database.",
        )

    secret_key = get_case_secret_key(case_dir, create=False)
    return CustodyDatabase(db_path, secret_key, initialize=False)


def verify_custody_case(
    case_dir: Path,
    evidence_id: str | None,
    source_hash: str | None,
) -> int:
    """Verify custody integrity for an existing case directory."""
    custody_db = load_custody_db(case_dir)
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
