"""Evidence acquisition with write-block enforcement."""

import hashlib
import json
import logging
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from frece.config import Config, load_config
from frece.errors import AcquisitionError
from frece.sandbox import SandboxedExecutor


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AcquisitionBatchResult(dict):
    """Batch acquisition result with explicit failure tracking.

    The object stores ``{"acquired": ..., "failed": ...}`` while keeping
    ``len()`` and ``values()`` aligned with the acquired set for older callers.
    """

    def __init__(self, acquired: dict[str, dict], failed: dict[str, str]):
        super().__init__({"acquired": acquired, "failed": failed})

    def __len__(self) -> int:
        return len(super().__getitem__("acquired"))

    def values(self):
        return super().__getitem__("acquired").values()


class WriteBlockChecker:
    """Check if target device is write-protected."""

    @staticmethod
    def _candidate_block_devices(device: str) -> list[str]:
        """Return candidate /sys/block device names for a device path."""
        device_name = Path(device).name
        candidates = [device_name]

        patterns = (
            r"^(nvme\d+n\d+)p\d+$",
            r"^(mmcblk\d+)p\d+$",
            r"^(loop\d+)p\d+$",
            r"^((?:sd|vd|xvd|hd)[a-z]+)\d+$",
        )

        for pattern in patterns:
            match = re.match(pattern, device_name)
            if match:
                candidates.append(match.group(1))
                break

        unique_candidates = []
        for candidate in candidates:
            if candidate not in unique_candidates:
                unique_candidates.append(candidate)
        return unique_candidates

    @staticmethod
    def is_writeblock_enabled(device: str) -> bool:
        """Check if device is write-protected.

        On Linux, reads /sys/block/<device>/ro.

        Args:
            device: Device name (e.g., 'sda1' or 'sdb').

        Returns:
            True if device is read-only (write-protected).

        Raises:
            AcquisitionError: If check fails.
        """
        for device_name in WriteBlockChecker._candidate_block_devices(device):
            try:
                ro_path = Path(f"/sys/block/{device_name}/ro")
                if ro_path.exists():
                    ro_value = int(ro_path.read_text().strip())
                    return ro_value == 1
            except (OSError, ValueError):
                pass

        return False

    @staticmethod
    def require_writeblock(device: str, force: bool = False) -> None:
        """Enforce write-block requirement.

        Args:
            device: Device path.
            force: If True, skip check (with disclaimer).

        Raises:
            AcquisitionError: If write-block not enabled and force=False.
        """
        if force:
            return

        if not WriteBlockChecker.is_writeblock_enabled(device):
            raise AcquisitionError(
                f"Device {device} is NOT write-protected",
                remediation=(
                    "STOP. Use a hardware write-blocker or --force-no-writeblock "
                    "with legal approval and signed disclaimer."
                ),
            )


class EvidenceAcquisition:
    """Acquire evidence with hash logging."""

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        config: Optional[Config] = None,
    ):
        self.logger = logger or logging.getLogger(__name__)
        self.config = config or load_config()
        self.executor = SandboxedExecutor(logger)

    @staticmethod
    def _assert_safe_output_target(source: str, output_path: Path) -> None:
        """Reject source/output combinations that can overwrite evidence."""
        try:
            resolved_source = Path(source).resolve()
        except OSError:
            resolved_source = Path(source)

        try:
            resolved_output = output_path.resolve()
        except OSError:
            resolved_output = output_path

        if resolved_source == resolved_output:
            raise AcquisitionError(
                "Output path is the same file as the source",
                remediation="Choose a different output location.",
            )

        try:
            src_stat = os.stat(source)
            if resolved_output.exists():
                out_stat = os.stat(resolved_output)
                if src_stat.st_ino == out_stat.st_ino and src_stat.st_dev == out_stat.st_dev:
                    raise AcquisitionError(
                        "Output is a hard-link alias of the source",
                        remediation="Choose a different output location.",
                    )
        except OSError:
            pass

        try:
            if resolved_output.exists():
                output_mode = resolved_output.stat().st_mode
                if stat.S_ISBLK(output_mode):
                    raise AcquisitionError(
                        f"Output path {output_path} is a block device",
                        remediation="Specify a regular file path for the output image.",
                    )
                if stat.S_ISCHR(output_mode) or stat.S_ISFIFO(output_mode) or stat.S_ISSOCK(
                    output_mode
                ):
                    raise AcquisitionError(
                        f"Output path {output_path} is a special device",
                        remediation="Specify a regular file path for the output image.",
                    )
        except OSError:
            pass

    def acquire_device(
        self,
        source: str,
        output_path: Path,
        writeblock_required: bool = True,
        force_no_writeblock: bool = False,
    ) -> dict:
        """Acquire device image with hashing.

        Args:
            source: Source device path.
            output_path: Output image file.
            writeblock_required: If True, enforce write-block.
            force_no_writeblock: Override write-block requirement.

        Returns:
            Acquisition metadata dict with hashes.

        Raises:
            AcquisitionError: If acquisition fails.
        """
        if writeblock_required and not force_no_writeblock:
            WriteBlockChecker.require_writeblock(source, force=False)

        self._assert_safe_output_target(source, output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"Starting acquisition from {source} to {output_path}")

        try:
            with open(source, "rb") as src, open(output_path, "wb") as dst:
                sha256_hash = hashlib.sha256()
                md5_hash = hashlib.md5()
                bytes_written = 0
                chunk_size = self.config.chunk_size

                while chunk := src.read(chunk_size):
                    dst.write(chunk)
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    bytes_written += len(chunk)

                    if bytes_written % (100 * 1024 * 1024) == 0:
                        self.logger.info(f"Acquired {bytes_written / (1024**3):.2f} GB")

                dst.flush()
                os.fsync(dst.fileno())

        except FileNotFoundError as e:
            raise AcquisitionError(
                f"Source not found: {source}",
                remediation="Verify device path is correct",
            ) from e
        except PermissionError as e:
            raise AcquisitionError(
                f"Permission denied: {source}",
                remediation="Run with sudo or check permissions",
            ) from e
        except OSError as e:
            raise AcquisitionError(
                f"Acquisition failed: {e}",
                remediation="Check disk space and device status",
            ) from e

        metadata = {
            "source": source,
            "output_file": str(output_path),
            "timestamp": _utc_now_iso(),
            "bytes_acquired": bytes_written,
            "sha256": sha256_hash.hexdigest(),
            "md5": md5_hash.hexdigest(),
        }

        self.logger.info(
            json.dumps(
                {
                    "event": "ACQUISITION_COMPLETE",
                    "source": source,
                    "bytes": bytes_written,
                    "sha256": metadata["sha256"],
                }
            )
        )

        return metadata

    def hash_file(
        self,
        file_path: Path,
        algorithms: tuple[str, ...] = ("sha256", "sha1", "md5"),
    ) -> dict:
        """Hash an evidence file with one or more algorithms."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise AcquisitionError(
                f"File not found: {file_path}",
                remediation="Verify the file path",
            )

        if not algorithms:
            raise AcquisitionError(
                "No hash algorithms provided",
                remediation="Specify at least one hash algorithm",
            )

        try:
            hashers = {alg: hashlib.new(alg) for alg in algorithms}
        except ValueError as e:
            raise AcquisitionError(
                f"Unsupported hash algorithm: {e}",
                remediation="Use algorithms supported by hashlib, such as sha256, sha1, or md5",
            ) from e

        size = 0
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    size += len(chunk)
                    for hasher in hashers.values():
                        hasher.update(chunk)
        except OSError as e:
            raise AcquisitionError(
                f"Cannot read {file_path}",
                remediation="Check file permissions",
            ) from e

        result = {
            "source": str(file_path),
            "size_bytes": size,
            "timestamp": _utc_now_iso(),
        }
        for alg, hasher in hashers.items():
            result[alg] = hasher.hexdigest()

        self.logger.info(
            json.dumps(
                {
                    "event": "HASH_COMPLETE",
                    "source": str(file_path),
                    "sha256": result.get("sha256", ""),
                    "size_bytes": size,
                    "timestamp": result["timestamp"],
                }
            )
        )
        return result

    def acquire_files(
        self,
        sources: list[Path],
        output_dir: Path,
        recursive: bool = False,
    ) -> AcquisitionBatchResult:
        """Acquire multiple files with hashing.

        Args:
            sources: List of source file/directory paths.
            output_dir: Output directory.
            recursive: If True, recurse into directories.

        Returns:
            Batch result with acquired-file metadata and surfaced failures.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        acquired: dict[str, dict] = {}
        failed: dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            for source in sources:
                source_path = Path(source)

                if source_path.is_file():
                    future = executor.submit(
                        self._acquire_single_file, source_path, output_dir
                    )
                    futures[str(source_path)] = future
                elif source_path.is_dir() and recursive:
                    for file_path in source_path.rglob("*"):
                        if file_path.is_file():
                            future = executor.submit(
                                self._acquire_single_file, file_path, output_dir
                            )
                            futures[str(file_path)] = future
                else:
                    failed[str(source_path)] = (
                        "Source not found or unsupported for acquisition"
                    )
                    self.logger.error(
                        json.dumps(
                            {
                                "event": "ACQUIRE_FAILED",
                                "source": str(source_path),
                                "reason": failed[str(source_path)],
                            }
                        )
                    )

            for source_str, future in futures.items():
                try:
                    acquired[source_str] = future.result()
                except AcquisitionError as exc:
                    failed[source_str] = exc.message
                    self.logger.error(
                        json.dumps(
                            {
                                "event": "ACQUIRE_FAILED",
                                "source": source_str,
                                "reason": exc.message,
                            }
                        )
                    )
                except Exception as exc:
                    failed[source_str] = str(exc)
                    self.logger.error(
                        json.dumps(
                            {
                                "event": "ACQUIRE_FAILED",
                                "source": source_str,
                                "reason": str(exc),
                            }
                        )
                    )

        return AcquisitionBatchResult(acquired, failed)

    def _acquire_single_file(self, source_path: Path, output_dir: Path) -> dict:
        """Acquire a single file with hashing.

        Streams the source file exactly once: hashes and copies simultaneously,
        avoiding the two-pass read that the original implementation used.
        Uses a unique temp name to be safe under parallel acquisition.

        Args:
            source_path: Source file path.
            output_dir: Output directory.

        Returns:
            File metadata dict.
        """
        import uuid

        sha256_hash = hashlib.sha256()
        # Unique temp name so parallel acquisitions never collide on the same path
        tmp_path = output_dir / f".acquiring_{uuid.uuid4().hex}_{source_path.name}.tmp"

        try:
            with open(source_path, "rb") as src, open(tmp_path, "wb") as dst:
                while chunk := src.read(self.config.chunk_size):
                    sha256_hash.update(chunk)
                    dst.write(chunk)
                dst.flush()
                os.fsync(dst.fileno())
        except OSError as e:
            tmp_path.unlink(missing_ok=True)
            if isinstance(e, FileNotFoundError):
                raise AcquisitionError(
                    f"Source not found: {source_path}",
                    remediation="Verify the file path",
                ) from e
            raise AcquisitionError(
                f"Cannot acquire {source_path}",
                remediation="Check file permissions and disk space",
            ) from e

        partial_hex = sha256_hash.hexdigest()[:8]
        output_file = output_dir / f"{partial_hex}_{source_path.name}"

        try:
            os.replace(tmp_path, output_file)
        except OSError as e:
            tmp_path.unlink(missing_ok=True)
            raise AcquisitionError(
                f"Cannot rename acquired file to {output_file}",
                remediation="Check output directory permissions and disk space",
            ) from e

        return {
            "source": str(source_path),
            "output_file": str(output_file),
            "sha256": sha256_hash.hexdigest(),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
