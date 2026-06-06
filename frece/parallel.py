# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
"""Parallel execution with appropriate executor selection."""

import hashlib
import inspect
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Any, Optional

from frece.errors import FreceError


class ParallelProcessor:
    """Execute operations in parallel with smart executor selection."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

    def hash_files_parallel(
        self,
        files: list[Path],
        chunk_size: int = 1024 * 1024,
        max_workers: int = 4,
    ) -> dict[str, str]:
        """Hash multiple files in parallel using threads (I/O-bound).

        Args:
            files: List of file paths to hash.
            chunk_size: Read chunk size.
            max_workers: Number of worker threads.

        Returns:
            Dict mapping file path to SHA256 hex digest.
        """
        hashes = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._hash_file, f, chunk_size): f for f in files
            }

            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    file_hash = future.result()
                    hashes[str(file_path)] = file_hash
                except Exception as e:
                    self.logger.error(f"Hashing failed for {file_path}: {e}")

        return hashes

    def carve_files_parallel(
        self,
        chunks: list[tuple[int, bytes]],
        signature_finder: Callable,
        max_workers: int = 4,
    ) -> list[tuple[int, str]]:
        """Carve signatures from chunks in parallel using threads.

        Args:
            chunks: List of (offset, chunk_data) tuples.
            signature_finder: Callable that finds signatures in data.
            max_workers: Number of worker threads.

        Returns:
            List of (offset, signature_type) tuples.
        """
        all_signatures = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._run_signature_finder, signature_finder, offset, chunk
                ): (offset, chunk)
                for offset, chunk in chunks
            }

            for future in as_completed(futures):
                try:
                    signatures = future.result()
                    all_signatures.extend(signatures)
                except Exception as e:
                    offset, chunk = futures[future]
                    self.logger.error(f"Carving failed for chunk at {offset}: {e}")

        return sorted(all_signatures, key=lambda x: x[0])

    def apply_to_files(
        self,
        func: Callable[[Path], Any],
        files: list[Path],
        max_workers: int = 4,
        is_cpu_bound: bool = False,
    ) -> dict[str, Any]:
        """Apply function to files in parallel.

        Uses ThreadPoolExecutor for I/O-bound, ProcessPoolExecutor for CPU-bound.

        Args:
            func: Function to apply (takes Path, returns value).
            files: List of file paths.
            max_workers: Number of workers.
            is_cpu_bound: If True, use ProcessPoolExecutor.

        Returns:
            Dict mapping file path to result.
        """
        results = {}

        executor_class = ProcessPoolExecutor if is_cpu_bound else ThreadPoolExecutor

        try:
            with executor_class(max_workers=max_workers) as executor:
                futures = {executor.submit(func, f): f for f in files}

                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        result = future.result()
                        results[str(file_path)] = result
                    except Exception as e:
                        self.logger.error(f"Operation failed for {file_path}: {e}")

        except Exception as e:
            raise FreceError(
                f"Parallel execution failed: {e}",
                remediation="Check worker configuration",
            )

        return results

    def _hash_file(self, file_path: Path, chunk_size: int) -> str:
        """Hash a single file.

        Args:
            file_path: Path to file.
            chunk_size: Read chunk size.

        Returns:
            SHA256 hex digest.
        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _run_signature_finder(
        self,
        signature_finder: Callable,
        offset: int,
        chunk: bytes,
    ) -> list[tuple[int, str]]:
        """Call the signature finder using its declared parameter order."""
        params = list(inspect.signature(signature_finder).parameters)
        if params and params[0] in {"data", "chunk", "buffer"}:
            result = signature_finder(chunk, offset)
        else:
            result = signature_finder(offset, chunk)

        return list(result)
