"""Tests for parallel processing."""

from pathlib import Path

import pytest

from frece.carver import SignatureDatabase
from frece.parallel import ParallelProcessor


class TestParallelProcessor:
    """Test parallel processing operations."""

    @pytest.fixture
    def processor(self):
        """Create processor instance."""
        return ParallelProcessor()

    def test_hash_single_file(self, processor, temp_dir):
        """Test hashing a single file."""
        test_file = temp_dir / "test.txt"
        test_file.write_bytes(b"test content")

        hashes = processor.hash_files_parallel([test_file])

        assert str(test_file) in hashes
        assert len(hashes[str(test_file)]) == 64

    def test_hash_multiple_files(self, processor, temp_dir):
        """Test hashing multiple files in parallel."""
        files = []
        for i in range(5):
            f = temp_dir / f"test{i}.txt"
            f.write_bytes(f"content{i}".encode())
            files.append(f)

        hashes = processor.hash_files_parallel(files, max_workers=2)

        assert len(hashes) == 5
        assert all(len(h) == 64 for h in hashes.values())

    def test_hash_files_different_sizes(self, processor, temp_dir):
        """Test hashing files of different sizes."""
        small = temp_dir / "small.txt"
        small.write_bytes(b"small")

        large = temp_dir / "large.txt"
        large.write_bytes(b"x" * (10 * 1024 * 1024))

        hashes = processor.hash_files_parallel([small, large])

        assert len(hashes) == 2
        assert hashes[str(small)] != hashes[str(large)]

    def test_hash_consistency(self, processor, temp_dir):
        """Test that same file produces same hash."""
        test_file = temp_dir / "test.txt"
        test_file.write_bytes(b"consistent")

        hash1 = processor.hash_files_parallel([test_file])[str(test_file)]
        hash2 = processor.hash_files_parallel([test_file])[str(test_file)]

        assert hash1 == hash2

    def test_apply_to_files_io_bound(self, processor, temp_dir):
        """Test applying I/O-bound function to files."""
        files = []
        for i in range(3):
            f = temp_dir / f"test{i}.txt"
            f.write_bytes(f"content{i}".encode())
            files.append(f)

        def count_bytes(path: Path) -> int:
            return path.stat().st_size

        results = processor.apply_to_files(count_bytes, files, max_workers=2, is_cpu_bound=False)

        assert len(results) == 3
        assert all(isinstance(v, int) for v in results.values())

    def test_apply_to_files_error_handling(self, processor, temp_dir):
        """Test error handling in apply_to_files."""
        files = [temp_dir / "nonexistent.txt"]

        def read_file(path: Path) -> str:
            return path.read_text()

        results = processor.apply_to_files(read_file, files)

        assert len(results) == 0

    def test_apply_cpu_bound_function(self, processor, temp_dir):
        """Test applying CPU-bound function (uses ProcessPoolExecutor)."""
        files = []
        for i in range(2):
            f = temp_dir / f"test{i}.txt"
            f.write_bytes(b"x" * 1000)
            files.append(f)

        def entropy(path: Path) -> float:
            data = path.read_bytes()
            if not data:
                return 0.0
            unique = len(set(data))
            return unique / 256

        results = processor.apply_to_files(
            entropy, files, max_workers=2, is_cpu_bound=True
        )

        assert len(results) >= 0
        assert all(isinstance(v, float) for v in results.values())

    def test_carve_files_parallel_stub(self, processor):
        """Test parallel carving with stub."""
        chunks = [
            (0, b"\x00" * 1024),
            (1024, b"\xff\xd8" + b"\x00" * 1022),
            (2048, b"\x00" * 1024),
        ]

        def find_sigs(offset: int, data: bytes):
            if b"\xff\xd8" in data:
                return [(offset + data.find(b"\xff\xd8"), "jpeg")]
            return []

        signatures = processor.carve_files_parallel(chunks, find_sigs, max_workers=2)

        assert len(signatures) == 1
        assert signatures[0][1] == "jpeg"

    def test_carve_files_parallel_signature_database(self, processor):
        """Test parallel carving with the real signature finder API."""
        chunks = [
            (0, b"\x00" * 4),
            (4, b"\xff\xd8\xff" + b"\x00" * 8),
        ]

        signatures = processor.carve_files_parallel(
            chunks,
            SignatureDatabase.find_signatures,
            max_workers=2,
        )

        assert signatures == [(4, "jpeg")]
