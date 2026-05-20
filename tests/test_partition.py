"""Tests for partition discovery."""

from unittest.mock import MagicMock, patch

import pytest

from frece.errors import RecoveryError
from frece.partition import list_partitions


def test_list_partitions_parses_mmls_output(temp_dir):
    sample_output = (
        "DOS Partition Table\n"
        "Offset Sector: 0\n"
        "Units are in 512-byte sectors\n"
        "001:  000:000  0002048  0004095  0002048  Linux (0x83)\n"
    )

    with patch("frece.partition.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=sample_output, stderr="")
        partitions = list_partitions(temp_dir / "disk.dd")

    assert len(partitions) == 1
    assert partitions[0].start_sector == 2048
    assert "Linux" in partitions[0].description


def test_list_partitions_missing_tool_raises(temp_dir):
    with patch("frece.partition.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(RecoveryError, match="mmls"):
            list_partitions(temp_dir / "disk.dd")
