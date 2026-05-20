"""Partition table discovery using mmls."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from frece.errors import RecoveryError


@dataclass
class Partition:
    """One partition row returned by mmls."""

    slot: str
    start_sector: int
    end_sector: int
    length_sectors: int
    description: str


def list_partitions(image_path: Path) -> list[Partition]:
    """Run mmls and return parsed partition descriptors."""
    try:
        result = subprocess.run(
            ["mmls", str(image_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RecoveryError(
            "Tool not found: mmls",
            remediation="Install The Sleuth Kit: apt-get install sleuthkit",
        ) from exc

    if result.returncode != 0:
        raise RecoveryError(
            f"mmls failed: {result.stderr.strip()}",
            remediation="Verify image path and format",
        )

    partitions: list[Partition] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\d+):\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)", line)
        if match:
            partitions.append(
                Partition(
                    slot=match.group(1),
                    start_sector=int(match.group(2)),
                    end_sector=int(match.group(3)),
                    length_sectors=int(match.group(4)),
                    description=match.group(5).strip(),
                )
            )

    return partitions
