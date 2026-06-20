# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential.
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
        # "mmls" is a standard Sleuth Kit tool expected on PATH.
        # Partial path is intentional for operator PATH flexibility.
        result = subprocess.run(  # nosec B603 B607
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
        stderr_msg = result.stderr.strip()
        if not stderr_msg:
            stderr_msg = (
                "mmls could not detect a partition table. "
                "The image may be a raw filesystem without a partition table. "
                "Use 'frece recover' or 'frece scan' directly on the image, "
                "or specify the filesystem offset with --offset."
            )
        raise RecoveryError(
            f"mmls failed: {stderr_msg}",
            remediation=(
                "Verify the image path and format. "
                "If this is a raw filesystem image (ext2/3/4, NTFS) without a "
                "partition table, 'frece partitions' does not apply – use "
                "'frece scan' or 'frece recover' directly."
            ),
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
