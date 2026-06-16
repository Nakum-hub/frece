# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential. Unauthorized use, copying, modification, or distribution is prohibited.
"""Configuration and constants."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def _default_case_root() -> Path:
    return Path.home() / ".frece" / "cases"


@dataclass
class Config:
    """FRECE configuration."""

    max_ram_per_operation: int = 64 * 1024 * 1024  # 64 MB
    default_hash: str = "sha256"
    case_root: Path = field(default_factory=_default_case_root)
    writeblock_required: bool = True
    chunk_size: int = 64 * 1024 * 1024  # 64 MB default chunk
    max_signature_length: int = 2048  # Max bytes to overlap between chunks
    max_video_size: int = 0  # 0 = unlimited
    max_icat_timeout: int = 0  # 0 = unlimited
    max_fls_timeout: int = 0  # 0 = unlimited
    max_path_length: int = 4096
    max_case_name_length: int = 255

    def ensure_case_root(self) -> None:
        """Create the case root directory on demand (not on every load)."""
        self.case_root.mkdir(parents=True, exist_ok=True)


def load_config(config_path: Path = Path.home() / ".frece" / "config.toml") -> Config:
    """Load configuration from TOML file.

    Args:
        config_path: Path to config.toml file.

    Returns:
        Config object with values from file or defaults.
        Note: does NOT create directories as a side-effect; call
        config.ensure_case_root() only when a case directory is actually needed.
    """
    config = Config()

    if config_path.exists():
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
            frece_config = data.get("tool", {}).get("frece", {})

            if "max_ram_per_operation" in frece_config:
                config.max_ram_per_operation = frece_config["max_ram_per_operation"]
            if "default_hash" in frece_config:
                config.default_hash = frece_config["default_hash"]
            if "case_root" in frece_config:
                # expanduser() so that "~/.frece/cases" in config.toml works correctly
                config.case_root = Path(frece_config["case_root"]).expanduser()
            if "writeblock_required" in frece_config:
                config.writeblock_required = frece_config["writeblock_required"]
            if "chunk_size" in frece_config:
                config.chunk_size = frece_config["chunk_size"]
            if "max_signature_length" in frece_config:
                config.max_signature_length = frece_config["max_signature_length"]
            if "max_video_size" in frece_config:
                config.max_video_size = frece_config["max_video_size"]
            if "max_icat_timeout" in frece_config:
                config.max_icat_timeout = frece_config["max_icat_timeout"]
            if "max_fls_timeout" in frece_config:
                config.max_fls_timeout = frece_config["max_fls_timeout"]

    return config


DEFAULT_CONFIG = Config()
