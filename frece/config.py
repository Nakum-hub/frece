"""Configuration and constants."""

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """FRECE configuration."""

    max_ram_per_operation: int = 64 * 1024 * 1024  # 64 MB
    default_hash: str = "sha256"
    case_root: Path = Path.home() / ".frece" / "cases"
    writeblock_required: bool = True
    chunk_size: int = 64 * 1024 * 1024  # 64 MB default chunk
    max_signature_length: int = 2048  # Max bytes to overlap between chunks
    max_video_size: int = 0  # 0 = unlimited
    max_path_length: int = 4096
    max_case_name_length: int = 255


def load_config(config_path: Path = Path.home() / ".frece" / "config.toml") -> Config:
    """Load configuration from TOML file.

    Args:
        config_path: Path to config.toml file.

    Returns:
        Config object with values from file or defaults.
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
                config.case_root = Path(frece_config["case_root"])
            if "writeblock_required" in frece_config:
                config.writeblock_required = frece_config["writeblock_required"]
            if "chunk_size" in frece_config:
                config.chunk_size = frece_config["chunk_size"]
            if "max_signature_length" in frece_config:
                config.max_signature_length = frece_config["max_signature_length"]
            if "max_video_size" in frece_config:
                config.max_video_size = frece_config["max_video_size"]

    config.case_root.mkdir(parents=True, exist_ok=True)
    return config


DEFAULT_CONFIG = Config()
