# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
"""Unit tests for config module."""
from pathlib import Path
from frece.config import Config, load_config

def test_default_config_has_case_root():
    c = Config()
    assert c.case_root is not None
    assert isinstance(c.case_root, Path)

def test_load_config_missing_file_returns_defaults():
    cfg = load_config(Path("/nonexistent/config.toml"))
    assert cfg.default_hash == "sha256"

def test_load_config_tilde_expanded(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[tool.frece]\ncase_root = "~/.frece_test"\n')
    cfg = load_config(cfg_file)
    assert "~" not in str(cfg.case_root)

def test_ensure_case_root_creates_dir(tmp_path):
    cfg = Config()
    cfg.case_root = tmp_path / "cases"
    assert not cfg.case_root.exists()
    cfg.ensure_case_root()
    assert cfg.case_root.exists()

def test_load_config_chunk_size(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[tool.frece]\nchunk_size = 134217728\n')
    cfg = load_config(cfg_file)
    assert cfg.chunk_size == 134217728

def test_load_config_max_video_size(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[tool.frece]\nmax_video_size = 1073741824\n')
    cfg = load_config(cfg_file)
    assert cfg.max_video_size == 1073741824
