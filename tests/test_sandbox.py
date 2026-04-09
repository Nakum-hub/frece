"""Tests for sandbox execution and input validation."""

import sys
import subprocess
from pathlib import Path

import pytest

from frece.sandbox import InputValidator, SandboxedExecutor
from frece.errors import SandboxError


class TestInputValidator:
    """Test input validation."""

    def test_validate_path_length(self):
        """Test path length validation."""
        valid_path = "a" * 100
        result = InputValidator.validate_path(valid_path)

        assert isinstance(result, Path)

    def test_validate_path_too_long(self):
        """Test rejection of overly long paths."""
        too_long = "a" * 5000

        with pytest.raises(SandboxError):
            InputValidator.validate_path(too_long, max_length=1000)

    def test_validate_path_dangerous_chars(self):
        """Test rejection of dangerous characters in paths."""
        dangerous_paths = [
            "path|to|file",
            "path;rm -rf /",
            "path`whoami`",
            "path$(id)",
            "path(command)",
        ]

        for path in dangerous_paths:
            with pytest.raises(SandboxError):
                InputValidator.validate_path(path)

    def test_validate_case_name_valid(self):
        """Test valid case names."""
        valid_name = "Case-001_Test"
        result = InputValidator.validate_case_name(valid_name)

        assert result == valid_name

    def test_validate_case_name_too_long(self):
        """Test rejection of overly long case names."""
        too_long = "a" * 300

        with pytest.raises(SandboxError):
            InputValidator.validate_case_name(too_long)

    def test_validate_case_name_dangerous(self):
        """Test rejection of dangerous case names."""
        dangerous_names = [
            "case|command",
            "case;rm -rf /",
            "case`whoami`",
        ]

        for name in dangerous_names:
            with pytest.raises(SandboxError):
                InputValidator.validate_case_name(name)

    def test_validate_string_arg(self):
        """Test generic string argument validation."""
        result = InputValidator.validate_string_arg("test_arg")

        assert result == "test_arg"

    def test_validate_string_arg_custom_length(self):
        """Test custom length limit."""
        with pytest.raises(SandboxError):
            InputValidator.validate_string_arg("toolong", max_length=5)

    def test_validate_string_arg_custom_name(self):
        """Test custom argument name in error."""
        with pytest.raises(SandboxError) as exc_info:
            InputValidator.validate_string_arg("x" * 100, max_length=50, arg_name="custom_arg")

        assert "custom_arg" in str(exc_info.value)


class TestSandboxedExecutor:
    """Test sandboxed command execution."""

    @pytest.fixture
    def executor(self):
        """Create executor instance."""
        return SandboxedExecutor()

    def test_run_safe_command(self, executor):
        """Test running a safe command."""
        result = executor.run_command(
            [sys.executable, "-c", "print('hello')"],
            timeout=10,
        )

        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_run_command_timeout(self, executor):
        """Test command timeout handling."""
        with pytest.raises(subprocess.TimeoutExpired):
            executor.run_command(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=1,
            )

    def test_dangerous_command_rm(self, executor):
        """Test rejection of dangerous rm command."""
        with pytest.raises(SandboxError):
            executor.run_command(["rm", "-rf", "/tmp/test"])

    def test_dangerous_command_dd(self, executor):
        """Test rejection of dangerous dd command."""
        with pytest.raises(SandboxError):
            executor.run_command(["dd", "if=/dev/zero", "of=/dev/sda"])

    def test_dangerous_command_mkfs(self, executor):
        """Test rejection of dangerous mkfs command."""
        with pytest.raises(SandboxError):
            executor.run_command(["mkfs", "/dev/sda1"])

    def test_dangerous_command_fdisk(self, executor):
        """Test rejection of dangerous fdisk command."""
        with pytest.raises(SandboxError):
            executor.run_command(["fdisk", "/dev/sda"])

    def test_command_must_be_list(self, executor):
        """Test that command must be a list, not string."""
        with pytest.raises(SandboxError):
            executor.run_command("echo hello")

    def test_empty_command_rejected(self, executor):
        """Test that empty command is rejected."""
        with pytest.raises(SandboxError):
            executor.run_command([])

    def test_command_not_found(self, executor):
        """Test handling of command not found."""
        with pytest.raises(SandboxError):
            executor.run_command(["nonexistent_command_xyz"])

    def test_command_exit_code_check(self, executor):
        """Test exit code checking."""
        result = executor.run_command(
            [sys.executable, "-c", "import sys; sys.exit(1)"],
            check=False,
        )
        assert result.returncode != 0

    def test_command_exit_code_error(self, executor):
        """Test error on non-zero exit with check=True."""
        with pytest.raises(SandboxError):
            executor.run_command(
                [sys.executable, "-c", "import sys; sys.exit(1)"],
                check=True,
            )

    def test_run_tool_with_args(self, executor):
        """Test running tool with arguments."""
        result = executor.run_tool(
            sys.executable,
            {"c": "print('hello')"},
            timeout=10,
        )

        assert "hello" in result

    def test_run_tool_with_flags(self, executor):
        """Test running tool with boolean flags."""
        result = executor.run_tool(sys.executable, {"h": True}, timeout=10)

        assert "usage" in result.lower()

    def test_run_tool_path_with_spaces(self, executor, temp_dir):
        """Test tool paths containing spaces."""
        script_dir = temp_dir / "dir with spaces"
        script_dir.mkdir()

        script_file = script_dir / "test_script.py"
        script_file.write_text("print('success')\n")

        result = executor.run_command([sys.executable, str(script_file)])
        assert "success" in result.stdout
