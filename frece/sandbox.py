# Copyright (c) 2025 Nakum-hub. All rights reserved. Proprietary and confidential. Unauthorized use, copying, modification, or distribution is prohibited.
"""Sandboxed module execution with input validation."""

import logging
import subprocess
from pathlib import Path
from typing import Any, Optional

import re as _sandbox_re
from frece.errors import SandboxError


class InputValidator:
    """Validate user inputs against length and character constraints."""

    MAX_PATH_LENGTH = 4096
    MAX_CASE_NAME_LENGTH = 255
    DANGEROUS_CHARS = {"<", ">", "|", "&", ";", "`", "$", "{", "}"}
    _CASE_NAME_RE = _sandbox_re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$|^[A-Za-z0-9]$')

    @staticmethod
    def validate_path(path_str: str, max_length: int = 4096) -> Path:
        """Validate and return a path object.

        Args:
            path_str: Path string to validate.
            max_length: Maximum allowed length.

        Returns:
            Validated Path object.

        Raises:
            SandboxError: If validation fails.
        """
        if len(path_str) > max_length:
            raise SandboxError(
                f"Path exceeds {max_length} characters",
                remediation=f"Use a shorter path (current: {len(path_str)})",
            )

        if any(c in path_str for c in InputValidator.DANGEROUS_CHARS):
            raise SandboxError(
                f"Path contains dangerous characters: {InputValidator.DANGEROUS_CHARS}",
                remediation="Use only alphanumeric, dash, underscore, and period.",
            )

        # Block null bytes
        if "\x00" in path_str:
            raise SandboxError(
                "Path contains null bytes",
                remediation="Remove null bytes from the path.",
            )

        # Block path traversal sequences
        path = Path(path_str)
        parts: tuple[str, ...] = ()
        try:
            parts = path.parts
        except Exception:
            pass
        if ".." in parts:
            raise SandboxError(
                "Path traversal ('..') is not allowed",
                remediation="Use an absolute path without '..' components.",
            )

        return path

    @staticmethod
    def validate_case_name(name: str) -> str:
        """Validate a case name — strict whitelist, prevents path traversal.

        Allows only: letters, digits, hyphen, underscore, period.
        Rejects: slashes, spaces, null bytes, shell metacharacters, '..'.

        Raises:
            SandboxError: If the name fails any validation rule.
        """
        if not name:
            raise SandboxError(
                "Case name cannot be empty",
                remediation="Provide a non-empty case name",
            )
        if len(name) > InputValidator.MAX_CASE_NAME_LENGTH:
            raise SandboxError(
                f"Case name exceeds {InputValidator.MAX_CASE_NAME_LENGTH} characters",
                remediation=f"Use a shorter case name (current: {len(name)})",
            )
        if "\x00" in name:
            raise SandboxError(
                "Case name contains null bytes",
                remediation="Remove null bytes from the case name",
            )
        if ".." in name:
            raise SandboxError(
                "Case name contains path traversal sequence '..'",
                remediation="Remove '..' from the case name",
            )
        if not InputValidator._CASE_NAME_RE.match(name):
            raise SandboxError(
                f"Case name '{name[:40]}' contains invalid characters",
                remediation=(
                    "Use only letters, digits, hyphens, underscores, and periods. "
                    "Example: CASE-2025-001"
                ),
            )
        return name

    @staticmethod
    def validate_string_arg(value: str, max_length: int = 4096, arg_name: str = "argument") -> str:
        """Validate a string argument.

        Args:
            value: Value to validate.
            max_length: Maximum allowed length.
            arg_name: Name of argument (for error message).

        Returns:
            Validated string.

        Raises:
            SandboxError: If validation fails.
        """
        if len(value) > max_length:
            raise SandboxError(
                f"{arg_name} exceeds {max_length} characters",
                remediation=f"Reduce to {max_length} chars or less",
            )

        return value


class SandboxedExecutor:
    """Execute subprocesses with sandboxing restrictions."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

    def run_command(
        self,
        command: list[str],
        timeout: int = 300,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a command in a sandboxed environment.

        Args:
            command: Command as list of arguments (NOT a shell string).
            timeout: Maximum execution time in seconds.
            check: If True, raise on non-zero exit code.

        Returns:
            CompletedProcess result.

        Raises:
            SandboxError: If command execution is denied or fails.
            subprocess.TimeoutExpired: If timeout exceeded.
        """
        if not command:
            raise SandboxError(
                "Empty command",
                remediation="Provide a non-empty command list",
            )

        if not isinstance(command, list):
            raise SandboxError(
                "Command must be a list, not a string",
                remediation="Pass command as list: ['tool', 'arg1', 'arg2']",
            )

        dangerous_tools = {"rm", "dd", "mkfs", "fdisk", "parted"}
        tool_name = Path(command[0]).name

        if tool_name in dangerous_tools:
            raise SandboxError(
                f"Tool '{tool_name}' requires explicit authorization",
                remediation="This tool is restricted. Contact security team.",
            )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            self.logger.info(
                f"Command executed: {' '.join(command)}, "
                f"exit_code={result.returncode}, "
                f"stdout_len={len(result.stdout)}, "
                f"stderr_len={len(result.stderr)}"
            )

            if check and result.returncode != 0:
                raise SandboxError(
                    f"Command failed: {tool_name}",
                    remediation=f"stderr: {result.stderr[:200]}",
                )

            return result

        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timeout: {tool_name}")
            raise
        except FileNotFoundError as e:
            raise SandboxError(
                f"Tool not found: {command[0]}",
                remediation=f"Install {tool_name} or check PATH",
            ) from e
        except SandboxError:
            raise
        except Exception as e:
            raise SandboxError(
                f"Execution failed: {tool_name}",
                remediation=str(e),
            ) from e

    def run_tool(
        self,
        tool_path: str,
        args: dict[str, Any],
        timeout: int = 300,
    ) -> str:
        """Run a tool with validated arguments (no shell expansion).

        Args:
            tool_path: Path to tool executable.
            args: Dict of argument name -> value.
            timeout: Timeout in seconds.

        Returns:
            stdout as string.

        Raises:
            SandboxError: If execution fails.
        """
        command = [tool_path]

        for key, value in args.items():
            flag = f"-{key}" if len(key) == 1 else f"--{key}"
            if value is True:
                command.append(flag)
            elif value is not False and value is not None:
                command.append(flag)
                command.append(str(value))

        result = self.run_command(command, timeout=timeout, check=True)
        return str(result.stdout)
