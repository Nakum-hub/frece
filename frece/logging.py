"""Structured logging for forensic operations."""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _utc_now_iso() -> str:
    """Return the current UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ForensicLogFormatter(logging.Formatter):
    """Log formatter producing JSON with UTC timestamps."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": _utc_now_iso(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "lineno": record.lineno,
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def setup_logging(
    log_dir: Optional[Path] = None, level: int = logging.INFO, name: str = "frece"
) -> logging.Logger:
    """Configure logging with file and console output.

    Args:
        log_dir: Directory for log files. If None, only console logging.
        level: Logging level (default INFO).
        name: Logger name.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = ForensicLogFormatter()

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            log_dir / f"{_utc_now_iso().replace(':', '-')}.log"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_custody_event(
    logger: logging.Logger,
    event_type: str,
    evidence_id: str,
    details: dict[str, Any],
) -> None:
    """Log a chain of custody event.

    Args:
        logger: Logger instance.
        event_type: Type of event (ACQUIRE, HASH, CARVE, VERIFY, etc.).
        evidence_id: Identifier of evidence involved.
        details: Event-specific details.
    """
    event = {
        "event_type": event_type,
        "evidence_id": evidence_id,
        "timestamp": _utc_now_iso(),
        **details,
    }
    logger.info(json.dumps(event))
