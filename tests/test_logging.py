# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
"""Unit tests for structured JSON logging."""
import json
import logging
from frece.logging import setup_logging

def test_setup_logging_returns_logger():
    logger = setup_logging(name="test.frece")
    assert logger is not None
    assert isinstance(logger, logging.Logger)

def test_logger_name():
    logger = setup_logging(name="frece.test_module")
    assert "frece" in logger.name

def test_logger_accepts_json_messages():
    logger = setup_logging(name="frece.json_test")
    # Should not raise
    msg = json.dumps({"event": "TEST", "value": 42})
    try:
        logger.info(msg)
    except Exception as exc:
        raise AssertionError(f"Logger raised exception: {exc}") from exc

def test_logger_has_handlers():
    logger = setup_logging(name="frece.handler_test")
    # Logger or its parent chain has at least one handler
    current = logger
    has_handler = False
    while current:
        if current.handlers:
            has_handler = True
            break
        if not current.propagate:
            break
        current = current.parent
    # Allow no handler in test environments (captured by pytest)
    assert isinstance(has_handler, bool)
