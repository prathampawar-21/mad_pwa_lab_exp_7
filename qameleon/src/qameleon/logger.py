"""Structured JSON logging for QAMELEON."""

import json
import logging
import sys
import time
from typing import Any


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            log_data.update(record.extra)
        return json.dumps(log_data)


def get_logger(name: str, level: str = "INFO", fmt: str = "json") -> logging.Logger:
    """Get a configured logger instance.

    Args:
        name: Logger name (typically __name__)
        level: Log level string
        fmt: Format - 'json' or 'text'

    Returns:
        Configured Logger instance
    """
    logger = logging.getLogger(f"qameleon.{name}")
    if logger.handlers:
        return logger

    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    return logger
