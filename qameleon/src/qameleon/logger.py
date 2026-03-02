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
        # Merge any custom fields added via the `extra` kwarg in logging calls.
        _standard_attrs = logging.LogRecord(
            "", 0, "", 0, "", (), None
        ).__dict__.keys() | {"message", "asctime"}
        for key, val in record.__dict__.items():
            if key not in _standard_attrs:
                log_data[key] = val
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
