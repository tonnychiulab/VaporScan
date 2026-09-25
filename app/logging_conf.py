"""Structured (JSON-lines) logging to stdout.

Designed to be tailed by Fluent Bit / Filebeat and shipped into
Graylog or another SIEM. Only metadata is ever logged here — filenames,
hashes, and results — never file content or request bodies.
"""
import json
import logging
import sys
import time
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime_iso(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "audit"):
            payload.update(record.audit)  # type: ignore[attr-defined]
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def formatTime_iso(record: logging.LogRecord) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z"


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


def audit_log(logger: logging.Logger, message: str, **fields: Any) -> None:
    """Emits one structured audit line. `fields` should be the table
    from spec §7 (request_id, source_ip, filename, sha256, ...) —
    never raw file bytes.
    """
    logger.info(message, extra={"audit": fields})
