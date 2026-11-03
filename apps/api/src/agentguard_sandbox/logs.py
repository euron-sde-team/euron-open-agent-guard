"""Structured JSON logs on stdout, one object per line.

Callers attach data with ``extra={"fields": {...}}``. What they attach is sizes, counts,
verdicts and ids; code, stdin, file contents, environment values and the token are never
logged by this service.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry.update(fields)
        run_id = getattr(record, "run_id", None)
        if run_id is not None:
            entry["run_id"] = run_id
        if record.exc_info and record.exc_info[0] is not None:
            # The exception type and message only: a traceback could quote request data.
            entry["error"] = f"{record.exc_info[0].__name__}: {record.exc_info[1]}"[:500]
        return json.dumps(entry, default=str)


def configure(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers[:] = []
        logger.propagate = True
