"""Structured JSON security logging.

One line per security-relevant event on stdout. On Cloud Run these land in
Cloud Logging as jsonPayload, ready for Log Analytics queries.
"""
import json
import logging
import sys
from datetime import datetime, timezone

_logger = logging.getLogger("miniapp.security")
_logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_handler)
_logger.propagate = False


def security_event(event: str, **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "severity": "INFO",
        "event": event,
        **fields,
    }
    _logger.info(json.dumps(record, default=str))
