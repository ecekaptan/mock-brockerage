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


def mask_iban(iban):
    """TR000000000000000000000001 -> TR********************0001"""
    if not iban:
        return iban
    iban = str(iban)
    if len(iban) <= 6:
        return "*" * len(iban)
    return iban[:2] + "*" * (len(iban) - 6) + iban[-4:]


def security_event(event: str, **fields) -> None:
    # FIX (IBANs in logs): an IBAN is personal data under KVKK, and logs get
    # copied to more places and more people than the database. Any field with
    # "iban" in its name is masked here, so a new log line can't forget it. The
    # country code and last 4 digits are enough to investigate; the full IBAN
    # stays in the withdrawals table.
    for key, value in fields.items():
        if "iban" in key:
            fields[key] = mask_iban(value)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "severity": "INFO",
        "event": event,
        **fields,
    }
    _logger.info(json.dumps(record, default=str))
