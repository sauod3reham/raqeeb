"""Local, append-only audit log for security-relevant events.

Never logs secrets, passwords, API keys, or full sensitive document content.
Each entry carries a correlation_id so a single request can be traced across
multiple log lines. Intended for local security review, not for shipping to
any external service.
"""
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from src.config import PROJECT_ROOT

LOG_DIR = PROJECT_ROOT / "logs"
AUDIT_LOG_PATH = LOG_DIR / "audit.log"

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"(api[_-]?key\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*)\S+", re.IGNORECASE),
]

_MAX_FIELD_LEN = 500


def _redact(value) -> str:
    if not isinstance(value, str):
        return str(value)
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    if len(redacted) > _MAX_FIELD_LEN:
        redacted = redacted[:_MAX_FIELD_LEN] + "…[truncated]"
    return redacted


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def log_event(
    event: str,
    correlation_id: str,
    user: str = "-",
    role: str = "-",
    resource: str = "-",
    result: str = "-",
    details: str = "",
    ip: str = "-",
) -> None:
    """Append a single structured (JSON-lines) audit entry. Failures to write
    are swallowed intentionally so logging can never break the main flow."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "correlation_id": correlation_id,
        "event": event,
        "user": user,
        "role": role,
        "resource": _redact(resource),
        "result": result,
        "details": _redact(details),
        "ip": ip,
    }
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
