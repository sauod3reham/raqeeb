"""Lightweight local authentication and role-based access control (RBAC).

This is a single-machine Streamlit tool with no database or HTTP session
cookies of its own — Streamlit itself is the "server", so a permission check
performed here executes entirely server-side (there is no client-trusted
equivalent to bypass). Passwords are never stored in plaintext: PBKDF2-HMAC
with a per-user random salt and a high iteration count.

Enable/disable via the AUTH_ENABLED env var (defaults to enabled). When
disabled, `has_permission` always returns True — intended only for local,
single-operator development use.
"""
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Optional

from src.config import PROJECT_ROOT

AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
USERS_FILE = PROJECT_ROOT / "data" / "users.json"

ROLE_PERMISSIONS = {
    "admin": {"run_audit", "download_report", "manage_knowledge_base", "view_knowledge_base", "manage_users"},
    "compliance_auditor": {"run_audit", "download_report", "view_knowledge_base"},
    "reviewer": {"download_report", "view_knowledge_base"},
    "viewer": {"view_knowledge_base"},
}

VALID_ROLES = set(ROLE_PERMISSIONS.keys())
_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS).hex()


def hash_new_password(password: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), "password_hash": _hash_password(password, salt)}


def _load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        records = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return {rec["username"]: rec for rec in records if "username" in rec}


def _save_users(users: dict) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(
        json.dumps(list(users.values()), ensure_ascii=False, indent=2), encoding="utf-8"
    )


def users_file_exists() -> bool:
    return USERS_FILE.exists() and len(_load_users()) > 0


def verify_credentials(username: str, password: str) -> Optional[str]:
    """Return the user's role on success, else None. Always performs a hash
    computation even for unknown usernames to reduce user-enumeration timing
    side-channels, and uses constant-time comparison for the final check."""
    username = (username or "").strip()
    users = _load_users()
    record = users.get(username)
    if not record:
        _hash_password(password or "", secrets.token_bytes(16))
        return None
    salt = bytes.fromhex(record["salt"])
    candidate = _hash_password(password or "", salt)
    if hmac.compare_digest(candidate, record["password_hash"]):
        return record.get("role")
    return None


def add_user(username: str, password: str, role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError(f"دور غير صالح: {role}. الأدوار المسموحة: {sorted(VALID_ROLES)}")
    users = _load_users()
    record = {"username": username, "role": role}
    record.update(hash_new_password(password))
    users[username] = record
    _save_users(users)


def remove_user(username: str) -> None:
    users = _load_users()
    users.pop(username, None)
    _save_users(users)


def list_users() -> list:
    return [{"username": u["username"], "role": u["role"]} for u in _load_users().values()]


def has_permission(role: Optional[str], action: str) -> bool:
    if not AUTH_ENABLED:
        return True
    if not role:
        return False
    return action in ROLE_PERMISSIONS.get(role, set())
