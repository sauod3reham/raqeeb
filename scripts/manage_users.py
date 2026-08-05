"""CLI for managing local application users (out-of-band from the web UI,
so account creation/deletion is never reachable pre-authentication over the
app itself).

Usage:
    python scripts/manage_users.py add <username> <role>      (prompts for password)
    python scripts/manage_users.py remove <username>
    python scripts/manage_users.py list

Roles: admin, compliance_auditor, reviewer, viewer
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.security.auth import add_user, remove_user, list_users, VALID_ROLES  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1]

    if command == "add":
        if len(sys.argv) != 4:
            print("الاستخدام: python scripts/manage_users.py add <username> <role>")
            return
        username, role = sys.argv[2], sys.argv[3]
        if role not in VALID_ROLES:
            print(f"دور غير صالح. الأدوار المسموحة: {sorted(VALID_ROLES)}")
            return
        password = getpass.getpass("كلمة المرور: ")
        confirm = getpass.getpass("تأكيد كلمة المرور: ")
        if password != confirm:
            print("كلمتا المرور غير متطابقتين.")
            return
        if len(password) < 10:
            print("يجب أن تكون كلمة المرور 10 أحرف على الأقل.")
            return
        add_user(username, password, role)
        print(f"تم إنشاء/تحديث المستخدم '{username}' بدور '{role}'.")

    elif command == "remove":
        if len(sys.argv) != 3:
            print("الاستخدام: python scripts/manage_users.py remove <username>")
            return
        remove_user(sys.argv[2])
        print(f"تم حذف المستخدم '{sys.argv[2]}' إن وُجد.")

    elif command == "list":
        for user in list_users():
            print(f"- {user['username']} ({user['role']})")

    else:
        print(__doc__)


if __name__ == "__main__":
    main()
