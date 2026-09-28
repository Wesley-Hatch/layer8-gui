#!/usr/bin/env python3
"""
Layer8 - Admin password reset utility.

Run this locally when you've forgotten your login. It reuses the app's own
DatabaseConnection, so it loads your DB credentials the same secure way the GUI
does (keyring / .env) and hashes the new password with the same argon_hash +
seal_hash path -- meaning the reset works for BOTH the Python client and the PHP
web panel.

Usage:
    python reset_password.py            # interactive: lists users, prompts for new password
    python reset_password.py <username> # reset a specific user, prompts for new password

Nothing is printed except usernames; the new password is read with getpass and
never echoed or logged.
"""

import sys
import getpass
from db_connection import DatabaseConnection


def list_users(db) -> list:
    """Return list of (table, username) across users / user_logins tables."""
    found = []
    cur = db.connection.cursor()
    for table, ucol in (("users", "username"), ("user_logins", "username")):
        try:
            cur.execute(f"SELECT {ucol} FROM {table}")
            rows = cur.fetchall()
            for r in rows:
                name = r[ucol] if isinstance(r, dict) else r[0]
                found.append((table, name))
        except Exception:
            pass  # table may not exist
    cur.close()
    return found


def reset(db, username: str, new_password: str) -> bool:
    """Hash+seal the new password and UPDATE the correct table/columns."""
    hashed = db.argon_hash(new_password)
    sealed = db.seal_hash(hashed)               # "k1:base64(...)"
    cur = db.connection.cursor()
    updated = False

    # PHP 'users' table: password_hash_enc (no key-id prefix) + k_id column
    try:
        cur.execute("SHOW TABLES LIKE 'users'")
        if cur.fetchone():
            sealed_data = sealed.split(":", 1)[1] if ":" in sealed else sealed
            cur.execute(
                f"UPDATE users SET password_hash_enc = {db.placeholder}, "
                f"k_id = {db.placeholder} WHERE username = {db.placeholder}",
                (sealed_data, db.pwd_key_id, username),
            )
            if cur.rowcount > 0:
                updated = True
    except Exception as e:
        print(f"(users table: {e})")

    # Python 'user_logins' table: full sealed string in password column
    if not updated:
        try:
            cur.execute(
                f"UPDATE user_logins SET password = {db.placeholder} "
                f"WHERE username = {db.placeholder}",
                (sealed, username),
            )
            if cur.rowcount > 0:
                updated = True
        except Exception as e:
            print(f"(user_logins table: {e})")

    try:
        db.connection.commit()
    except Exception:
        pass
    cur.close()
    return updated


def main():
    db = DatabaseConnection()
    ok, err = db.connect()
    if not ok:
        print(f"Could not connect to the database: {err}")
        sys.exit(1)

    username = sys.argv[1] if len(sys.argv) > 1 else None

    if not username:
        users = list_users(db)
        if not users:
            print("No users found in 'users' or 'user_logins'.")
            db.close()
            sys.exit(1)
        print("Existing accounts:")
        for table, name in users:
            print(f"  - {name}   [{table}]")
        username = input("\nUsername to reset: ").strip()

    if not username:
        print("No username given.")
        db.close()
        sys.exit(1)

    new_pw = getpass.getpass(f"New password for '{username}': ")
    confirm = getpass.getpass("Confirm new password: ")
    if new_pw != confirm:
        print("Passwords did not match. Aborted.")
        db.close()
        sys.exit(1)
    if len(new_pw) < 8:
        print("Please choose at least 8 characters. Aborted.")
        db.close()
        sys.exit(1)

    if reset(db, username, new_pw):
        print(f"\nPassword updated for '{username}'. You can log in now.")
    else:
        print(f"\nNo account named '{username}' was found to update.")
    db.close()


if __name__ == "__main__":
    main()
