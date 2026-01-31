#!/usr/bin/env python3
"""
Test script to verify password hash compatibility between PHP and Python
"""

import sys
from db_connection import DatabaseConnection

def test_stored_hash():
    """Check what's actually stored in the database"""
    print("=" * 60)
    print("PASSWORD HASH VERIFICATION TEST")
    print("=" * 60)

    db = DatabaseConnection()
    success, error = db.connect()

    if not success:
        print(f"❌ Connection failed: {error}")
        return

    print("✅ Connected to database\n")

    # Fetch all users
    cursor = db.connection.cursor(dictionary=True)
    cursor.execute("SELECT id, username, password, is_admin FROM user_logins")
    users = cursor.fetchall()
    cursor.close()

    print(f"Found {len(users)} users in database:\n")

    for user in users:
        print(f"User: {user['username']} (ID: {user['id']}, Admin: {user['is_admin']})")
        sealed = user['password']
        print(f"  Sealed hash (first 50 chars): {sealed[:50]}...")
        print(f"  Sealed hash length: {len(sealed)}")

        # Try to unseal
        unsealed = db.unseal_hash(sealed)
        if unsealed:
            print(f"  ✅ Unsealed successfully")
            print(f"  Unsealed hash (first 50 chars): {unsealed[:50]}...")
            print(f"  Is Argon2 hash: {unsealed.startswith('$argon2')}")
        else:
            print(f"  ❌ Failed to unseal")
        print()

    db.close()
    print("=" * 60)

def test_password_verification(username, password):
    """Test if a specific password works"""
    print(f"\n{'=' * 60}")
    print(f"TESTING LOGIN: {username}")
    print("=" * 60)

    db = DatabaseConnection()
    success, error = db.connect()

    if not success:
        print(f"❌ Connection failed: {error}")
        return

    print(f"Testing password: {password}")

    success, result = db.verify_login(username, password)

    if success:
        print(f"✅ LOGIN SUCCESSFUL!")
        print(f"   User data: {result}")
    else:
        print(f"❌ LOGIN FAILED: {result}")

    db.close()
    print("=" * 60)

if __name__ == "__main__":
    # First, check what's in the database
    test_stored_hash()

    # Test with known credentials
    if len(sys.argv) > 2:
        username = sys.argv[1]
        password = sys.argv[2]
        test_password_verification(username, password)
    else:
        # Test default credentials
        print("\nTesting default Python-created credentials:")
        test_password_verification("Layer8Wes", "Valorant123!")

        print("\n\nTo test other credentials, run:")
        print("python test_password_hash.py <username> <password>")
