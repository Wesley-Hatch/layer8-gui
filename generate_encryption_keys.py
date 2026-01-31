#!/usr/bin/env python3
"""
Generate secure encryption keys for Layer8 database encryption.
Run this ONCE and copy the output to your .env file.
"""

import secrets
import base64

def generate_keys():
    print("="*60)
    print("  Layer8 - Encryption Key Generator")
    print("="*60)
    
    # 1. Generate 32-byte encryption key for password sealing
    pwd_key = secrets.token_bytes(32)
    pwd_key_b64 = base64.b64encode(pwd_key).decode('utf-8')
    
    # 2. Generate random pepper (16-32 bytes recommended)
    pepper = secrets.token_bytes(24)
    pepper_b64 = base64.b64encode(pepper).decode('utf-8')
    
    # 3. Generate PWD_KEY_ID (just a version identifier)
    key_id = secrets.token_hex(4)  # 8 character hex
    
    print("\n✅ Keys generated successfully!")
    print("\n" + "="*60)
    print("Copy these to your .env file:")
    print("="*60)
    
    print(f"\nL8_DB_PEPPER={pepper_b64}")
    print(f"L8_DB_PWD_KEY={pwd_key_b64}")
    print(f"PWD_KEY_ID={key_id}")
    
    print("\n" + "="*60)
    print("⚠️  IMPORTANT SECURITY NOTES:")
    print("="*60)
    print("1. Keep these keys SECRET - never commit to git")
    print("2. Use the SAME keys in both PHP and Python")
    print("3. If you lose these keys, you CANNOT decrypt existing passwords")
    print("4. Store backups securely (password manager, encrypted storage)")
    print("5. Both PHP and Python must use the same L8_DB_PWD_KEY")
    print("\n" + "="*60)
    
    # Also output for PHP config.php
    print("\nFor PHP config.php, add:")
    print("="*60)
    print(f"define('PEPPER', '{pepper_b64}');")
    print(f"define('PWD_KEY', base64_decode('{pwd_key_b64}'));")
    print(f"define('PWD_KEY_ID', '{key_id}');")
    print("="*60)

if __name__ == "__main__":
    generate_keys()
