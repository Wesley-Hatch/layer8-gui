"""
Layer8 GUI Login Diagnostic Tool

This script performs deep diagnostics on why GUI login is failing
even when database connection is successful.
"""

from db_connection import DatabaseConnection
import sys

def diagnose_login_issue():
    print("=" * 80)
    print("LAYER8 GUI LOGIN DIAGNOSTIC")
    print("=" * 80)
    print()
    
    # Initialize database
    db = DatabaseConnection()
    
    # Step 1: Configuration Check
    print("STEP 1: Configuration Check")
    print("-" * 80)
    
    print(f"Pepper: {db.pepper[:30]}...")
    print(f"Pepper Length: {len(db.pepper)} chars")
    print(f"Expected: zVtR89WKPvDDtsHzt5sEqMiMcel9/qzbTVZwoD8JgXM=")
    pepper_match = db.pepper == "zVtR89WKPvDDtsHzt5sEqMiMcel9/qzbTVZwoD8JgXM="
    print(f"Pepper Match: {'✅ YES' if pepper_match else '❌ NO'}")
    print()
    
    print(f"Encryption Key Length: {len(db.pwd_key)} bytes")
    print(f"Expected: 32 bytes")
    key_ok = len(db.pwd_key) == 32
    print(f"Key Length OK: {'✅ YES' if key_ok else '❌ NO'}")
    print()
    
    print(f"Key ID: {db.pwd_key_id}")
    print()
    
    if not pepper_match:
        print("❌ CRITICAL: Pepper doesn't match!")
        print("   Your Python .env has wrong pepper value")
        print("   Expected: zVtR89WKPvDDtsHzt5sEqMiMcel9/qzbTVZwoD8JgXM=")
        print(f"   Got:      {db.pepper}")
        return
    
    if not key_ok:
        print("❌ CRITICAL: Encryption key is wrong length!")
        return
    
    # Step 2: Database Connection
    print("STEP 2: Database Connection")
    print("-" * 80)
    
    success, error = db.connect()
    if not success:
        print(f"❌ Connection failed: {error}")
        return
    
    print("✅ Database connection successful")
    print()
    
    # Step 3: Check Users
    print("STEP 3: Check Users in Database")
    print("-" * 80)
    
    try:
        cursor = db.connection.cursor(dictionary=True)
        # Check both tables
        all_users = []
        try:
            cursor.execute("SELECT username, id, 'users' as tbl FROM users")
            all_users.extend(cursor.fetchall())
        except:
            pass
            
        try:
            cursor.execute("SELECT username, id, 'user_logins' as tbl FROM user_logins")
            all_users.extend(cursor.fetchall())
        except:
            pass
        
        if not all_users:
            print("❌ No users found in database!")
            cursor.close()
            db.close()
            return
        
        print(f"Found {len(all_users)} user(s):")
        for user in all_users:
            print(f"  • {user['username']} (ID: {user['id']}, Table: {user['tbl']})")
        print()
        
        cursor.close()
        
    except Exception as e:
        print(f"❌ Error querying users: {e}")
        db.close()
        return
    
    # Step 4: Test Password Decryption
    print("STEP 4: Test Password Decryption")
    print("-" * 80)
    
    try:
        cursor = db.connection.cursor(dictionary=True)
        cursor.execute("SELECT username, password FROM user_logins LIMIT 1")
        test_user = cursor.fetchone()
        cursor.close()
        
        if test_user:
            username = test_user['username']
            sealed_hash = test_user['password']
            
            print(f"Testing user: {username}")
            print(f"Sealed hash: {sealed_hash[:60]}...")
            print()
            
            # Parse format
            if ':' in sealed_hash:
                parts = sealed_hash.split(':', 1)
                key_id = parts[0]
                print(f"Key ID in database: {key_id}")
                print(f"Current key ID: {db.pwd_key_id}")
                
                if key_id != db.pwd_key_id:
                    print("⚠️  WARNING: Key ID mismatch!")
                    print("   This might indicate the user was created with different keys")
            
            print()
            print("Attempting to decrypt password hash...")
            
            # Try to unseal
            plaintext_hash = db.unseal_hash(sealed_hash)
            
            if plaintext_hash:
                print("✅ Successfully decrypted password hash!")
                print(f"   Hash type: {plaintext_hash[:20]}...")
                
                if plaintext_hash.startswith('$argon2'):
                    print("   ✅ Hash format is Argon2id (correct)")
                else:
                    print("   ⚠️  Hash format is NOT Argon2id")
                
                print()
                print("💡 DIAGNOSIS: Encryption keys are CORRECT")
                print()
                
            else:
                print("❌ FAILED to decrypt password hash!")
                print()
                print("💡 DIAGNOSIS: Encryption keys MISMATCH")
                print()
                print("   REASONS:")
                print("   1. User was created in PHP with OLD keys")
                print("   2. Python .env has different keys than PHP .htaccess")
                print("   3. Encryption key or pepper is wrong")
                print()
                print("   SOLUTIONS:")
                print("   A. Make sure .env and .htaccess have IDENTICAL keys")
                print("   B. Delete user in PHP and recreate with current keys")
                print("   C. Run: python reset_users.py")
                return
        
    except Exception as e:
        print(f"❌ Error testing decryption: {e}")
        import traceback
        traceback.print_exc()
        db.close()
        return
    
    # Step 5: Test Actual Login
    print("STEP 5: Interactive Login Test")
    print("-" * 80)
    
    username = input("Enter username to test: ").strip()
    if not username:
        username = test_user['username']
        print(f"Using: {username}")
    
    password = input(f"Enter password for {username}: ").strip()
    if not password:
        print("❌ No password provided")
        db.close()
        return
    
    print()
    print(f"Testing login: {username} / {'*' * len(password)}")
    print()
    
    # Show step-by-step what happens
    print("Step-by-step verification:")
    print()
    
    # 1. Fetch user
    print("1. Fetching user from database...")
    # Use verify_login logic to fetch user
    success, user = db.verify_login(username, "dummy_password_just_to_get_data")
    # Actually verify_login returns False if password fails, but it sets current_user if it found them? 
    # No, it doesn't. Let's just do a manual check like in verify_login
    
    user = None
    cursor = db.connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user: 
            user['password'] = user.get('password_hash_enc')
            if user.get('k_id') and ':' not in str(user['password']):
                user['password'] = f"{user['k_id']}:{user['password']}"
    except: pass
    
    if not user:
        try:
            cursor.execute("SELECT * FROM user_logins WHERE username = %s", (username,))
            user = cursor.fetchone()
        except: pass
    cursor.close()
    
    if not user:
        print(f"   ❌ User '{username}' not found in database")
        db.close()
        return
    
    print(f"   ✅ User found (ID: {user['id']})")
    print()
    
    # 2. Get sealed hash
    sealed_hash = user.get('password') or user.get('password_hash')
    print("2. Getting encrypted password hash from database...")
    print(f"   Sealed hash: {sealed_hash[:60]}...")
    print()
    
    # 3. Decrypt hash
    print("3. Decrypting password hash...")
    plaintext_hash = db.unseal_hash(sealed_hash)
    
    if not plaintext_hash:
        print("   ❌ FAILED to decrypt!")
        print()
        print("   💡 This is why login fails!")
        print("   The encryption key is wrong or user was created with different keys")
        db.close()
        return
    
    print(f"   ✅ Decrypted successfully")
    print(f"   Hash: {plaintext_hash[:50]}...")
    print()
    
    # 4. Add pepper
    print("4. Adding pepper to password...")
    peppered = db.pepper_password(password)
    print(f"   Original: {password}")
    print(f"   Peppered: {peppered[:50]}...")
    
    # Check for old bug (colon in pepper)
    if ':' in peppered and peppered.index(':') < len(password):
        print("   ⚠️  WARNING: Colon detected in peppered password!")
        print("   This might indicate old db_connection.py with ':' bug")
    
    print()
    
    # 5. Verify with Argon2
    print("5. Verifying with Argon2id...")
    
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
        
        ph = PasswordHasher()
        
        try:
            ph.verify(plaintext_hash, peppered)
            print("   ✅ PASSWORD VERIFIED!")
            print()
            print("=" * 80)
            print("✅ LOGIN SHOULD WORK!")
            print("=" * 80)
            print()
            print("The password is correct and everything is configured properly.")
            print("If GUI still shows 'invalid login', check:")
            print("1. GUI is using the NEW db_connection.py (no ':' bug)")
            print("2. GUI is reading the correct .env file")
            print("3. No caching issues in GUI")
            
        except VerifyMismatchError:
            print("   ❌ PASSWORD MISMATCH!")
            print()
            print("=" * 80)
            print("❌ LOGIN FAILS: Wrong Password")
            print("=" * 80)
            print()
            print("The password you entered is incorrect.")
            print()
            print("Possible reasons:")
            print("1. Wrong password entered")
            print("2. User was created with different pepper")
            print("3. Case sensitivity issue")
            print()
            print("Try these passwords:")
            
            # Suggest common test passwords
            test_passwords = [
                password,
                password.lower(),
                password.upper(),
                password.capitalize()
            ]
            
            for test_pwd in set(test_passwords):
                test_peppered = db.pepper_password(test_pwd)
                try:
                    ph.verify(plaintext_hash, test_peppered)
                    print(f"   ✅ Found it! Try: {test_pwd}")
                    break
                except:
                    pass
            
    except ImportError:
        print("   ❌ argon2-cffi not installed!")
        print("   Install: pip install argon2-cffi")
    
    db.close()
    print()
    print("=" * 80)

if __name__ == "__main__":
    try:
        diagnose_login_issue()
    except KeyboardInterrupt:
        print("\n\nDiagnostic cancelled by user")
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
