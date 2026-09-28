import secrets
import base64

def generate_pepper(length=32) -> str:
    """Generate cryptographically secure pepper"""
    # Use base64 to ensure it's ASCII safe but has high entropy
    return base64.b64encode(secrets.token_bytes(length)).decode('utf-8')

def generate_encryption_key() -> str:
    """Generate 32-byte encryption key (Base64 encoded)"""
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')

def generate_master_password(length=16) -> str:
    """Generate strong master password"""
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    print("=== Layer8 Credential Generator ===")
    print("Use these values during the First-Run Setup Wizard.\n")
    
    pepper = generate_pepper()
    enc_key = generate_encryption_key()
    master_pwd = generate_master_password()
    
    print(f"Pepper (min 32 chars):")
    print(f"{pepper}\n")
    
    print(f"Encryption Key (exactly 32 bytes when decoded):")
    print(f"{enc_key}\n")
    
    print(f"Master Password (for local encrypted fallback):")
    print(f"{master_pwd}\n")
    
    print("IMPORTANT: Store these values in a secure password manager!")
    print("The pepper and encryption key are REQUIRED to access existing data.")
