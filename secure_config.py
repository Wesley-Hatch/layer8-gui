import os
import json
import base64
import platform
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any

import keyring
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('application')

class SecureConfig:
    """
    Secure configuration storage for Layer8 GUI
    
    Priority order:
    1. System keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service)
    2. Encrypted config file with master password (fallback)
    """
    
    def __init__(self, app_name='Layer8Security'):
        self.app_name = app_name
        self.config_dir = self._get_config_dir()
        self.config_file = self.config_dir / 'config.enc'
        self.salt_file = self.config_dir / 'salt.bin'
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def _get_config_dir(self) -> Path:
        """Get platform-specific config directory"""
        home = Path.home()
        if platform.system() == "Windows":
            return Path(os.environ.get('APPDATA', str(home / 'AppData' / 'Roaming'))) / 'Layer8'
        elif platform.system() == "Darwin":
            return home / 'Library' / 'Application Support' / 'Layer8'
        else:  # Linux and others
            return home / '.config' / 'layer8'

    def is_configured(self) -> bool:
        """Check if credentials are already configured"""
        # Check keyring first
        try:
            if keyring.get_password(self.app_name, 'db_host'):
                return True
        except Exception as e:
            logger.error(f"Error checking keyring: {e}")

        # Check encrypted file
        return self.config_file.exists()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a Fernet key from a password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def save_credentials(self, credentials: dict, master_password: str = None):
        """Save credentials securely"""
        # 1. Try to save to system keyring
        keyring_success = True
        try:
            for key, value in credentials.items():
                if isinstance(value, bytes):
                    value = base64.b64encode(value).decode('utf-8')
                keyring.set_password(self.app_name, key, str(value))
        except Exception as e:
            logger.warning(f"Could not save to keyring: {e}")
            keyring_success = False

        # 2. Save to encrypted file if master password provided or if keyring failed
        if master_password:
            try:
                if not self.salt_file.exists():
                    salt = os.urandom(16)
                    self.salt_file.write_bytes(salt)
                else:
                    salt = self.salt_file.read_bytes()

                key = self._derive_key(master_password, salt)
                f = Fernet(key)
                
                # Convert bytes to string for JSON serialization
                serializable_creds = {}
                for k, v in credentials.items():
                    if isinstance(v, bytes):
                        serializable_creds[k] = base64.b64encode(v).decode('utf-8')
                    else:
                        serializable_creds[k] = v
                
                encrypted_data = f.encrypt(json.dumps(serializable_creds).encode())
                self.config_file.write_bytes(encrypted_data)
            except Exception as e:
                logger.error(f"Failed to save encrypted config: {e}")
                if not keyring_success:
                    raise  # Raise if both methods failed

    def load_credentials(self, master_password: str = None) -> dict:
        """Load credentials securely"""
        credentials = {}
        
        # 1. Try loading from keyring first
        fields = ['db_host', 'db_port', 'db_name', 'db_user', 'db_password', 'pepper', 'pwd_key']
        try:
            loaded_from_keyring = True
            for field in fields:
                val = keyring.get_password(self.app_name, field)
                if val is None:
                    loaded_from_keyring = False
                    break
                
                # Handle special fields
                if field == 'db_port':
                    credentials[field] = int(val)
                elif field == 'pwd_key':
                    credentials[field] = base64.b64decode(val)
                else:
                    credentials[field] = val
            
            if loaded_from_keyring:
                return credentials
        except Exception as e:
            logger.warning(f"Error loading from keyring: {e}")

        # 2. Try loading from encrypted file
        if self.config_file.exists():
            if not master_password:
                raise ValueError("Master password required to unlock configuration file")
            
            try:
                salt = self.salt_file.read_bytes()
                key = self._derive_key(master_password, salt)
                f = Fernet(key)
                
                encrypted_data = self.config_file.read_bytes()
                decrypted_data = f.decrypt(encrypted_data)
                
                creds = json.loads(decrypted_data.decode())
                
                # Post-process
                if 'db_port' in creds:
                    creds['db_port'] = int(creds['db_port'])
                if 'pwd_key' in creds:
                    creds['pwd_key'] = base64.b64decode(creds['pwd_key'])
                
                return creds
            except Exception as e:
                logger.error(f"Failed to load encrypted config: {e}")
                raise ValueError("Failed to decrypt configuration. Check master password.")

        raise ValueError("No credentials found in keyring or encrypted file")

    def test_database_connection(self, credentials: dict) -> Tuple[bool, str]:
        """Test if credentials work"""
        import pymysql
        try:
            conn = pymysql.connect(
                host=credentials['db_host'],
                port=int(credentials['db_port']),
                user=credentials['db_user'],
                password=credentials['db_password'],
                database=credentials['db_name'],
                connect_timeout=5
            )
            conn.close()
            return True, "Connection successful!"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    def validate_credentials(self, credentials: dict) -> List[str]:
        """Validate credential format"""
        errors = []
        required = ['db_host', 'db_port', 'db_name', 'db_user', 'db_password', 'pepper', 'pwd_key']
        
        for field in required:
            if field not in credentials or not credentials[field]:
                errors.append(f"Missing required field: {field}")
        
        if 'db_port' in credentials:
            try:
                port = int(credentials['db_port'])
                if not (1 <= port <= 65535):
                    errors.append("Invalid port number (1-65535)")
            except ValueError:
                errors.append("Port must be a number")
                
        if 'pepper' in credentials and len(credentials['pepper']) < 32:
            errors.append("Pepper must be at least 32 characters long")
            
        if 'pwd_key' in credentials:
            # It could be bytes or b64 string at this point depending on where it comes from
            key = credentials['pwd_key']
            if isinstance(key, str):
                try:
                    key = base64.b64decode(key)
                except:
                    errors.append("Encryption key must be valid base64")
            
            if isinstance(key, bytes) and len(key) != 32:
                errors.append("Encryption key must be exactly 32 bytes")

        return errors

    def migrate_from_env(self) -> Optional[dict]:
        """Migrate from .env file to secure storage"""
        from dotenv import load_dotenv
        load_dotenv()
        
        # Check if we have anything to migrate
        if not os.getenv('L8_DB_HOST'):
            return None
            
        credentials = {
            'db_host': os.getenv('L8_DB_HOST'),
            'db_port': int(os.getenv('L8_DB_PORT', '3306')),
            'db_name': os.getenv('L8_DB_NAME'),
            'db_user': os.getenv('MYSQL_USER') or os.getenv('L8_DB_USER'),
            'db_password': os.getenv('MYSQL_PASSWORD') or os.getenv('L8_DB_PASS'),
            'pepper': os.getenv('L8_PEPPER'),
            'pwd_key': os.getenv('L8_PWD_KEY_B64')
        }
        
        # Note: pwd_key might need decoding if it's in B64
        if credentials['pwd_key']:
            try:
                credentials['pwd_key'] = base64.b64decode(credentials['pwd_key'])
            except:
                pass
                
        return credentials
