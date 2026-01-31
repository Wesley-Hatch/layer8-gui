"""
Layer8 Security Platform - Database Connection Module
Updated to use unified configuration system (config.py)

This module handles MySQL database connections and user authentication
with secure Argon2id hashing and AES-256-GCM encryption.
"""

import pymysql
import pymysql.cursors
import sqlite3
import logging
import os
import sys
from typing import Optional, Tuple, Dict, Any

# Import unified configuration
try:
    from config import Config

    config = Config()
    CONFIG_AVAILABLE = True
except ImportError:
    logging.warning("config.py not found - using fallback environment variables")
    CONFIG_AVAILABLE = False
    import os
    from dotenv import load_dotenv

    load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='database_connection.log'
)


class DatabaseConnection:
    """
    Handles MySQL database connections and user authentication with secure encryption.

    This class now uses the unified configuration system (config.py) which ensures
    that all encryption keys, database credentials, and hashing parameters are
    synchronized between the Python GUI and PHP web admin.
    """

    def __init__(self):
        """Initialize database connection with unified configuration"""

        if CONFIG_AVAILABLE:
            # Use unified configuration (preferred)
            self.dialect = getattr(config, 'db_dialect', 'mysql')
            self.db_path = getattr(config, 'db_path', 'db.sqlite3')
            self.host = config.db_host
            self.user = config.db_user
            self.password = config.db_pass
            self.database = config.db_name
            self.port = config.db_port

            # Security parameters
            self.pepper = config.pepper
            self.pwd_key = config.pwd_key_bytes
            self.pwd_key_id = config.pwd_key_id

            # Argon2id parameters
            self.argon_memory_cost = config.argon_memory_cost
            self.argon_time_cost = config.argon_time_cost
            self.argon_threads = config.argon_threads

            logging.info(f"Using unified configuration (Dialect: {self.dialect})")
        else:
            # Fallback to environment variables (legacy support)
            import os
            import base64

            self.dialect = os.getenv('L8_DB_DIALECT', 'mysql')
            self.db_path = os.getenv('L8_DB_PATH', 'db.sqlite3')
            self.host = os.getenv('L8_DB_HOST', '82.197.82.156')
            self.user = os.getenv('MYSQL_USER', 'u844677182_Layer8Database')
            self.password = os.getenv('MYSQL_PASSWORD', 'Layer8WJA')
            self.database = os.getenv('L8_DB_NAME', 'u844677182_app')
            self.port = int(os.getenv('L8_DB_PORT', '3306'))

            # Security parameters (fallback)
            self.pepper = os.getenv('L8_PEPPER', 'DEV-PEPPER-CHANGE-ME')
            pwd_key_b64 = os.getenv('L8_PWD_KEY_B64', '')
            if pwd_key_b64:
                self.pwd_key = base64.b64decode(pwd_key_b64)[:32]
            else:
                import hashlib
                self.pwd_key = hashlib.sha256(b'DEV-PWD-KEY-CHANGE-ME').digest()
            self.pwd_key_id = os.getenv('L8_PWD_KEY_ID', 'k1')

            # Argon2id parameters (fallback)
            self.argon_memory_cost = int(os.getenv('L8_ARGON_MEMORY_COST', '131072'))
            self.argon_time_cost = int(os.getenv('L8_ARGON_TIME_COST', '3'))
            self.argon_threads = int(os.getenv('L8_ARGON_THREADS', '2'))

            logging.warning("Using fallback environment variables - install config.py for better integration")

        self.connection: Optional[Any] = None
        self.last_error: Optional[str] = None
        self.current_user: Optional[Dict[str, Any]] = None
        self.placeholder = "?" if self.dialect == 'sqlite' else "%s"

        if self.dialect == 'sqlite':
            logging.info(f"DatabaseConnection initialized for SQLite: {self.db_path}")
        else:
            logging.info(f"DatabaseConnection initialized for MySQL: {self.database}@{self.host}")
        
        logging.debug(f"Pepper length: {len(self.pepper)} chars, Key length: {len(self.pwd_key)} bytes")

    def connect(self) -> Tuple[bool, Optional[str]]:
        """
        Establish connection to database (MySQL or SQLite).

        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            if self.dialect == 'sqlite':
                logging.info(f"Connecting to SQLite database: {self.db_path}")
                # Ensure directory exists
                os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
                self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
                # Enable dictionary-like results
                self.connection.row_factory = sqlite3.Row
                logging.info("Successfully connected to SQLite")
                return True, None
            else:
                logging.info(f"Attempting to connect to MySQL at {self.host}:{self.port}")

                # Use PyMySQL (pure Python, PyInstaller compatible)
                self.connection = pymysql.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.database,
                    connect_timeout=8,
                    autocommit=True,
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor
                )

                if self.connection.open:
                    logging.info(f"Successfully connected to MySQL Server")
                    return True, None
                else:
                    self.last_error = "Connection object created but not connected"
                    logging.error(self.last_error)
                    return False, self.last_error

        except pymysql.Error as e:
            self.last_error = f"Database error {e.args[0]}: {e.args[1] if len(e.args) > 1 else str(e)}"
            logging.error(self.last_error)
            return False, self.last_error
        except Exception as e:
            self.last_error = f"Database connection error: {str(e)}"
            logging.error(self.last_error)
            return False, self.last_error

    def _parse_mysql_error(self, error: pymysql.Error) -> str:
        """Parse MySQL error and return user-friendly message"""
        error_messages = {
            2003: "Cannot connect to database server. Check if Remote MySQL is enabled in Hostinger and your IP is whitelisted.",
            1045: "Access denied. Invalid username or password.",
            1049: f"Database '{self.database}' does not exist.",
            2013: "Lost connection to MySQL server during query.",
            2006: "MySQL server has gone away.",
            1146: "Table doesn't exist in the database.",
        }

        errno = error.args[0] if error.args else 0
        friendly = error_messages.get(errno)
        if friendly:
            errmsg = error.args[1] if len(error.args) > 1 else str(error)
            return f"{friendly} (Error {errno}: {errmsg})"

        return f"Database error: {str(error)}"

    # =========================================================================
    # PASSWORD HASHING & ENCRYPTION (Synchronized with PHP)
    # =========================================================================

    def pepper_password(self, password: str, style: str = 'colon') -> str:
        """
        Add pepper to password before hashing.

        CRITICAL: This must match PHP's pepper_password() function exactly.
        The PHP backend has used both direct concatenation and colon delimiter.
        Currently, the PHP reset script uses colon delimiter (password:pepper).

        Args:
            password: Plain text password
            style: 'colon' (default) or 'direct'

        Returns:
            str: Peppered password
        """
        if style == 'colon':
            return f"{password}:{self.pepper}"
        else:
            return f"{password}{self.pepper}"

    def argon_hash(self, password: str) -> str:
        """
        Hash a peppered password with Argon2id.

        This matches PHP's argon_hash() behavior exactly:
        - Uses same memory_cost, time_cost, and parallelism
        - Returns Argon2id hash in PHC string format

        Args:
            password: Plain text password

        Returns:
            str: Argon2id hash in PHC format ($argon2id$...)
        """
        try:
            from argon2 import PasswordHasher
            from argon2.low_level import Type

            # Use 'colon' style to match current PHP reset behavior
            peppered = self.pepper_password(password, style='colon')

            # Match PHP's argon options exactly
            ph = PasswordHasher(
                memory_cost=self.argon_memory_cost,  # 131072 = 128 MB (1 << 17)
                time_cost=self.argon_time_cost,  # 3 iterations
                parallelism=self.argon_threads,  # 2 threads
                hash_len=32,
                salt_len=16,
                type=Type.ID  # Argon2id (hybrid mode)
            )

            hash_result = ph.hash(peppered)
            logging.debug(f"Generated Argon2id hash: {hash_result[:50]}...")
            return hash_result

        except ImportError:
            logging.error("argon2-cffi not installed - password hashing unavailable")
            logging.error("Install with: pip install argon2-cffi")
            # Return peppered password as fallback (INSECURE - dev only)
            return peppered

        except Exception as e:
            logging.error(f"Argon2 hashing error: {e}")
            return peppered

    def seal_hash(self, hash_plaintext: str) -> str:
        """
        Encrypt hash for storage using AES-256-GCM.

        This matches PHP's seal_hash() function:
        - Uses same encryption key (pwd_key)
        - Same AES-256-GCM algorithm
        - Same format: keyid:base64(nonce:tag:ciphertext)

        Format: "k1:base64(nonce + tag + ciphertext)"

        Args:
            hash_plaintext: The Argon2id hash to encrypt

        Returns:
            str: Encrypted hash with key ID prefix
        """
        if not self.pwd_key or len(self.pwd_key) != 32:
            logging.warning("Invalid encryption key - using plaintext storage (INSECURE)")
            import base64
            return f"plain:{base64.b64encode(hash_plaintext.encode()).decode()}"

        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
            import base64

            # Create cipher with random 12-byte nonce (standard for GCM and matches PHP)
            nonce = get_random_bytes(12)
            cipher = AES.new(self.pwd_key, AES.MODE_GCM, nonce=nonce)

            # Encrypt and get authentication tag
            ciphertext, tag = cipher.encrypt_and_digest(hash_plaintext.encode('utf-8'))

            # Format: nonce (12 bytes) + tag (16 bytes) + ciphertext
            # This matches PHP's openssl_encrypt with 'aes-256-gcm'
            blob = nonce + tag + ciphertext

            # Return with key ID prefix: "k1:base64data"
            sealed = f"{self.pwd_key_id}:{base64.b64encode(blob).decode()}"

            logging.debug(f"Sealed hash with key {self.pwd_key_id}: {sealed[:50]}...")
            return sealed

        except ImportError:
            logging.error("pycryptodome not installed - encryption unavailable")
            logging.error("Install with: pip install pycryptodome")
            import base64
            return f"plain:{base64.b64encode(hash_plaintext.encode()).decode()}"

        except Exception as e:
            logging.error(f"AES encryption error: {e}")
            import base64
            return f"plain:{base64.b64encode(hash_plaintext.encode()).decode()}"

    def unseal_hash(self, sealed_blob: str) -> Optional[str]:
        """
        Decrypt the stored blob back into the original hash string.

        This matches PHP's unseal_hash() function:
        - Parses keyid:base64data format
        - Uses same AES-256-GCM decryption
        - Verifies authentication tag

        Args:
            sealed_blob: Encrypted hash from database (format: "k1:base64data")

        Returns:
            Optional[str]: Decrypted Argon2id hash, or None if decryption fails
        """
        try:
            import base64

            # Check for plaintext format (dev/fallback)
            if sealed_blob.startswith('plain:'):
                logging.warning("Detected plaintext storage - decoding as base64")
                return base64.b64decode(sealed_blob[6:]).decode('utf-8')

            # Parse format: "keyid:base64data"
            if ':' not in sealed_blob:
                logging.error("Invalid sealed format - missing key ID")
                # Try as raw base64 (legacy format)
                try:
                    raw = base64.b64decode(sealed_blob)
                except:
                    return None
            else:
                parts = sealed_blob.split(':', 1)
                key_id = parts[0]

                if key_id != self.pwd_key_id:
                    logging.warning(f"Key ID mismatch: stored={key_id}, current={self.pwd_key_id}")
                    # Continue anyway - might be during key rotation

                raw = base64.b64decode(parts[1])

            # Decrypt with AES-256-GCM
            from Crypto.Cipher import AES

            if len(raw) < 28:  # Min: 12 (nonce) + 16 (tag) + 0 (ciphertext)
                logging.error(f"Encrypted blob too short: {len(raw)} bytes")
                return None

            # Extract: nonce (12 bytes) + tag (16 bytes) + ciphertext
            nonce = raw[:12]
            tag = raw[12:28]
            ciphertext = raw[28:]

            # Create cipher and decrypt
            cipher = AES.new(self.pwd_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            result = plaintext.decode('utf-8')
            logging.debug(f"Successfully unsealed hash: {result[:50]}...")
            return result

        except ImportError:
            logging.error("pycryptodome not installed")
            return None

        except Exception as e:
            logging.error(f"Unseal error: {e}")
            logging.debug(f"Failed blob: {sealed_blob[:100]}...")
            return None

    def verify_password(self, password: str, sealed_hash: str) -> bool:
        """
        Verify password against sealed (encrypted) hash from database.

        Process:
        1. Unseal (decrypt) the hash
        2. Add pepper to password
        3. Verify with Argon2id

        Args:
            password: Plain text password to verify
            sealed_hash: Encrypted hash from database

        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError, InvalidHashError
        except ImportError:
            logging.error("argon2-cffi not installed")
            return False

        # 1. Unseal (decrypt) the hash
        plaintext_hash = self.unseal_hash(sealed_hash)
        if not plaintext_hash:
            logging.warning("Failed to unseal hash")
            return False

        # 2. Verify with Argon2 - Try multiple pepper styles for compatibility
        ph = PasswordHasher()

        try:
            if plaintext_hash.startswith('$argon2'):
                # Style 1: Colon delimiter (Current PHP reset style)
                try:
                    ph.verify(plaintext_hash, self.pepper_password(password, style='colon'))
                    logging.info("Password verification successful (colon style)")
                    return True
                except VerifyMismatchError:
                    pass

                # Style 2: Direct concatenation (Legacy style)
                try:
                    ph.verify(plaintext_hash, self.pepper_password(password, style='direct'))
                    logging.info("Password verification successful (direct style)")
                    return True
                except VerifyMismatchError:
                    pass

                logging.debug("Password verification failed for all pepper styles")
                return False
            else:
                # Not an Argon2 hash - might be legacy/plaintext
                logging.warning(f"Hash doesn't start with $argon2: {plaintext_hash[:20]}...")
                # Try both styles for legacy comparison
                return (self.pepper_password(password, style='colon') == plaintext_hash or
                        self.pepper_password(password, style='direct') == plaintext_hash)

        except VerifyMismatchError:
            logging.debug("Password verification failed - incorrect password")
            return False

        except InvalidHashError as e:
            logging.error(f"Invalid hash format: {e}")
            return False

        except Exception as e:
            logging.error(f"Verification error: {e}")
            return False

    # =========================================================================
    # DATABASE OPERATIONS
    # =========================================================================

    def _is_active_connection(self) -> bool:
        """Check if database connection is active"""
        if not self.connection:
            return False

        if self.dialect == 'sqlite':
            try:
                self.connection.execute("SELECT 1")
                return True
            except:
                return False
        else:
            # PyMySQL: check if connection is open
            try:
                return self.connection.open
            except:
                return False

    def verify_login(self, username: str, password: str) -> Tuple[bool, Any]:
        """
        Verify user credentials against database securely.
        Supports both 'users' (PHP) and 'user_logins' (Python) tables.

        Args:
            username: Username to verify
            password: Plain text password to verify

        Returns:
            Tuple[bool, Any]: (success, user_data_dict or error_message)
        """
        logging.info(f"Login attempt for username: {username}")

        # Ensure we have a connection
        if not self._is_active_connection():
            logging.warning("No active connection, attempting to connect...")
            success, error = self.connect()
            if not success:
                logging.error(f"Connection failed: {error}")
                return False, error

        try:
            if self.dialect == 'sqlite':
                cursor = self.connection.cursor()
            else:
                cursor = self.connection.cursor(dictionary=True)

            user = None
            
            # 1. Try 'users' table (PHP backend standard)
            try:
                query = f"SELECT * FROM users WHERE username = {self.placeholder}"
                cursor.execute(query, (username,))
                user = cursor.fetchone()
                
                if user:
                    if self.dialect == 'sqlite': user = dict(user)
                    logging.debug(f"User found in 'users' table")
                    # Map PHP columns to standard internal format
                    if 'role' in user:
                        user['is_admin'] = user.get('role') in ['admin', 'superadmin', 'staff']
                    
                    # Handle password hash and key ID
                    pwd_enc = user.get('password_hash_enc')
                    k_id = user.get('k_id', self.pwd_key_id)
                    
                    if pwd_enc:
                        # Prepend key ID if not already there
                        if ':' not in str(pwd_enc):
                            user['password'] = f"{k_id}:{pwd_enc}"
                        else:
                            user['password'] = pwd_enc
            except Exception as e:
                logging.debug(f"Table 'users' not available or error: {e}")

            # 2. Try 'user_logins' table if not found in 'users'
            if not user:
                try:
                    query = f"SELECT * FROM user_logins WHERE username = {self.placeholder}"
                    cursor.execute(query, (username,))
                    user = cursor.fetchone()
                    
                    if user:
                        if self.dialect == 'sqlite': user = dict(user)
                        logging.debug(f"User found in 'user_logins' table")
                except Exception as e:
                    logging.debug(f"Table 'user_logins' not available or error: {e}")

            cursor.close()

            if user:
                # Handle various password column names
                stored_hash = user.get('password') or user.get('password_hash') or user.get('password_hash_enc')

                if self.verify_password(password, stored_hash):
                    logging.info(f"Login successful for user: {username} (ID: {user.get('id', 'N/A')})")
                    self.current_user = user
                    return True, user
                else:
                    logging.warning(f"Login failed for user: {username} - Invalid password")
                    return False, "Invalid username or password"
            else:
                logging.warning(f"Login failed for user: {username} - User not found")
                return False, "Invalid username or password"

        except Exception as e:
            if self.dialect == 'mysql' and isinstance(e, pymysql.Error):
                error_msg = self._parse_mysql_error(e)
            else:
                error_msg = f"Unexpected error during login: {str(e)}"
            logging.error(error_msg)
            return False, error_msg

    def create_user(self, username: str, password: str, email: str = "", is_admin: bool = False) -> Tuple[bool, str]:
        """
        Create a new user in the database with secure hashing.
        Automatically uses 'users' table if it exists in MySQL.

        Args:
            username: Username for new user
            password: Plain text password (will be hashed and encrypted)
            email: Email address (optional)
            is_admin: Whether user has admin privileges

        Returns:
            Tuple[bool, str]: (success, message)
        """
        if not self._is_active_connection():
            success, error = self.connect()
            if not success:
                return False, error

        try:
            import time
            cursor = self.connection.cursor()

            # Hash and seal password
            hashed = self.argon_hash(password)
            sealed = self.seal_hash(hashed)
            
            # Check if 'users' table exists to stay compatible with PHP
            use_users_table = False
            if self.dialect == 'mysql':
                cursor.execute("SHOW TABLES LIKE 'users'")
                if cursor.fetchone():
                    use_users_table = True

            if use_users_table:
                # Map to 'users' table columns
                role = 'admin' if is_admin else 'user'
                # Remove key ID prefix for PHP compatibility (stored in k_id column)
                sealed_data = sealed.split(':', 1)[1] if ':' in sealed else sealed
                
                now = time.strftime('%Y-%m-%d %H:%M:%S')
                query = f"""
                        INSERT INTO users (username, email, password_hash_enc, k_id, role, active, created_at, updated_at)
                        VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, 
                                {self.placeholder}, 1, {self.placeholder}, {self.placeholder})
                        """
                cursor.execute(query, (username, email, sealed_data, self.pwd_key_id, role, now, now))
            else:
                # Use default 'user_logins' table
                query = f"""
                        INSERT INTO user_logins (username, email, password, is_admin)
                        VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})
                        """
                cursor.execute(query, (username, email, sealed, is_admin))

            self.connection.commit()
            cursor.close()

            logging.info(f"User created successfully: {username}")
            return True, "User created successfully"

        except Exception as e:
            if self.dialect == 'mysql' and isinstance(e, pymysql.Error):
                errno = e.args[0] if e.args else 0
                if errno == 1062:  # Duplicate entry
                    return False, "Username already exists"
                error_msg = self._parse_mysql_error(e)
            else:
                error_msg = f"User creation error: {str(e)}"

            logging.error(error_msg)
            return False, error_msg

    def ensure_table_exists(self) -> Tuple[bool, str]:
        """
        Ensure a valid user table exists.
        Checks for 'users' (PHP) first, then 'user_logins'.

        Returns:
            Tuple[bool, str]: (success, message)
        """
        if not self._is_active_connection():
            success, error = self.connect()
            if not success:
                return False, error

        try:
            cursor = self.connection.cursor()

            # Check for PHP 'users' table first
            if self.dialect == 'sqlite':
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
            else:
                cursor.execute("SHOW TABLES LIKE 'users';")
            
            if cursor.fetchone():
                logging.info("Table 'users' already exists")
                cursor.close()
                return True, "Table 'users' exists"

            # Check for 'user_logins' table
            if self.dialect == 'sqlite':
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_logins';")
            else:
                cursor.execute("SHOW TABLES LIKE 'user_logins';")
            
            result = cursor.fetchone()

            if not result:
                logging.info("Creating user_logins table...")

                if self.dialect == 'sqlite':
                    create_table_sql = """
                                       CREATE TABLE user_logins \
                                       ( \
                                           id         INTEGER PRIMARY KEY AUTOINCREMENT, \
                                           username   VARCHAR(255) NOT NULL UNIQUE, \
                                           email      VARCHAR(255) DEFAULT '', \
                                           password   VARCHAR(512) NOT NULL, \
                                           is_admin   BOOLEAN      DEFAULT FALSE, \
                                           created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
                                       ); \
                                       """
                else:
                    create_table_sql = """
                                       CREATE TABLE user_logins \
                                       ( \
                                           id         INT AUTO_INCREMENT PRIMARY KEY, \
                                           username   VARCHAR(255) NOT NULL UNIQUE, \
                                           email      VARCHAR(255) DEFAULT '', \
                                           password   VARCHAR(512) NOT NULL, \
                                           is_admin   BOOLEAN      DEFAULT FALSE, \
                                           created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP, \
                                           INDEX      idx_username (username)
                                       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4; \
                                       """

                cursor.execute(create_table_sql)
                logging.info("Table created successfully")

                # Create default admin user
                self.create_user('Layer8Wes', 'Valorant123!', 'wesley@layer8.io', True)
                self.create_user('admin', 'admin123', 'admin@layer8.io', True)

                logging.info("Default users created")
                cursor.close()
                return True, "Table created with default users"
            else:
                cursor.close()
                return True, "Table already exists"

        except Exception as e:
            if self.dialect == 'mysql' and isinstance(e, pymysql.Error):
                error_msg = self._parse_mysql_error(e)
            else:
                error_msg = f"Table creation error: {str(e)}"
            logging.error(error_msg)
            return False, error_msg

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test the database connection and setup.

        Returns:
            Tuple[bool, str]: (success, message)
        """
        # Test connection
        success, error = self.connect()
        if not success:
            return False, f"Connection failed: {error}"

        # Ensure table exists
        success, message = self.ensure_table_exists()
        if not success:
            return False, f"Table setup failed: {message}"

        # Test login with default credentials (try Layer8Wes or admin)
        success, result = self.verify_login('Layer8Wes', 'Valorant123!')
        if not success:
            success, result = self.verify_login('admin', 'admin123')
            
        if not success:
            return False, f"Login test failed: {result}"

        return True, "All tests passed successfully"

    def close(self):
        """Close database connection"""
        if self._is_active_connection():
            self.connection.close()
            logging.info("Database connection closed")

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# ============================================================================
# TESTING & DIAGNOSTICS
# ============================================================================

def quick_test():
    """Quick test of database connection"""
    print("=" * 80)
    print("Layer8 Database Connection Test")
    print("=" * 80)
    print()

    print("Testing database connection...")

    db = DatabaseConnection()

    # Show configuration
    print("\nConfiguration:")
    print(f"  Host: {db.host}:{db.port}")
    print(f"  Database: {db.database}")
    print(f"  User: {db.user}")
    print(f"  Pepper Length: {len(db.pepper)} chars")
    print(f"  Key Length: {len(db.pwd_key)} bytes")
    print(f"  Key ID: {db.pwd_key_id}")
    print(
        f"  Argon2id: {db.argon_memory_cost // 1024}MB / {db.argon_time_cost} iterations / {db.argon_threads} threads")
    print()

    success, message = db.test_connection()

    if success:
        print(f"✅ SUCCESS: {message}")
        print("\nYou can now use these credentials to login:")
        print("  Username: Layer8Wes")
        print("  Password: Valorant123!")
        print("\n  Username: admin")
        print("  Password: admin123")
    else:
        print(f"❌ FAILED: {message}")
        print("\nCheck database_connection.log for details")

    print()
    print("=" * 80)

    db.close()


if __name__ == "__main__":
    quick_test()