"""
Layer8 Security Platform - Python Configuration

This module loads configuration from environment variables that should be set via:
1. .env file (loaded automatically on import)
2. System environment variables (takes precedence over .env)
3. Fallback defaults (for initial setup only)

SECURITY NOTES:
- Never commit actual secrets to version control
- Use environment variables in production
- Restrict file permissions on .env files
- Regularly rotate encryption keys

Usage:
    from config import Config
    config = Config()
    
    # Access configuration
    db_host = config.db_host
    pepper = config.pepper
    pwd_key = config.pwd_key_bytes
"""

import os
import base64
import logging
from pathlib import Path
from typing import Optional

# Try to load .env file
try:
    from dotenv import load_dotenv
    import sys

    # Priority 1: PyInstaller temp directory (where bundled files are extracted)
    if getattr(sys, 'frozen', False):
        # Get the PyInstaller temp directory
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            bundle_dir = Path(sys._MEIPASS)
            env_path = bundle_dir / '.env'
            if env_path.exists():
                load_dotenv(env_path)
                logging.info(f"Loaded configuration from PyInstaller bundle: {env_path}")
            else:
                logging.warning(f".env not found in PyInstaller bundle: {env_path}")

        # Also check next to executable (for user-provided .env overrides)
        exe_dir = Path(sys.executable).parent
        env_path = exe_dir / '.env'
        if env_path.exists():
            load_dotenv(env_path, override=True)  # Override bundled config
            logging.info(f"Loaded configuration from executable directory: {env_path}")

    # Priority 2: In the same directory as this file (dev environment)
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path, override=False)
        logging.info(f"Loaded configuration from {env_path}")

    # Priority 3: Parent directory (dev environment fallback)
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        load_dotenv(env_path, override=False)
        logging.info(f"Loaded configuration from {env_path}")

except ImportError:
    logging.warning("python-dotenv not installed, using environment variables only")


class Config:
    """
    Configuration manager for Layer8 Security Platform
    
    This class reads configuration from environment variables and provides
    validated, typed access to all configuration parameters.
    """
    
    def __init__(self):
        """Initialize configuration from environment variables"""
        self._load_config()
        self._validate_config()
    
    def _load_config(self):
        """Load all configuration from environment variables"""
        
        # ==============================================================================
        # DATABASE CONFIGURATION
        # ==============================================================================
        
        self.db_dialect = os.getenv('L8_DB_DIALECT', 'mysql')
        
        # MySQL configuration
        self.db_host = os.getenv('L8_DB_HOST') or os.getenv('MYSQL_HOST', '127.0.0.1')
        self.db_port = int(os.getenv('L8_DB_PORT') or os.getenv('MYSQL_PORT', '3306'))
        self.db_name = os.getenv('L8_DB_NAME') or os.getenv('MYSQL_DATABASE', 'u844677182_app')
        self.db_user = os.getenv('L8_DB_USER') or os.getenv('MYSQL_USER', 'u844677182_Layer8Database')
        self.db_pass = os.getenv('L8_DB_PASS') or os.getenv('MYSQL_PASSWORD', 'Layer8WJA')
        
        # SQLite configuration
        self.db_path = os.getenv('L8_DB_PATH')
        if not self.db_path:
            # Default to db.sqlite3 in the same directory as this file
            self.db_path = str(Path(__file__).parent / 'db.sqlite3')
        
        # ==============================================================================
        # SESSION CONFIGURATION
        # ==============================================================================
        
        self.session_name = os.getenv('L8_SESSION_NAME', 'layer8_admin')
        self.session_secure = os.getenv('L8_SESSION_SECURE', 'true').lower() == 'true'
        self.session_samesite = os.getenv('L8_SESSION_SAMESITE', 'Lax')
        
        # ==============================================================================
        # RATE LIMITING CONFIGURATION
        # ==============================================================================
        
        self.max_failed_attempts = int(os.getenv('L8_MAX_FAILED_ATTEMPTS', '5'))
        self.lockout_window_min = int(os.getenv('L8_LOCKOUT_WINDOW_MIN', '15'))
        
        # ==============================================================================
        # PASSWORD PROTECTION & ENCRYPTION
        # ==============================================================================
        
        # Password Pepper
        self.pepper = os.getenv('L8_PEPPER')
        if not self.pepper:
            # Try to load from file (not recommended)
            pepper_file = Path('C:/secure/layer8_pepper.key')
            if pepper_file.exists():
                self.pepper = pepper_file.read_text().strip()
            else:
                # Development fallback - MUST BE CHANGED IN PRODUCTION
                self.pepper = 'DEV-PEPPER-CHANGE-ME-IN-PRODUCTION'
                logging.warning('Using default pepper! Set L8_PEPPER environment variable in production.')
        
        # Password Encryption Key
        self.pwd_key_id = os.getenv('L8_PWD_KEY_ID', 'k1')
        
        pwd_key_b64 = os.getenv('L8_PWD_KEY_B64')
        self.pwd_key_bytes: Optional[bytes] = None
        
        if pwd_key_b64:
            try:
                decoded = base64.b64decode(pwd_key_b64, validate=True)
                if len(decoded) >= 32:
                    self.pwd_key_bytes = decoded[:32]  # Normalize to exactly 32 bytes
            except Exception as e:
                logging.error(f"Failed to decode L8_PWD_KEY_B64: {e}")
        
        # Try to load from file if not set via environment variable
        if not self.pwd_key_bytes:
            key_file = Path('C:/secure/layer8_pwd_enc.key')
            if key_file.exists():
                try:
                    self.pwd_key_bytes = key_file.read_bytes()
                except Exception as e:
                    logging.error(f"Failed to read key file: {e}")
        
        # Development fallback - derive from default (MUST BE CHANGED IN PRODUCTION)
        if not self.pwd_key_bytes or len(self.pwd_key_bytes) < 32:
            import hashlib
            self.pwd_key_bytes = hashlib.sha256(b'DEV-PWD-KEY-CHANGE-ME-IN-PRODUCTION').digest()
            logging.warning('Using default encryption key! Set L8_PWD_KEY_B64 environment variable in production.')
        
        # Normalize to exactly 32 bytes
        if len(self.pwd_key_bytes) > 32:
            self.pwd_key_bytes = self.pwd_key_bytes[:32]
        elif len(self.pwd_key_bytes) < 32:
            self.pwd_key_bytes = self.pwd_key_bytes + b'\x00' * (32 - len(self.pwd_key_bytes))
        
        # Argon2id Parameters
        self.argon_memory_cost = int(os.getenv('L8_ARGON_MEMORY_COST', str(1 << 17)))  # 131072 = 128 MB
        self.argon_time_cost = int(os.getenv('L8_ARGON_TIME_COST', '3'))
        self.argon_threads = int(os.getenv('L8_ARGON_THREADS', '2'))
        
        # ==============================================================================
        # API KEYS
        # ==============================================================================
        
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY') or os.getenv('CLAUDE_API_KEY')
        
        # ==============================================================================
        # APPLICATION PATHS
        # ==============================================================================
        
        self.data_dir = Path(os.getenv('L8_DATA_DIR', 'data'))
        self.log_dir = Path(os.getenv('L8_LOG_DIR', 'logs'))
    
    def _validate_config(self):
        """Validate critical configuration parameters"""
        
        errors = []
        warnings = []
        
        # Validate database configuration
        if self.db_dialect.lower() == 'mysql':
            if not self.db_host:
                errors.append('MySQL host not configured. Set L8_DB_HOST or MYSQL_HOST.')
            if not self.db_name:
                errors.append('MySQL database not configured. Set L8_DB_NAME or MYSQL_DATABASE.')
            if not self.db_user:
                errors.append('MySQL user not configured. Set L8_DB_USER or MYSQL_USER.')
        
        # Validate encryption configuration
        if self.pepper == 'DEV-PEPPER-CHANGE-ME-IN-PRODUCTION':
            warnings.append('SECURITY WARNING: Default pepper in use! Set L8_PEPPER environment variable.')
        
        if not self.pwd_key_bytes or len(self.pwd_key_bytes) != 32:
            errors.append('SECURITY ERROR: Encryption key must be exactly 32 bytes.')
        
        # Log validation results
        for error in errors:
            logging.error(f"CONFIG ERROR: {error}")
        
        for warning in warnings:
            logging.warning(f"CONFIG WARNING: {warning}")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def get_summary(self) -> dict:
        """
        Get configuration summary for debugging (without exposing secrets)
        
        Returns:
            dict: Configuration summary with sensitive values masked
        """
        return {
            'db_dialect': self.db_dialect,
            'db_host': self.db_host if self.db_dialect.lower() == 'mysql' else 'N/A',
            'db_port': self.db_port if self.db_dialect.lower() == 'mysql' else 'N/A',
            'db_name': self.db_name if self.db_dialect.lower() == 'mysql' else 'N/A',
            'db_user': self.db_user if self.db_dialect.lower() == 'mysql' else 'N/A',
            'session_name': self.session_name,
            'max_failed_attempts': self.max_failed_attempts,
            'lockout_window_min': self.lockout_window_min,
            'pwd_key_id': self.pwd_key_id,
            'argon_memory_mb': round(self.argon_memory_cost / 1024),
            'argon_time_cost': self.argon_time_cost,
            'argon_threads': self.argon_threads,
            'pepper_set': bool(self.pepper and self.pepper != 'DEV-PEPPER-CHANGE-ME-IN-PRODUCTION'),
            'pwd_key_set': bool(self.pwd_key_bytes and len(self.pwd_key_bytes) == 32),
            'anthropic_api_key_set': bool(self.anthropic_api_key)
        }
    
    def __repr__(self):
        """String representation of config (safe for logging)"""
        summary = self.get_summary()
        return f"Config({summary})"


# Singleton instance for easy import
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """
    Get the singleton configuration instance
    
    Returns:
        Config: The global configuration instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance


# For convenience, create a default instance on module import
try:
    config = get_config()
except Exception as e:
    logging.error(f"Failed to load configuration: {e}")
    config = None


if __name__ == "__main__":
    # Test configuration loading
    logging.basicConfig(level=logging.INFO)
    
    try:
        test_config = Config()
        print("\n" + "="*80)
        print("Layer8 Configuration Summary")
        print("="*80)
        
        summary = test_config.get_summary()
        for key, value in summary.items():
            print(f"{key:.<30} {value}")
        
        print("="*80)
        print("\nConfiguration loaded successfully!")
        
        # Validate encryption keys match expected format
        print(f"\nEncryption key length: {len(test_config.pwd_key_bytes)} bytes")
        print(f"Pepper length: {len(test_config.pepper)} characters")
        
    except Exception as e:
        print(f"\nERROR: Failed to load configuration: {e}")
        import traceback
        traceback.print_exc()
