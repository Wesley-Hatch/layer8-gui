"""
Migrate from old .env or hardcoded config to secure storage for Layer8
"""
import os
import sys
from dotenv import load_dotenv
from secure_config import SecureConfig
from setup_wizard import SetupWizard
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('application')

def detect_old_config():
    """Detect if old configuration exists"""
    # Check for .env file
    if os.path.exists('.env'):
        return 'env_file'
    
    # Check for config.py with hardcoded values
    try:
        import config
        # Check if it has the default hardcoded host
        if hasattr(config, 'db_host') and config.db_host == '127.0.0.1':
            return 'config_py'
    except:
        pass
    
    return None

def migrate_from_env():
    """Migrate from .env file"""
    load_dotenv()
    
    config = SecureConfig()
    credentials = config.migrate_from_env()
    
    if not credentials:
        raise ValueError("No credentials found in .env file to migrate.")
        
    # Validate all present (basic check)
    required = ['db_host', 'db_port', 'db_name', 'db_user', 'db_password', 'pepper', 'pwd_key']
    missing = [k for k in required if not credentials.get(k)]
    
    if missing:
        logging.warning(f"Some credentials missing in .env: {missing}")
        logging.info("Falling back to Setup Wizard for missing values.")
        return None # Trigger wizard
    
    return credentials

def run_migration():
    """Run migration wizard"""
    print("=== Layer8 Credential Migration Tool ===\n")
    
    old_type = detect_old_config()
    secure_config = SecureConfig()
    
    if secure_config.is_configured():
        print("Application is already configured with secure storage.")
        choice = input("Do you want to re-run configuration? (y/N): ")
        if choice.lower() != 'y':
            print("Migration aborted.")
            return

    if not old_type:
        print("No old configuration detected. Launching first-time setup wizard...")
        wizard = SetupWizard()
        wizard.run()
        return
    
    print(f"Old configuration detected ({old_type}).")
    
    credentials = None
    if old_type == 'env_file':
        try:
            credentials = migrate_from_env()
        except Exception as e:
            logger.error(f"Migration error: {e}")
            
    if credentials:
        print("\nCredentials detected in .env:")
        print(f"Host: {credentials['db_host']}")
        print(f"Database: {credentials['db_name']}")
        print(f"User: {credentials['db_user']}")
        
        confirm = input("\nMigrate these credentials to secure storage? (Y/n): ")
        if confirm.lower() != 'n':
            master_pwd = input("Enter a master password for local encrypted backup: ")
            if not master_pwd:
                print("Master password is required. Migration aborted.")
                return
                
            try:
                secure_config.save_credentials(credentials, master_pwd)
                print("\n✅ Migration complete!")
                print("Your credentials are now stored in the system keyring and an encrypted file.")
                print("You can now safely delete the .env file.")
            except Exception as e:
                logger.error(f"Failed to save credentials: {e}")
        else:
            print("Migration aborted. Running Setup Wizard instead...")
            wizard = SetupWizard()
            wizard.run()
    else:
        print("Could not automatically migrate. Launching Setup Wizard...")
        wizard = SetupWizard()
        wizard.run()

if __name__ == "__main__":
    run_migration()
