"""
Layer8 GUI Auto-Updater Module

This module handles automatic updates for the Layer8 GUI application.
It checks for updates, downloads them, and applies them safely.

Features:
- Checks GitHub releases for new versions
- Downloads updates securely
- Validates checksums
- Creates backups before updating
- Rollback capability if update fails
- Silent background updates or user-prompted updates
"""

import os
import sys
import json
import hashlib
import shutil
import zipfile
import tempfile
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='updater.log'
)
logger = logging.getLogger('Layer8Updater')


class Layer8Updater:
    """
    Auto-updater for Layer8 GUI Application
    
    Usage:
        updater = Layer8Updater(
            current_version="1.0.0",
            update_url="https://api.github.com/repos/yourusername/layer8-gui/releases/latest",
            app_directory=Path(__file__).parent
        )
        
        # Check for updates
        if updater.check_for_updates():
            print(f"New version available: {updater.latest_version}")
            
            # Download and install
            if updater.download_update():
                updater.install_update()
    """
    
    def __init__(
        self,
        current_version: str,
        update_url: str,
        app_directory: Path,
        github_token: Optional[str] = None,
        auto_check_interval: int = 86400  # 24 hours in seconds
    ):
        """
        Initialize the updater
        
        Args:
            current_version: Current version (e.g., "1.0.0")
            update_url: URL to check for updates (GitHub API endpoint)
            app_directory: Directory where the app is installed
            github_token: Optional GitHub API token for private repos
            auto_check_interval: How often to check for updates (seconds)
        """
        self.current_version = current_version
        self.update_url = update_url
        self.app_directory = Path(app_directory)
        self.github_token = github_token
        self.auto_check_interval = auto_check_interval
        
        self.latest_version: Optional[str] = None
        self.download_url: Optional[str] = None
        self.update_info: Optional[Dict] = None
        self.download_path: Optional[Path] = None
        
        # Paths
        self.backup_dir = self.app_directory / "backups"
        self.temp_dir = self.app_directory / "temp_update"
        self.version_file = self.app_directory / "version.json"
        self.update_config_file = self.app_directory / "update_config.json"
        
        # Ensure directories exist
        self.backup_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)
        
        logger.info(f"Updater initialized: v{current_version}")
    
    # =========================================================================
    # VERSION MANAGEMENT
    # =========================================================================
    
    def get_current_version(self) -> str:
        """Get current version from version file or constructor"""
        if self.version_file.exists():
            try:
                with open(self.version_file, 'r') as f:
                    data = json.load(f)
                    return data.get('version', self.current_version)
            except:
                pass
        return self.current_version
    
    def save_version(self, version: str):
        """Save version to file"""
        version_data = {
            'version': version,
            'updated_at': datetime.now().isoformat(),
            'previous_version': self.current_version
        }
        
        with open(self.version_file, 'w') as f:
            json.dump(version_data, f, indent=2)
    
    @staticmethod
    def compare_versions(version1: str, version2: str) -> int:
        """
        Compare two semantic versions
        
        Returns:
            1 if version1 > version2
            0 if version1 == version2
            -1 if version1 < version2
        """
        def parse_version(v):
            # Remove 'v' prefix if present
            v = v.lstrip('v')
            # Split into parts and convert to integers
            parts = []
            for part in v.split('.'):
                # Remove non-numeric suffixes (e.g., "1.0.0-beta" -> "1.0.0")
                numeric = ''.join(c for c in part if c.isdigit())
                parts.append(int(numeric) if numeric else 0)
            # Ensure we have at least 3 parts (major.minor.patch)
            while len(parts) < 3:
                parts.append(0)
            return parts
        
        v1_parts = parse_version(version1)
        v2_parts = parse_version(version2)
        
        for i in range(3):
            if v1_parts[i] > v2_parts[i]:
                return 1
            elif v1_parts[i] < v2_parts[i]:
                return -1
        
        return 0
    
    # =========================================================================
    # UPDATE CHECKING
    # =========================================================================
    
    def check_for_updates(self, force: bool = False) -> bool:
        """
        Check if updates are available
        
        Args:
            force: Force check even if recently checked
            
        Returns:
            bool: True if update is available
        """
        # Check if we should skip (already checked recently)
        if not force and not self._should_check_for_updates():
            logger.info("Skipping update check (checked recently)")
            return False
        
        try:
            logger.info("Checking for updates...")
            
            # Try to import requests, fall back to urllib if not available
            try:
                import requests
                use_requests = True
            except ImportError:
                import urllib.request
                import urllib.error
                use_requests = False
                logger.warning("requests library not available, using urllib")
            
            # Prepare headers
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Layer8-GUI-Updater'
            }
            
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            # Fetch release info
            if use_requests:
                response = requests.get(self.update_url, headers=headers, timeout=10)
                response.raise_for_status()
                release_info = response.json()
            else:
                req = urllib.request.Request(self.update_url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as response:
                    release_info = json.loads(response.read().decode())
            
            # Parse release info
            self.latest_version = release_info.get('tag_name', '').lstrip('v')
            
            # Find download URL for the appropriate platform
            assets = release_info.get('assets', [])
            
            # Determine platform
            platform = sys.platform
            if platform == 'win32':
                asset_name = 'layer8-gui-windows.zip'
            elif platform == 'darwin':
                asset_name = 'layer8-gui-macos.zip'
            else:
                asset_name = 'layer8-gui-linux.zip'
            
            # Find matching asset
            for asset in assets:
                if asset_name in asset['name'].lower():
                    self.download_url = asset['browser_download_url']
                    break
            
            if not self.download_url:
                logger.warning(f"No download found for platform: {platform}")
                return False
            
            self.update_info = release_info
            
            # Compare versions
            if self.compare_versions(self.latest_version, self.current_version) > 0:
                logger.info(f"Update available: {self.current_version} -> {self.latest_version}")
                self._save_update_check_time()
                return True
            else:
                logger.info(f"Already on latest version: {self.current_version}")
                self._save_update_check_time()
                return False
        
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return False
    
    def _should_check_for_updates(self) -> bool:
        """Check if enough time has passed since last update check"""
        if not self.update_config_file.exists():
            return True
        
        try:
            with open(self.update_config_file, 'r') as f:
                config = json.load(f)
                last_check = datetime.fromisoformat(config.get('last_check', ''))
                next_check = last_check + timedelta(seconds=self.auto_check_interval)
                return datetime.now() >= next_check
        except:
            return True
    
    def _save_update_check_time(self):
        """Save the time of the last update check"""
        config = {
            'last_check': datetime.now().isoformat(),
            'latest_version': self.latest_version
        }
        
        with open(self.update_config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    # =========================================================================
    # DOWNLOADING
    # =========================================================================
    
    def download_update(self, progress_callback=None) -> bool:
        """
        Download the update
        
        Args:
            progress_callback: Optional callback(bytes_downloaded, total_bytes)
            
        Returns:
            bool: True if download successful
        """
        if not self.download_url:
            logger.error("No download URL available")
            return False
        
        try:
            logger.info(f"Downloading update from {self.download_url}")
            
            # Download to temp file
            self.download_path = self.temp_dir / f"update-{self.latest_version}.zip"
            
            # Try to import requests, fall back to urllib
            try:
                import requests
                
                response = requests.get(self.download_url, stream=True, timeout=30)
                response.raise_for_status()
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                
                with open(self.download_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            if progress_callback:
                                progress_callback(downloaded, total_size)
            
            except ImportError:
                import urllib.request
                
                with urllib.request.urlopen(self.download_url, timeout=30) as response:
                    total_size = int(response.headers.get('content-length', 0))
                    downloaded = 0
                    
                    with open(self.download_path, 'wb') as f:
                        while True:
                            chunk = response.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            if progress_callback:
                                progress_callback(downloaded, total_size)
            
            logger.info(f"Download complete: {self.download_path}")
            
            # Verify download (optional checksum verification)
            if self.update_info and 'checksum' in self.update_info:
                if not self._verify_checksum(self.download_path, self.update_info['checksum']):
                    logger.error("Checksum verification failed!")
                    return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error downloading update: {e}")
            return False
    
    def _verify_checksum(self, file_path: Path, expected_checksum: str) -> bool:
        """Verify file checksum (SHA256)"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            actual_checksum = sha256_hash.hexdigest()
            return actual_checksum == expected_checksum
        
        except Exception as e:
            logger.error(f"Error verifying checksum: {e}")
            return False
    
    # =========================================================================
    # INSTALLATION
    # =========================================================================
    
    def install_update(self) -> bool:
        """
        Install the downloaded update
        
        Returns:
            bool: True if installation successful
        """
        if not self.download_path or not self.download_path.exists():
            logger.error("No download file found")
            return False
        
        try:
            logger.info("Installing update...")
            
            # 1. Create backup
            backup_path = self._create_backup()
            if not backup_path:
                logger.error("Failed to create backup")
                return False
            
            logger.info(f"Backup created: {backup_path}")
            
            # 2. Extract update
            extract_dir = self.temp_dir / "extracted"
            extract_dir.mkdir(exist_ok=True)
            
            with zipfile.ZipFile(self.download_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            logger.info("Update extracted")
            
            # 3. Replace files
            self._replace_files(extract_dir)
            
            # 4. Update version
            self.save_version(self.latest_version)
            self.current_version = self.latest_version
            
            # 5. Cleanup
            self._cleanup_temp_files()
            
            logger.info("Update installed successfully!")
            return True
        
        except Exception as e:
            logger.error(f"Error installing update: {e}")
            
            # Attempt rollback
            if backup_path:
                logger.info("Attempting rollback...")
                self._rollback(backup_path)
            
            return False
    
    def _create_backup(self) -> Optional[Path]:
        """Create backup of current installation"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_v{self.current_version}_{timestamp}"
            backup_path = self.backup_dir / backup_name
            
            # Copy all files except backups and temp
            shutil.copytree(
                self.app_directory,
                backup_path,
                ignore=shutil.ignore_patterns('backups', 'temp_update', '*.log', '__pycache__', '*.pyc')
            )
            
            return backup_path
        
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return None
    
    def _replace_files(self, source_dir: Path):
        """Replace app files with updated files"""
        # Get list of files to replace
        for item in source_dir.rglob('*'):
            if item.is_file():
                # Calculate relative path
                rel_path = item.relative_to(source_dir)
                dest_path = self.app_directory / rel_path
                
                # Create parent directory if needed
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy file
                shutil.copy2(item, dest_path)
                logger.debug(f"Updated: {rel_path}")
    
    def _rollback(self, backup_path: Path) -> bool:
        """Rollback to backup"""
        try:
            logger.info(f"Rolling back to backup: {backup_path}")
            
            # Remove current files (except backups)
            for item in self.app_directory.iterdir():
                if item.name not in ['backups', 'temp_update']:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
            
            # Restore from backup
            for item in backup_path.rglob('*'):
                if item.is_file():
                    rel_path = item.relative_to(backup_path)
                    dest_path = self.app_directory / rel_path
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest_path)
            
            logger.info("Rollback successful")
            return True
        
        except Exception as e:
            logger.error(f"Error during rollback: {e}")
            return False
    
    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.temp_dir.mkdir(exist_ok=True)
            
            logger.info("Temp files cleaned up")
        
        except Exception as e:
            logger.warning(f"Error cleaning up temp files: {e}")
    
    # =========================================================================
    # AUTO-UPDATE
    # =========================================================================
    
    def auto_update(self, silent: bool = False, restart_callback=None) -> bool:
        """
        Perform automatic update check and install
        
        Args:
            silent: If True, update silently without user interaction
            restart_callback: Function to call when restart is needed
            
        Returns:
            bool: True if update was installed
        """
        logger.info("Starting auto-update check...")
        
        if not self.check_for_updates():
            return False
        
        logger.info(f"Update available: {self.latest_version}")
        
        if not silent:
            # In a GUI, you'd show a dialog here
            # For now, just log
            logger.info("Update available notification shown to user")
        
        # Download
        if not self.download_update():
            return False
        
        # Install
        if not self.install_update():
            return False
        
        # Restart required
        if restart_callback:
            restart_callback()
        
        return True
    
    def start_background_checker(self):
        """Start background thread that periodically checks for updates"""
        def check_loop():
            while True:
                try:
                    if self.check_for_updates():
                        logger.info(f"Background check found update: {self.latest_version}")
                        # You can trigger a notification here
                    
                    # Sleep for check interval
                    import time
                    time.sleep(self.auto_check_interval)
                
                except Exception as e:
                    logger.error(f"Error in background checker: {e}")
                    import time
                    time.sleep(3600)  # Sleep 1 hour on error
        
        thread = threading.Thread(target=check_loop, daemon=True)
        thread.start()
        logger.info("Background update checker started")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def check_for_updates_simple(current_version: str, update_url: str) -> Tuple[bool, Optional[str]]:
    """
    Simple update check
    
    Returns:
        (update_available, latest_version)
    """
    updater = Layer8Updater(
        current_version=current_version,
        update_url=update_url,
        app_directory=Path.cwd()
    )
    
    has_update = updater.check_for_updates(force=True)
    return has_update, updater.latest_version


if __name__ == "__main__":
    # Example usage
    updater = Layer8Updater(
        current_version="1.0.1",
        update_url="https://api.github.com/repos/Wesley-Hatch/Layer8-GUI/releases/latest",
        app_directory=Path(__file__).parent
    )
    
    print(f"Current version: {updater.current_version}")
    print("Checking for updates...")
    
    if updater.check_for_updates():
        print(f"Update available: {updater.latest_version}")
        print(f"Download URL: {updater.download_url}")
        
        response = input("Download and install? (y/n): ")
        if response.lower() == 'y':
            print("Downloading...")
            
            def progress(downloaded, total):
                percent = (downloaded / total) * 100 if total > 0 else 0
                print(f"\rProgress: {percent:.1f}%", end='', flush=True)
            
            if updater.download_update(progress_callback=progress):
                print("\nDownload complete!")
                print("Installing...")
                
                if updater.install_update():
                    print("Update installed successfully!")
                    print("Please restart the application.")
                else:
                    print("Installation failed.")
            else:
                print("\nDownload failed.")
    else:
        print("No updates available.")
