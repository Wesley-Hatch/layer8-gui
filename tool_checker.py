import shutil
import subprocess
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('scanner')
from typing import Dict, Optional

class ToolChecker:
    """Check for required security tools"""
    
    REQUIRED_TOOLS = {
        'nmap': 'Network scanner',
        'nikto': 'Web vulnerability scanner',
        'gobuster': 'Directory bruteforcer',
        'sqlmap': 'SQL injection tool',
        'wpscan': 'WordPress scanner',
        'hydra': 'Brute force tool',
        'msfconsole': 'Metasploit Framework',
        'fping': 'Ping sweep tool',
        'masscan': 'Mass IP port scanner',
        'wireshark': 'Network protocol analyzer'
    }
    
    @staticmethod
    def check_all_tools() -> Dict[str, dict]:
        """
        Check which tools are installed
        Returns: {tool_name: {installed: bool, path: str, version: str, description: str}}
        """
        results = {}
        
        for tool, description in ToolChecker.REQUIRED_TOOLS.items():
            path = shutil.which(tool)
            installed = path is not None
            version = None
            
            if installed:
                try:
                    # Try common version flags
                    version_flags = ['--version', '-version', '-V']
                    for flag in version_flags:
                        try:
                            result = subprocess.run(
                                [tool, flag],
                                capture_output=True,
                                text=True,
                                timeout=2
                            )
                            if result.returncode == 0:
                                # Get first line of version output
                                version = result.stdout.split('\n')[0].strip() or result.stderr.split('\n')[0].strip()
                                if version:
                                    break
                        except:
                            continue
                except Exception as e:
                    logger.debug(f"Could not get version for {tool}: {e}")
                    version = "Unknown"
            
            results[tool] = {
                'installed': installed,
                'path': path,
                'version': version or ("Unknown" if installed else None),
                'description': description
            }
        
        return results
    
    @staticmethod
    def is_tool_installed(tool_name: str) -> bool:
        """Check if a specific tool is installed"""
        return shutil.which(tool_name) is not None

    @staticmethod
    def get_tool_path(tool_name: str) -> Optional[str]:
        """Get the full path to a tool"""
        return shutil.which(tool_name)
