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

    # Standard system / networking utilities the app itself drives (Web Fetch,
    # NSLookup, Custom Cmd, etc.). These ship with the OS (curl, ping, nslookup
    # and friends are built into Windows 10/11 and standard on Linux/macOS), so
    # they do NOT need bundling - they just need to be recognized. Resolved via
    # shutil.which at runtime; whatever isn't present simply reports installed=False.
    SYSTEM_TOOLS = {
        'curl': 'HTTP client',
        'ping': 'ICMP echo',
        'nslookup': 'DNS lookup',
        'tracert': 'Trace route (Windows)',
        'traceroute': 'Trace route (Unix)',
        'ipconfig': 'IP configuration (Windows)',
        'ifconfig': 'IP configuration (Unix)',
        'ip': 'IP configuration (Linux)',
        'arp': 'ARP table',
        'netstat': 'Network connections',
        'nbtstat': 'NetBIOS stats (Windows)',
        'route': 'Routing table',
        'netsh': 'Network shell (Windows)',
        'whoami': 'Current user',
        'systeminfo': 'System information (Windows)',
        'hostname': 'Host name',
        'net': 'Net command (Windows)',
        'powershell': 'PowerShell',
        'wmic': 'WMI command-line (Windows)',
        'dig': 'DNS lookup (Unix)',
        'host': 'DNS lookup (Unix)',
        'wget': 'HTTP client',
        'ssh': 'Secure shell client',
        'telnet': 'Telnet client',
        'ftp': 'FTP client',
        'nc': 'Netcat',
    }

    # Where to get the third-party tools the app wraps (and a few common ones a
    # user might type into Custom Cmd). Shown when a command is not found so the
    # user knows exactly how to install it rather than guessing. We do NOT bundle
    # these: most are not freely redistributable, they are large, and shipping
    # offensive binaries inside the app trips antivirus/SmartScreen.
    INSTALL_HINTS = {
        'nmap': "Get it from https://nmap.org/download (Windows installer) or 'sudo apt install nmap' (Linux).",
        'nikto': "Get it from https://github.com/sullo/nikto or 'sudo apt install nikto' (Linux).",
        'gobuster': "Download from https://github.com/OJ/gobuster/releases or 'sudo apt install gobuster'.",
        'sqlmap': "Get it from https://sqlmap.org or 'sudo apt install sqlmap' (Linux).",
        'wpscan': "Install with 'gem install wpscan' (needs Ruby) or 'sudo apt install wpscan'.",
        'hydra': "Get it from https://github.com/vanhauser-thc/thc-hydra or 'sudo apt install hydra'.",
        'msfconsole': "Install Metasploit from https://www.metasploit.com/download or 'sudo apt install metasploit-framework'.",
        'fping': "Install with 'sudo apt install fping' (Linux) or see https://fping.org.",
        'masscan': "Build from https://github.com/robertdavidgraham/masscan or 'sudo apt install masscan'.",
        'wireshark': "Download from https://www.wireshark.org/download.html or 'sudo apt install wireshark'.",
        'john': "Download 'winX64_1_JtR.zip' from https://github.com/openwall/john-packages/releases/latest "
                "and extract it to a 'tools\\john' folder next to the app (so tools\\john\\run\\john.exe exists); "
                "Linux: 'sudo apt install john'.",
        'dirb': "Install with 'sudo apt install dirb' (Linux) or see https://github.com/v0re/dirb.",
        'dig': "On Windows install BIND tools (https://www.isc.org/download/); on Linux 'sudo apt install dnsutils'.",
        'nc': "Install netcat: 'sudo apt install netcat' (Linux); on Windows try ncat from the Nmap suite.",
        'ncat': "Ships with the Nmap installer: https://nmap.org/download.",
        'openssl': "On Windows install from https://slproweb.com/products/Win32OpenSSL.html; on Linux 'sudo apt install openssl'.",
    }

    @staticmethod
    def get_install_hint(tool_name: str) -> Optional[str]:
        """Return a short 'how to install' note for a known tool, else None."""
        if not tool_name:
            return None
        return ToolChecker.INSTALL_HINTS.get(tool_name.strip().lower())

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

        # System utilities: resolve the path only. We deliberately DO NOT probe
        # versions here - many of these (ping, arp, route, ...) have no --version
        # flag and would instead try to act on "--version" and hang until timeout.
        for tool, description in ToolChecker.SYSTEM_TOOLS.items():
            if tool in results:
                continue
            path = shutil.which(tool)
            results[tool] = {
                'installed': path is not None,
                'path': path,
                'version': 'system' if path else None,
                'description': description,
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
