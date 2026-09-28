import subprocess
import os
from typing import List, Optional, Tuple, Dict
from input_validator import InputValidator
from tool_checker import ToolChecker
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('scanner')

class SafeExecutor:
    """
    Safely execute security tools with command injection prevention
    """
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.tool_paths = self._refresh_tool_paths()
    
    def _refresh_tool_paths(self) -> Dict[str, str]:
        """Get the absolute paths of all installed tools"""
        tools = ToolChecker.check_all_tools()
        return {name: info['path'] for name, info in tools.items() if info['installed']}
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is installed"""
        return tool_name in self.tool_paths

    def run_command(self, tool: str, args: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        """
        Execute a command safely using an argument list and shell=False
        """
        if not self.is_tool_available(tool):
            raise FileNotFoundError(f"Tool not found: {tool}")
            
        # Security check: Ensure no argument contains shell metacharacters
        for arg in args:
            if InputValidator.contains_shell_metacharacters(arg):
                raise ValueError(f"Dangerous character in command argument: {arg}")
        
        cmd = [self.tool_paths[tool]] + args
        
        logger.info(f"Executing safe command: {' '.join(cmd)}")
        
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            shell=False,
            cwd=cwd
        )

    def execute_nmap(self, target: str, options: List[str] = None) -> subprocess.CompletedProcess:
        """Safely execute nmap"""
        is_valid, error = InputValidator.validate_target(target)
        if not is_valid:
            raise ValueError(f"Invalid target for nmap: {error}")
            
        # Whitelist allowed nmap options
        allowed_options = [
            '-sV', '-sC', '-A', '-sS', '-sT', '-sU', '-Pn', '-f', 
            '--mtu', '--data-length', '--scan-delay', '--script', 
            '--script-args', '-p', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5'
        ]
        
        safe_args = []
        if options:
            i = 0
            while i < len(options):
                opt = options[i]
                
                # Check if option is allowed
                is_allowed = False
                for allowed in allowed_options:
                    if opt == allowed or opt.startswith(allowed):
                        is_allowed = True
                        break
                
                if not is_allowed:
                    raise ValueError(f"Disallowed nmap option: {opt}")
                
                safe_args.append(opt)
                i += 1
                
        safe_args.append(target)
        return self.run_command('nmap', safe_args)

    def execute_nikto(self, target: str) -> subprocess.CompletedProcess:
        """Safely execute nikto"""
        # Target could be URL or Host
        is_url, _ = InputValidator.validate_url(target)
        is_host, _ = InputValidator.validate_target(target)
        
        if not is_url and not is_host:
            raise ValueError(f"Invalid target for nikto: {target}")
            
        return self.run_command('nikto', ['-h', target])

    def execute_gobuster(self, url: str, wordlist: str) -> subprocess.CompletedProcess:
        """Safely execute gobuster"""
        is_valid_url, url_error = InputValidator.validate_url(url)
        if not is_valid_url:
            raise ValueError(f"Invalid URL for gobuster: {url_error}")
            
        is_valid_path, path_error = InputValidator.validate_file_path(wordlist)
        if not is_valid_path:
            raise ValueError(f"Invalid wordlist path for gobuster: {path_error}")
            
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")
            
        return self.run_command('gobuster', ['dir', '-u', url, '-w', wordlist])

    def execute_sqlmap(self, url: str, extra_args: List[str] = None) -> subprocess.CompletedProcess:
        """Safely execute sqlmap"""
        is_valid, error = InputValidator.validate_url(url)
        if not is_valid:
            raise ValueError(f"Invalid URL for sqlmap: {error}")
            
        args = ['-u', url, '--batch']
        if extra_args:
            args.extend(extra_args)
            
        return self.run_command('sqlmap', args)
