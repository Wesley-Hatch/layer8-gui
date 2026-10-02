import re
import ipaddress
import os
from typing import Optional, Tuple, List
from urllib.parse import urlparse

class InputValidator:
    """
    Validate user inputs for security tools
    Prevents command injection and other attacks
    """
    
    @staticmethod
    def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
        """
        Validate IP address (IPv4 or IPv6)
        Returns: (is_valid, error_message)
        """
        if not ip:
            return False, "IP address is empty"
        try:
            ipaddress.ip_address(ip)
            return True, None
        except ValueError:
            return False, f"Invalid IP address format: {ip}"

    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate domain name
        """
        if not domain:
            return False, "Domain is empty"
        
        # RFC 1035 domain name pattern
        pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        if re.match(pattern, domain) and len(domain) <= 255:
            return True, None
        return False, f"Invalid domain name format: {domain}"

    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL (HTTP/HTTPS only)
        """
        if not url:
            return False, "URL is empty"
        
        try:
            result = urlparse(url)
            if all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']:
                # Further validate netloc (could be IP or domain)
                host = result.netloc.split(':')[0]
                is_ip, _ = InputValidator.validate_ip(host)
                is_domain, _ = InputValidator.validate_domain(host)
                if is_ip or is_domain or host == 'localhost':
                    return True, None
            return False, f"Invalid URL format or unsupported scheme: {url}"
        except Exception:
            return False, f"Error parsing URL: {url}"

    @staticmethod
    def validate_port(port: str) -> Tuple[bool, Optional[str]]:
        """
        Validate port number (1-65535)
        """
        try:
            p = int(port)
            if 1 <= p <= 65535:
                return True, None
            return False, f"Port out of range (1-65535): {port}"
        except ValueError:
            return False, f"Invalid port number: {port}"

    @staticmethod
    def validate_port_range(port_range: str) -> Tuple[bool, Optional[str]]:
        """
        Validate port range (e.g., 80-443, 1-1000)
        """
        if '-' not in port_range:
            return InputValidator.validate_port(port_range)
        
        parts = port_range.split('-')
        if len(parts) != 2:
            return False, f"Invalid port range format: {port_range}"
        
        v1, e1 = InputValidator.validate_port(parts[0])
        v2, e2 = InputValidator.validate_port(parts[1])
        
        if not v1 or not v2:
            return False, e1 or e2
        
        if int(parts[0]) > int(parts[1]):
            return False, f"Start port cannot be greater than end port: {port_range}"
            
        return True, None

    @staticmethod
    def validate_cidr(cidr: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CIDR notation (e.g., 192.168.1.0/24)
        """
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True, None
        except ValueError:
            return False, f"Invalid CIDR notation: {cidr}"

    @staticmethod
    def validate_file_path(path: str, allowed_dirs: List[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate file path (no directory traversal)
        """
        if not path:
            return False, "Path is empty"
            
        # Check for traversal
        normalized = os.path.normpath(path)
        if '..' in normalized.split(os.path.sep):
            return False, "Directory traversal attempt detected"
            
        if allowed_dirs:
            abs_path = os.path.abspath(normalized)
            is_allowed = False
            for allowed in allowed_dirs:
                if abs_path.startswith(os.path.abspath(allowed)):
                    is_allowed = True
                    break
            if not is_allowed:
                return False, f"Path outside of allowed directories: {path}"
                
        return True, None

    # Characters that can be dangerous when a string reaches a shell. Kept as a
    # constant so callers can opt specific characters back in (see `allow`).
    SHELL_METACHARACTERS = [';', '|', '&', '$', '`', '\n', '\r', '(', ')', '<', '>',
                            '*', '?', '[', ']', '{', '}', '!', '\\', '"', "'"]

    @staticmethod
    def contains_shell_metacharacters(text: str, allow=None) -> bool:
        """
        Check if text contains dangerous shell characters.

        `allow` is an optional iterable of characters to treat as safe. Callers
        that execute with shell=False (where these characters are passed as
        literal arguments, not interpreted) can allow URL punctuation such as
        '?' and '&' without opening a command-injection hole. Default behavior
        is unchanged for every existing caller.
        """
        allowed = set(allow or ())
        return any(char in text for char in InputValidator.SHELL_METACHARACTERS
                   if char not in allowed)

    @staticmethod
    def sanitize_for_shell(text: str) -> str:
        """
        Remove shell metacharacters or raise error if found
        """
        if InputValidator.contains_shell_metacharacters(text):
            # For security, we prefer to reject rather than silently sanitize
            raise ValueError(f"Dangerous characters detected in input: {text}")
        return text

    @staticmethod
    def validate_target(target: str) -> Tuple[bool, Optional[str]]:
        """
        Generic target validator (IP, Domain, or CIDR)
        """
        is_ip, _ = InputValidator.validate_ip(target)
        if is_ip: return True, None
        
        is_domain, _ = InputValidator.validate_domain(target)
        if is_domain: return True, None
        
        is_cidr, _ = InputValidator.validate_cidr(target)
        if is_cidr: return True, None
        
        return False, f"Target must be a valid IP, Domain, or CIDR: {target}"
