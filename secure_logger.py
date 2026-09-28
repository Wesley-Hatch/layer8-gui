import logging
import json
import os
import sys
import platform
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
from pathlib import Path
import queue
import threading
import atexit

class CategoryFilter(logging.Filter):
    """Filter log records by category name."""
    def __init__(self, category: str):
        super().__init__()
        self.category = f"layer8.{category}"
    
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name == self.category or record.name.startswith(f"{self.category}.")

class SecurityFilter(logging.Filter):
    """Filter for security events."""
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith("layer8.security")

class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings for machine-readable logging.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
        }

        # Add extra context if provided
        if hasattr(record, 'context') and isinstance(record.context, dict):
            log_data['context'] = record.context

        # Add exception info if it exists
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_data)

class SecureLogger:
    """
    Secure logging system for Layer8 with automatic sanitization of sensitive data.
    
    Features:
    - Automatic redaction of passwords, keys, and tokens.
    - Structured JSON output.
    - Category-based log files (database, security, ai, etc.).
    - Cross-platform log storage in user directories.
    - Log rotation and retention.
    - Asynchronous logging using a QueueListener.
    """

    # Global state for asynchronous logging
    _log_queue = queue.Queue(-1)
    _listener = None
    _handlers_initialized = False
    _log_dir = None

    # Sensitive field patterns (case-insensitive)
    SENSITIVE_PATTERNS = [
        'password', 'passwd', 'pwd', 'pass',
        'api_key', 'apikey', 'api-key',
        'token', 'csrf', 'jwt',
        'secret', 'private_key', 'encryption_key',
        'pepper', 'salt', 'pwd_key',
        'credit_card', 'cvv', 'ssn', 'auth'
    ]

    def __init__(self, category: str, log_level: str = 'INFO'):
        """
        Initialize a category-specific logger.
        
        Args:
            category: The log category (e.g., 'application', 'database', 'security', 'scanner', 'ai')
            log_level: Default logging level
        """
        self.category = category.lower()
        
        # Initialize global handlers once
        if not SecureLogger._handlers_initialized:
            SecureLogger._setup_global_handlers()
        
        self.logger = logging.getLogger(f"layer8.{self.category}")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Add QueueHandler to route all logs to the background listener
        if not any(isinstance(h, QueueHandler) for h in self.logger.handlers):
            self.logger.addHandler(QueueHandler(SecureLogger._log_queue))

    @classmethod
    def _setup_global_handlers(cls):
        """Setup the background listener and its handlers."""
        cls._log_dir = cls._get_log_dir()
        cls._log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set directory permissions (Owner RW only) - POSIX only
        if platform.system() != "Windows":
            try:
                os.chmod(cls._log_dir, 0o700)
            except: pass

        formatter = JSONFormatter()
        handlers = []

        # 1. Main application log (everything)
        app_handler = RotatingFileHandler(
            cls._log_dir / 'application.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        app_handler.setFormatter(formatter)
        handlers.append(app_handler)

        # 2. Category-specific logs
        categories = ['database', 'scanner', 'ai', 'ui', 'network']
        for cat in categories:
            cat_handler = RotatingFileHandler(
                cls._log_dir / f'{cat}.log',
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding='utf-8'
            )
            cat_handler.setFormatter(formatter)
            cat_handler.addFilter(CategoryFilter(cat))
            handlers.append(cat_handler)

        # 3. Error log (Only ERROR and CRITICAL)
        error_handler = RotatingFileHandler(
            cls._log_dir / 'error.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=10,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        handlers.append(error_handler)

        # 4. Security log (centralized security events)
        security_handler = RotatingFileHandler(
            cls._log_dir / 'security.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=10,
            encoding='utf-8'
        )
        security_handler.setFormatter(formatter)
        security_handler.addFilter(SecurityFilter())
        handlers.append(security_handler)

        # Start the listener
        cls._listener = QueueListener(cls._log_queue, *handlers, respect_handler_level=True)
        cls._listener.start()
        cls._handlers_initialized = True
        
        # Register shutdown
        atexit.register(cls.shutdown)

    @staticmethod
    def _get_log_dir() -> Path:
        """Get platform-specific log directory."""
        system = platform.system()
        if system == "Windows":
            base_dir = Path(os.getenv("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))) / "Layer8"
        elif system == "Darwin":
            base_dir = Path.home() / "Library" / "Logs" / "Layer8"
        else:  # Linux/other
            base_dir = Path.home() / ".local" / "share" / "layer8" / "logs"
            # Some Linux users prefer ~/.config/layer8/logs but .local/share is more correct for logs
            # However, the requirement mentioned ~/.config/layer8/logs for config.
            # I'll stick to what's common or specified.
            if system == "Linux":
                 base_dir = Path.home() / ".local" / "share" / "layer8" / "logs"
        
        # If we are in a dev environment and don't want to pollute system dirs, 
        # we could check for a local logs dir, but requirements say store in user dir.
        
        return base_dir / "logs"

    @classmethod
    def shutdown(cls):
        """Shutdown the background listener."""
        if cls._listener:
            cls._listener.stop()
            cls._listener = None
            cls._handlers_initialized = False

    def sanitize(self, data: Any) -> Any:
        """
        Recursively sanitize sensitive data.
        """
        if isinstance(data, dict):
            return {k: self._sanitize_value(k, v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self.sanitize(item) for item in data)
        elif isinstance(data, str):
            # Also check if the string itself looks like a secret (e.g. JSON string)
            if data.strip().startswith('{') and data.strip().endswith('}'):
                try:
                    js = json.loads(data)
                    return json.dumps(self.sanitize(js))
                except:
                    return data
            return data
        else:
            return data

    def _sanitize_value(self, key: str, value: Any) -> Any:
        """Sanitize a single value based on its key name."""
        key_lower = str(key).lower()
        
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in key_lower:
                return self._redact_value(value)
        
        # If it's a nested structure, sanitize it
        if isinstance(value, (dict, list, tuple)):
            return self.sanitize(value)
            
        return value

    def _redact_value(self, value: Any) -> str:
        """Redact a sensitive value while keeping some context for short ones."""
        if value is None:
            return "None"
        
        val_str = str(value)
        if not val_str:
            return ""
            
        if len(val_str) <= 4:
            return "***"
        else:
            # Show first 2 characters, mask the rest
            return val_str[:2] + "*" * (len(val_str) - 2)

    def _log(self, level: int, message: str, context: Optional[Dict] = None, exc_info: bool = False):
        """Internal log routing."""
        sanitized_context = self.sanitize(context) if context else {}
        
        # Inject context into LogRecord
        extra = {'context': sanitized_context}
        
        self.logger.log(level, message, extra=extra, exc_info=exc_info)

    def debug(self, message: str, context: Optional[Dict] = None):
        self._log(logging.DEBUG, message, context)

    def info(self, message: str, context: Optional[Dict] = None):
        self._log(logging.INFO, message, context)

    def warning(self, message: str, context: Optional[Dict] = None):
        self._log(logging.WARNING, message, context)

    def error(self, message: str, context: Optional[Dict] = None, exc_info: bool = True):
        self._log(logging.ERROR, message, context, exc_info=exc_info)

    def critical(self, message: str, context: Optional[Dict] = None, exc_info: bool = True):
        self._log(logging.CRITICAL, message, context, exc_info=exc_info)

    def security(self, event: str, context: Optional[Dict] = None):
        """
        Log a security-relevant event to security.log.
        """
        sanitized_context = self.sanitize(context) if context else {}
        
        # We use a specific logger name that SecurityFilter will catch
        sec_logger = logging.getLogger(f"layer8.security.{self.category}")
        
        # Ensure it also has the QueueHandler if not already added
        if not any(isinstance(h, QueueHandler) for h in sec_logger.handlers):
            sec_logger.addHandler(QueueHandler(SecureLogger._log_queue))
            
        # Log with high level to ensure it's captured
        sec_logger.log(
            logging.WARNING, 
            event, 
            extra={'context': sanitized_context}
        )
        
        # Also log to main category log as INFO
        self.info(f"SECURITY EVENT: {event}", context=context)

# Global utility to get a logger
_loggers: Dict[str, SecureLogger] = {}

def get_logger(category: str, level: str = 'INFO') -> SecureLogger:
    """Get or create a SecureLogger for the given category."""
    if category not in _loggers:
        _loggers[category] = SecureLogger(category, level)
    return _loggers[category]
