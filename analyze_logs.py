"""
Layer8 Log Analysis Tool
Provides a command-line interface to search and report on structured JSON logs.
"""
import json
import os
import platform
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class LogAnalyzer:
    """Analyze structured JSON logs for Layer8."""
    
    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or self._get_default_log_dir()
        if not self.log_dir.exists():
            print(f"Warning: Log directory does not exist: {self.log_dir}")

    def _get_default_log_dir(self) -> Path:
        """Get platform-specific log directory (matching SecureLogger)."""
        system = platform.system()
        if system == "Windows":
            base_dir = Path(os.getenv("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))) / "Layer8"
        elif system == "Darwin":
            base_dir = Path.home() / "Library" / "Logs" / "Layer8"
        else:
            base_dir = Path.home() / ".local" / "share" / "layer8" / "logs"
        return base_dir / "logs"

    def search(self, query: str = "", log_file: str = 'application.log', hours: int = 24, level: str = None) -> List[Dict[str, Any]]:
        """
        Search logs for specific criteria.
        """
        matches = []
        cutoff = datetime.now() - timedelta(hours=hours)
        
        log_path = self.log_dir / log_file
        if not log_path.exists():
            return matches
        
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    
                    # Check timestamp
                    try:
                        timestamp = datetime.fromisoformat(entry['timestamp'])
                        if timestamp < cutoff:
                            continue
                    except (ValueError, KeyError):
                        continue
                    
                    # Check level
                    if level and entry.get('level') != level.upper():
                        continue
                    
                    # Check if query matches anywhere in the JSON
                    if not query or query.lower() in line.lower():
                        matches.append(entry)
                
                except json.JSONDecodeError:
                    continue
        
        return matches

    def get_security_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get security-specific events."""
        return self.search(log_file='security.log', hours=hours)

    def get_errors(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get all errors from error.log."""
        return self.search(log_file='error.log', hours=hours)

    def print_report(self, hours: int = 24):
        """Print a formatted report of recent activity."""
        print("="*80)
        print(f" LAYER8 SECURITY LOG REPORT - Last {hours} Hours")
        print(f" Log Directory: {self.log_dir}")
        print("="*80)
        
        # 1. Error Summary
        errors = self.get_errors(hours)
        print(f"\n[!] Errors Detected: {len(errors)}")
        for err in errors[-5:]: # Show last 5
            ts = err.get('timestamp', '').split('T')[-1][:8]
            msg = err.get('message', 'No message')
            print(f"  {ts} [{err.get('module', '???')}] {msg}")
            if 'exception' in err:
                print(f"      EXC: {err['exception'].splitlines()[-1]}")

        # 2. Security Summary
        sec_events = self.get_security_events(hours)
        print(f"\n[*] Security Events: {len(sec_events)}")
        for event in sec_events[-10:]:
            ts = event.get('timestamp', '').split('T')[-1][:8]
            msg = event.get('message', 'Unknown event')
            ctx = event.get('context', {})
            ctx_str = f" ({ctx})" if ctx else ""
            print(f"  {ts} {msg}{ctx_str}")

        # 3. Application Flow
        app_events = self.search(log_file='application.log', hours=hours, level='INFO')
        print(f"\n[i] General Activity: {len(app_events)} events logged.")
        
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(description="Layer8 Log Analysis Tool")
    parser.add_argument("--hours", type=int, default=24, help="How many hours back to search")
    parser.add_argument("--search", type=str, default="", help="Text to search for in logs")
    parser.add_argument("--file", type=str, default="application.log", help="Log file to search")
    parser.add_argument("--level", type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Filter by log level")
    parser.add_argument("--report", action="store_true", help="Generate a summary report")
    
    args = parser.parse_args()
    analyzer = LogAnalyzer()
    
    if args.report:
        analyzer.print_report(args.hours)
    else:
        results = analyzer.search(args.search, args.file, args.hours, args.level)
        print(f"Found {len(results)} matches:\n")
        for entry in results:
            ts = entry.get('timestamp', '')
            lvl = entry.get('level', 'INFO').ljust(8)
            msg = entry.get('message', '')
            ctx = entry.get('context', '')
            print(f"[{ts}] {lvl} {msg} {ctx}")

if __name__ == "__main__":
    main()
