"""
win_audit - Layer8 Windows Vulnerability Auditor

A read-only, authorized configuration/vulnerability auditor for Windows hosts.
Runs a curated list of PowerShell/Windows checks - locally or against a remote
host over WinRM (PowerShell Remoting) - grouped into categories that are
executed one category at a time, and writes findings to CSV and/or JSON.

Use only against systems you own or are explicitly authorized to assess.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
