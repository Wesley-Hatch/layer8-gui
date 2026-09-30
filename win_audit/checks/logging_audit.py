"""Category 6 (extra) - Logging & audit policy."""

from __future__ import annotations

import re
from typing import Any, List

from ..models import CATEGORY_LOGGING, Finding
from ..transport import CommandResult
from .base import BaseCheck, register


CAT = CATEGORY_LOGGING


@register
class AuditPolicy(BaseCheck):
    id = "LOG-POL-001"
    title = "Advanced audit policy coverage"
    category = CAT
    severity = "MEDIUM"
    reference = "CIS: audit Logon, Account Logon, Policy Change, Privilege Use"
    remediation = "Enable Success/Failure auditing for key subcategories via GPO or auditpol."
    ps = "[pscustomobject]@{Raw=((auditpol /get /category:*) -join \"`n\")} | ConvertTo-Json -Compress"

    KEY_SUBCATS = ["Logon", "Logoff", "Special Logon", "Credential Validation",
                   "Audit Policy Change", "Sensitive Privilege Use", "Process Creation"]

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        text = data.get("Raw", "") if isinstance(data, dict) else ""
        if not text:
            return [self._error(target, raw)]
        no_audit: List[str] = []
        for sub in self.KEY_SUBCATS:
            m = re.search(re.escape(sub) + r"\s{2,}(.+)", text)
            if m and "no auditing" in m.group(1).strip().lower():
                no_audit.append(sub)
        if no_audit:
            return [self.finding(target, "FAIL",
                                 f"Key audit subcategories set to 'No Auditing': {', '.join(no_audit)}",
                                 evidence=text[:1200])]
        return [self.finding(target, "PASS", "Key audit subcategories are being audited",
                             evidence=text[:600])]


@register
class PowerShellLogging(BaseCheck):
    id = "LOG-PS-001"
    title = "PowerShell script block & module logging"
    category = CAT
    severity = "MEDIUM"
    reference = "Detection of malicious PowerShell"
    remediation = "Enable Script Block Logging and Module Logging via GPO."
    ps = ("$sb=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging).EnableScriptBlockLogging;"
          "$mod=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging).EnableModuleLogging;"
          "[pscustomobject]@{ScriptBlock=$sb;Module=$mod} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        if data.get("ScriptBlock") != 1:
            out.append(self.finding(target, "WARN", "PowerShell Script Block Logging is not enabled",
                                    severity="MEDIUM", evidence=str(data), title="Script block logging"))
        else:
            out.append(self.finding(target, "PASS", "Script block logging enabled", title="Script block logging"))
        if data.get("Module") != 1:
            out.append(self.finding(target, "INFO", "PowerShell Module Logging is not enabled",
                                    severity="LOW", evidence=str(data), title="Module logging"))
        return out


@register
class CommandLineAuditing(BaseCheck):
    id = "LOG-CMD-001"
    title = "Process creation command-line auditing"
    category = CAT
    severity = "LOW"
    reference = "Event 4688 with command line"
    remediation = ("Enable 'Include command line in process creation events' "
                   "(ProcessCreationIncludeCmdLine_Enabled=1) plus Audit Process Creation.")
    ps = ("$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled).ProcessCreationIncludeCmdLine_Enabled;"
          "[pscustomobject]@{IncludeCmdLine=$v} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        val = data.get("IncludeCmdLine") if isinstance(data, dict) else None
        if val == 1:
            return [self.finding(target, "PASS", "Command line is captured in process-creation events",
                                 evidence=str(data))]
        return [self.finding(target, "WARN",
                             "Process-creation events do not include command lines (weaker forensics)",
                             evidence=str(data))]
