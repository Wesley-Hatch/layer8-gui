"""Category 7 - Local privilege escalation vectors.

These are the primitives a skilled attacker uses to go from a foothold (any
user / a service account) to SYSTEM. All checks are read-only ACL/registry
inspection - nothing is exploited.
"""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_PRIVESC, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register
from .pssnippets import PS_ACL_HELPER


CAT = CATEGORY_PRIVESC

# Privileges that enable escalation when held by a non-admin / service context.
DANGEROUS_PRIVS = {
    "SeImpersonatePrivilege": "Potato-family SYSTEM escalation",
    "SeAssignPrimaryTokenPrivilege": "token-assignment SYSTEM escalation",
    "SeDebugPrivilege": "inject into / dump any process (incl. LSASS)",
    "SeBackupPrivilege": "read any file incl. SAM/SYSTEM hives",
    "SeRestorePrivilege": "write any file / registry key",
    "SeTakeOwnershipPrivilege": "take ownership of any securable object",
    "SeLoadDriverPrivilege": "load a (malicious) kernel driver",
    "SeTcbPrivilege": "act as part of the OS",
    "SeCreateTokenPrivilege": "forge arbitrary access tokens",
    "SeManageVolumePrivilege": "raw volume access -> arbitrary file read",
}


@register
class TokenPrivileges(BaseCheck):
    id = "PRIV-TOKEN-001"
    title = "Dangerous privileges available in the audited context"
    category = CAT
    severity = "HIGH"
    reference = "Potato attacks / SeBackup / SeDebug abuse"
    attack = "T1134 / T1068"
    remediation = ("If a non-admin or service account holds these, remove them. Service accounts "
                   "with SeImpersonate can be escalated to SYSTEM via Potato-family attacks.")
    ps = ("$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
          ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
          "$who=(whoami) 2>$null;"
          "$privs=@();(whoami /priv) 2>$null | ForEach-Object{ if($_ -match '^(Se\\w+)'){$privs+=$matches[1]} };"
          "[pscustomobject]@{IsAdmin=$isAdmin;User=$who;Privs=$privs} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        privs = data.get("Privs") or []
        if isinstance(privs, str):
            privs = [privs]
        held = [p for p in privs if p in DANGEROUS_PRIVS]
        is_admin = bool(data.get("IsAdmin"))
        user = data.get("User")
        if not held:
            return [self.finding(target, "INFO", f"No dangerous privileges in context ({user})",
                                 evidence=str(data))]
        desc = "; ".join(f"{p} ({DANGEROUS_PRIVS[p]})" for p in held)
        if is_admin:
            return [self.finding(target, "INFO",
                                 f"Context '{user}' is admin and holds: {desc}",
                                 severity="INFO", evidence=str(data))]
        # Non-admin holding these is a genuine escalation path.
        sev = "CRITICAL" if any(p in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
                                       "SeDebugPrivilege") for p in held) else "HIGH"
        return [self.finding(target, "FAIL",
                             f"Non-admin context '{user}' holds escalation privileges: {desc}",
                             severity=sev, evidence=str(data))]


@register
class WritableServiceBinaries(BaseCheck):
    id = "PRIV-SVCBIN-001"
    title = "Service binaries / directories writable by non-admins"
    category = CAT
    severity = "CRITICAL"
    reference = "Weak service permissions -> SYSTEM"
    attack = "T1543.003 / T1574"
    remediation = ("Restrict NTFS permissions on the service executable and its folder so only "
                   "admins/SYSTEM can write. Replace the binary or re-ACL the directory.")
    ps = (PS_ACL_HELPER +
          "$out=@();"
          "foreach($s in Get-CimInstance Win32_Service){"
          "$exe=Get-ServiceExe $s.PathName;"
          "if(-not $exe){continue}"
          "$b=Get-RiskyAcl $exe; $d=Get-RiskyAcl (Split-Path -Parent $exe);"
          "if($b -or $d){$out+=[pscustomobject]@{Name=$s.Name;Account=$s.StartName;State=$s.State;"
          "Start=$s.StartMode;Exe=$exe;BinWritable=$b;DirWritable=$d}}};"
          "$out | ConvertTo-Json -Depth 4")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No services with user-writable binaries/directories")]
        out: List[Finding] = []
        for r in rows:
            acct = str(r.get("Account") or "")
            is_system = acct.lower() in ("localsystem", "nt authority\\system", ".\\localsystem")
            sev = "CRITICAL" if (is_system and r.get("BinWritable")) else "HIGH"
            what = "binary" if r.get("BinWritable") else "directory"
            out.append(self.finding(
                target, "FAIL",
                f"Service '{r.get('Name')}' (runs as {acct or 'unknown'}) has a user-writable {what}: "
                f"{r.get('Exe')} [{r.get('BinWritable') or r.get('DirWritable')}]",
                severity=sev, evidence=str(r),
                title=f"Writable service {what}: {r.get('Name')}"))
        return out


@register
class WritableServiceRegistry(BaseCheck):
    id = "PRIV-SVCREG-001"
    title = "Service registry keys writable by non-admins"
    category = CAT
    severity = "CRITICAL"
    reference = "Writable service key -> change ImagePath -> SYSTEM"
    attack = "T1574.011"
    remediation = "Restrict permissions on HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>."
    ps = (PS_ACL_HELPER +
          "$out=@();"
          "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' -EA SilentlyContinue | "
          "Select-Object -First 800 | ForEach-Object{"
          "$risk=Get-RiskyRegAcl $_.PSPath;"
          "if($risk){$out+=[pscustomobject]@{Service=$_.PSChildName;Writable=$risk}}};"
          "$out | ConvertTo-Json -Depth 3")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No service registry keys writable by non-admins")]
        names = ", ".join(str(r.get("Service")) for r in rows[:15])
        return [self.finding(target, "FAIL",
                             f"{len(rows)} service key(s) writable by low-privileged users: {names}",
                             evidence=str(rows[:25]))]


@register
class WritablePathDirs(BaseCheck):
    id = "PRIV-PATH-001"
    title = "Writable directories in the system PATH (DLL / binary planting)"
    category = CAT
    severity = "HIGH"
    reference = "PATH hijack / DLL search-order abuse"
    attack = "T1574.007"
    remediation = "Remove user-writable directories from the machine PATH or lock down their ACLs."
    ps = (PS_ACL_HELPER +
          "$p=[Environment]::GetEnvironmentVariable('Path','Machine');"
          "$out=@();foreach($d in ($p -split ';')){ if([string]::IsNullOrWhiteSpace($d)){continue}"
          "$risk=Get-RiskyAcl $d.Trim(); if($risk){$out+=[pscustomobject]@{Dir=$d.Trim();Writable=$risk}}};"
          "$out | ConvertTo-Json -Depth 3")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No user-writable directories in the system PATH")]
        dirs = "; ".join(f"{r.get('Dir')} [{r.get('Writable')}]" for r in rows)
        return [self.finding(target, "FAIL",
                             f"{len(rows)} PATH director(ies) writable by non-admins: {dirs}",
                             evidence=str(rows))]


@register
class WritableScheduledTasks(BaseCheck):
    id = "PRIV-TASK-001"
    title = "Scheduled-task binaries writable by non-admins"
    category = CAT
    severity = "HIGH"
    reference = "Weak task binary ACL -> run as the task principal (often SYSTEM)"
    attack = "T1053.005"
    remediation = "Re-ACL the task's target executable so only admins/SYSTEM can modify it."
    ps = (PS_ACL_HELPER +
          "$out=@();"
          "foreach($t in (Get-ScheduledTask -EA SilentlyContinue)){"
          "$ctx=$t.Principal.UserId; "
          "foreach($a in $t.Actions){ $ex=$a.Execute; if(-not $ex){continue}"
          "$ex=$ex.Trim('\"'); if($ex -notmatch '\\\\'){ $ex=(Get-Command $ex -EA SilentlyContinue).Source }"
          "if(-not $ex){continue}"
          "$risk=Get-RiskyAcl $ex;"
          "if($risk){$out+=[pscustomobject]@{Task=$t.TaskName;Path=$t.TaskPath;RunAs=$ctx;Exe=$ex;Writable=$risk}}}};"
          "$out | ConvertTo-Json -Depth 4")

    HIGH_CTX = ("system", "s-1-5-18", "localsystem", "highest")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No scheduled-task binaries writable by non-admins")]
        out: List[Finding] = []
        for r in rows:
            ctx = str(r.get("RunAs") or "").lower()
            sev = "CRITICAL" if any(k in ctx for k in self.HIGH_CTX) else "HIGH"
            out.append(self.finding(
                target, "FAIL",
                f"Task '{r.get('Path')}{r.get('Task')}' (runs as {r.get('RunAs')}) has writable binary "
                f"{r.get('Exe')} [{r.get('Writable')}]",
                severity=sev, evidence=str(r),
                title=f"Writable task binary: {r.get('Task')}"))
        return out


@register
class WritableAutorunTargets(BaseCheck):
    id = "PRIV-RUN-001"
    title = "Autorun / startup targets writable by non-admins"
    category = CAT
    severity = "HIGH"
    reference = "Persistence + escalation via writable autostart binary"
    attack = "T1547.001"
    remediation = "Lock down ACLs on autorun target binaries and the machine startup folder."
    ps = (PS_ACL_HELPER +
          "$out=@();"
          "$startup='C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp';"
          "$s=Get-RiskyAcl $startup; if($s){$out+=[pscustomobject]@{Item='CommonStartupFolder';Target=$startup;Writable=$s}};"
          "foreach($k in @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')){"
          "if(Test-Path $k){$p=Get-ItemProperty $k; $p.PSObject.Properties|Where-Object{$_.Name -notlike 'PS*'}|ForEach-Object{"
          "$exe=Get-ServiceExe $_.Value; $r=Get-RiskyAcl $exe;"
          "if($r){$out+=[pscustomobject]@{Item=$_.Name;Target=$exe;Writable=$r}}}}};"
          "$out | ConvertTo-Json -Depth 3")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No user-writable autorun/startup targets")]
        items = "; ".join(f"{r.get('Item')}->{r.get('Target')}" for r in rows)
        return [self.finding(target, "FAIL",
                             f"{len(rows)} writable autorun/startup target(s): {items}",
                             evidence=str(rows))]
