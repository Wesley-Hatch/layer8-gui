"""Category 4 - Network & services."""

from __future__ import annotations

import re
from typing import Any, List

from ..models import CATEGORY_NETWORK, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_NETWORK

# Ports that are notable when listening on a non-loopback address.
RISKY_PORTS = {
    21: ("FTP", "HIGH", "Cleartext FTP exposed"),
    23: ("Telnet", "CRITICAL", "Cleartext Telnet exposed"),
    135: ("RPC", "MEDIUM", "RPC endpoint mapper exposed"),
    139: ("NetBIOS", "MEDIUM", "NetBIOS session service exposed"),
    445: ("SMB", "MEDIUM", "SMB exposed"),
    1433: ("MSSQL", "MEDIUM", "SQL Server exposed"),
    3306: ("MySQL", "MEDIUM", "MySQL exposed"),
    3389: ("RDP", "HIGH", "RDP exposed"),
    5900: ("VNC", "HIGH", "VNC exposed"),
    5985: ("WinRM-HTTP", "MEDIUM", "WinRM over HTTP exposed"),
}


@register
class ListeningPorts(BaseCheck):
    id = "NET-PORT-001"
    title = "Listening TCP ports & owning processes"
    category = CAT
    severity = "MEDIUM"
    reference = "Attack surface inventory"
    remediation = "Close or firewall services that do not need to listen on all interfaces."
    ps = ("Get-NetTCPListener -State Listen | ForEach-Object {"
          "$p=Get-Process -Id $_.OwningProcess -EA SilentlyContinue;"
          "[pscustomobject]@{Addr=$_.LocalAddress;Port=$_.LocalPort;PID=$_.OwningProcess;Proc=$p.ProcessName}}"
          " | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "INFO", "No listening TCP ports reported", evidence=str(raw.stdout[:200]))]
        out: List[Finding] = []
        exposed = [r for r in rows if str(r.get("Addr")) in ("0.0.0.0", "::")]
        for r in exposed:
            port = r.get("Port")
            if port in RISKY_PORTS:
                svc, sev, msg = RISKY_PORTS[port]
                out.append(self.finding(
                    target, "WARN",
                    f"{msg}: port {port}/{svc} listening on {r.get('Addr')} (proc {r.get('Proc')}, pid {r.get('PID')})",
                    severity=sev, evidence=str(r), title=f"Exposed service: {svc} ({port})"))
        # Always emit an inventory line.
        listed = ", ".join(f"{r.get('Port')}/{r.get('Proc')}" for r in exposed[:25])
        out.append(self.finding(target, "INFO",
                                f"{len(exposed)} port(s) listening on all interfaces: {listed}",
                                evidence=str(exposed[:40]), title="Listening ports (inventory)"))
        return out


@register
class UnquotedServicePaths(BaseCheck):
    id = "NET-SVC-001"
    title = "Unquoted service paths (privilege escalation)"
    category = CAT
    severity = "HIGH"
    reference = "Windows unquoted service path privilege escalation"
    remediation = "Wrap the service's BinaryPath in quotes (sc.exe config <svc> binPath= \"...\")."
    ps = ("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,StartName,State"
          " | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self._error(target, raw)]
        flagged: List[str] = []
        for r in rows:
            path = (r.get("PathName") or "").strip()
            if not path or path.startswith('"'):
                continue
            # Strip trailing arguments heuristically at the first .exe
            m = re.match(r"^(.*?\.exe)\b", path, re.IGNORECASE)
            exe = m.group(1) if m else path
            if " " in exe and not exe.lower().startswith("c:\\windows\\"):
                flagged.append(f"{r.get('Name')} -> {path}")
        if flagged:
            return [self.finding(
                target, "FAIL",
                f"{len(flagged)} service(s) with unquoted, space-containing paths",
                severity="HIGH", evidence="\n".join(flagged[:20]))]
        return [self.finding(target, "PASS", "No vulnerable unquoted service paths found")]


@register
class SmbShares(BaseCheck):
    id = "NET-SHARE-001"
    title = "SMB shares and overly-permissive access"
    category = CAT
    severity = "HIGH"
    reference = "Data exposure via open shares"
    remediation = "Remove 'Everyone'/'Authenticated Users' Full Control; scope shares to specific groups."
    ps = ("$out=@();"
          "foreach($s in Get-SmbShare){"
          "$acc=Get-SmbShareAccess -Name $s.Name -EA SilentlyContinue | "
          "Select-Object AccountName,AccessControlType,AccessRight;"
          "$out+=[pscustomobject]@{Name=$s.Name;Path=$s.Path;Access=$acc}};"
          "$out | ConvertTo-Json -Depth 4")

    DEFAULT = {"admin$", "c$", "ipc$", "print$"}

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "INFO", "No SMB shares reported")]
        out: List[Finding] = []
        risky: List[str] = []
        custom = [r for r in rows if str(r.get("Name", "")).lower() not in self.DEFAULT]
        for r in custom:
            for a in as_list(r.get("Access")):
                acct = str(a.get("AccountName", "")).lower()
                right = str(a.get("AccessRight"))
                allow = str(a.get("AccessControlType")).lower() in ("allow", "0")
                if allow and acct in ("everyone", "builtin\\users", "nt authority\\authenticated users") \
                        and right in ("Full", "3", "Change", "2"):
                    risky.append(f"{r.get('Name')} ({r.get('Path')}) -> {acct}:{right}")
        if risky:
            out.append(self.finding(target, "FAIL",
                                    f"{len(risky)} share ACL(s) grant broad access",
                                    severity="HIGH", evidence="\n".join(risky[:20]),
                                    title="Over-permissive share ACL"))
        names = ", ".join(str(r.get("Name")) for r in custom) or "(none)"
        out.append(self.finding(target, "INFO", f"Non-default shares: {names}",
                                evidence=str(custom)[:1000], title="SMB shares (inventory)"))
        return out


@register
class AutorunEntries(BaseCheck):
    id = "NET-RUN-001"
    title = "Autorun (Run key) persistence inventory"
    category = CAT
    severity = "MEDIUM"
    reference = "Persistence review"
    remediation = "Review each autorun entry; remove anything unrecognized."
    ps = ("$keys=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
          "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
          "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run');"
          "$out=@();foreach($k in $keys){ if(Test-Path $k){"
          "$p=Get-ItemProperty $k; $p.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} |"
          "ForEach-Object{$out+=[pscustomobject]@{Key=$k;Name=$_.Name;Value=$_.Value}} }};"
          "$out | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No user/machine Run-key autoruns found")]
        listed = "; ".join(f"{r.get('Name')}={r.get('Value')}" for r in rows[:15])
        return [self.finding(target, "INFO", f"{len(rows)} autorun entr(ies): {listed}",
                             evidence=str(rows)[:1500])]
