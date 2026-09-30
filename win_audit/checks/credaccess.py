"""Category 8 - Credential access & secrets at rest.

Finds credentials and secrets an attacker would harvest post-foothold. By design
these checks report the *presence and location* of exposed secrets, NOT the
plaintext values - an audit artifact must not become a credential dump.
"""

from __future__ import annotations

import re
from typing import Any, List

from ..models import CATEGORY_CREDS, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_CREDS


@register
class AutologonPassword(BaseCheck):
    id = "CRED-AUTOLOGON-001"
    title = "Cleartext autologon password in the registry"
    category = CAT
    severity = "CRITICAL"
    reference = "Winlogon DefaultPassword"
    attack = "T1552.002"
    remediation = ("Remove DefaultPassword/AltDefaultPassword and disable AutoAdminLogon. Use the "
                   "Autologon Sysinternals tool (LSA secret) if autologon is truly required.")
    ps = ("$p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
          "[pscustomobject]@{AutoAdminLogon=$p.AutoAdminLogon;DefaultUserName=$p.DefaultUserName;"
          "DefaultDomain=$p.DefaultDomainName;HasDefaultPassword=[bool]$p.DefaultPassword;"
          "HasAltPassword=[bool]$p.AltDefaultPassword} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if data.get("HasDefaultPassword") or data.get("HasAltPassword"):
            who = f"{data.get('DefaultDomain','')}\\{data.get('DefaultUserName','')}".strip("\\")
            return [self.finding(
                target, "FAIL",
                f"Cleartext autologon password stored for '{who}' (value redacted from report)",
                severity="CRITICAL",
                evidence="Winlogon DefaultPassword present (value intentionally not captured)")]
        return [self.finding(target, "PASS", "No cleartext autologon password stored")]


@register
class StoredCredentials(BaseCheck):
    id = "CRED-CMDKEY-001"
    title = "Stored credentials in Credential Manager (cmdkey)"
    category = CAT
    severity = "MEDIUM"
    reference = "Windows Credential Manager reuse"
    attack = "T1555.004"
    remediation = "Review and remove unnecessary saved credentials; avoid saving domain/admin creds."
    ps = "[pscustomobject]@{Raw=((cmdkey /list) -join \"`n\")} | ConvertTo-Json -Compress"

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        text = data.get("Raw", "") if isinstance(data, dict) else ""
        targets = re.findall(r"Target:\s*(.+)", text)
        has_domain = any("domain:" in t.lower() for t in targets)
        if not targets:
            return [self.finding(target, "PASS", "No saved credentials in Credential Manager")]
        sev = "HIGH" if has_domain else "MEDIUM"
        preview = "; ".join(t.strip() for t in targets[:6])
        more = f" (+{len(targets) - 6} more)" if len(targets) > 6 else ""
        return [self.finding(target, "WARN",
                             f"{len(targets)} stored credential(s){more}. Sample targets: {preview}",
                             severity=sev, evidence=str(targets[:25]))]


@register
class SavedWifiKeys(BaseCheck):
    id = "CRED-WIFI-001"
    title = "Recoverable saved Wi-Fi keys"
    category = CAT
    severity = "LOW"
    reference = "netsh wlan show profile key=clear"
    attack = "T1552.001"
    remediation = "For agency/enterprise SSIDs prefer 802.1X; treat any host with saved PSKs as key-bearing."
    ps = ("$profs=(netsh wlan show profiles) 2>$null | Select-String 'All User Profile\\s*:\\s*(.+)$' |"
          " ForEach-Object{ $_.Matches[0].Groups[1].Value.Trim() };"
          "$out=@();foreach($n in $profs){ $d=(netsh wlan show profile name=\"$n\" key=clear) 2>$null;"
          "$has=(($d | Select-String 'Key Content').Count -gt 0);"
          "$out+=[pscustomobject]@{Profile=$n;CleartextKey=$has}};"
          "$out | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        with_key = [r.get("Profile") for r in rows if r.get("CleartextKey")]
        if not with_key:
            return [self.finding(target, "INFO", "No recoverable saved Wi-Fi PSKs")]
        return [self.finding(target, "WARN",
                             f"{len(with_key)} saved Wi-Fi profile(s) with recoverable keys: "
                             f"{', '.join(str(p) for p in with_key[:12])}",
                             severity="LOW", evidence=str(with_key))]


@register
class UnattendSecrets(BaseCheck):
    id = "CRED-UNATTEND-001"
    title = "Deployment answer files containing password fields"
    category = CAT
    severity = "HIGH"
    reference = "unattend.xml / sysprep leftovers"
    attack = "T1552.001"
    remediation = "Delete leftover answer files after deployment; never store plaintext passwords in them."
    ps = ("$paths=@('C:\\unattend.xml','C:\\Windows\\Panther\\Unattend.xml',"
          "'C:\\Windows\\Panther\\Unattend\\Unattend.xml','C:\\Windows\\System32\\Sysprep\\unattend.xml',"
          "'C:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml','C:\\sysprep\\sysprep.xml',"
          "'C:\\sysprep.inf','C:\\Windows\\Panther\\unattended.xml','C:\\autounattend.xml');"
          "$out=@();foreach($p in $paths){ if(Test-Path $p){"
          "$c=Get-Content $p -Raw -EA SilentlyContinue;"
          "$pw=($c -match '<Password>' -or $c -match 'cpassword' -or $c -match 'AdministratorPassword');"
          "$out+=[pscustomobject]@{File=$p;HasPasswordField=[bool]$pw}}};"
          "$out | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No leftover deployment answer files found")]
        with_pw = [r.get("File") for r in rows if r.get("HasPasswordField")]
        if with_pw:
            return [self.finding(target, "FAIL",
                                 f"Answer file(s) with password fields present: {', '.join(with_pw)}",
                                 severity="HIGH", evidence=str(rows))]
        files = ", ".join(str(r.get("File")) for r in rows)
        return [self.finding(target, "WARN", f"Answer file(s) present (review): {files}",
                             severity="LOW", evidence=str(rows))]


@register
class GppCpassword(BaseCheck):
    id = "CRED-GPP-001"
    title = "Group Policy Preferences cpassword in local GPO cache"
    category = CAT
    severity = "CRITICAL"
    reference = "MS14-025 GPP cpassword (AES key is public)"
    attack = "T1552.006"
    remediation = "Remove GPP items that set passwords; the AES key is public so cpassword is trivially decrypted."
    ps = ("$root='C:\\ProgramData\\Microsoft\\Group Policy\\History';$out=@();"
          "if(Test-Path $root){Get-ChildItem $root -Recurse -Include *.xml -EA SilentlyContinue | "
          "ForEach-Object{ $c=Get-Content $_.FullName -Raw -EA SilentlyContinue; if($c -match 'cpassword'){$out+=$_.FullName}}};"
          "[pscustomobject]@{Files=$out} | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        files = as_list(data.get("Files")) if isinstance(data, dict) else []
        if not files:
            return [self.finding(target, "PASS", "No cached GPP cpassword files found")]
        return [self.finding(target, "FAIL",
                             f"{len(files)} cached GPP file(s) contain cpassword (decryptable): "
                             f"{'; '.join(str(f) for f in files[:8])}",
                             severity="CRITICAL", evidence=str(files))]


@register
class PowerShellHistorySecrets(BaseCheck):
    id = "CRED-PSHIST-001"
    title = "Secrets in PowerShell console history"
    category = CAT
    severity = "MEDIUM"
    reference = "PSReadLine ConsoleHost_history.txt"
    attack = "T1552.001"
    remediation = "Clear history files; avoid passing plaintext secrets on the PowerShell command line."
    ps = ("$out=@();Get-ChildItem 'C:\\Users' -Directory -EA SilentlyContinue | ForEach-Object{"
          "$h=Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt';"
          "if(Test-Path $h){ $m=(Select-String -Path $h -Pattern 'password|passwd|-AsPlainText|ConvertTo-SecureString|apikey|api_key|secret|token|-Credential' -EA SilentlyContinue).Count;"
          "if($m -gt 0){$out+=[pscustomobject]@{User=$_.Name;Hits=$m}}}};"
          "$out | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No secret-looking entries in PowerShell history")]
        who = "; ".join(f"{r.get('User')}({r.get('Hits')})" for r in rows)
        return [self.finding(target, "WARN",
                             f"PowerShell history with secret-looking entries for: {who} (values not captured)",
                             severity="MEDIUM", evidence=str(rows))]


@register
class StoredAppSecrets(BaseCheck):
    id = "CRED-APP-001"
    title = "Stored application secrets (PuTTY / WinSCP / SNMP)"
    category = CAT
    severity = "MEDIUM"
    reference = "Reversible app-stored credentials"
    attack = "T1552.001"
    remediation = "Remove saved passwords; WinSCP saved passwords and SNMP community strings are reversible/weak."
    ps = ("$out=@();"
          "if(Test-Path 'HKCU:\\Software\\SimonTatham\\PuTTY\\Sessions'){Get-ChildItem 'HKCU:\\Software\\SimonTatham\\PuTTY\\Sessions'|"
          "ForEach-Object{ if((Get-ItemProperty $_.PSPath).ProxyPassword){$out+=[pscustomobject]@{App='PuTTY';Item=$_.PSChildName;Secret='ProxyPassword'}}}};"
          "$ws='HKCU:\\Software\\Martin Prikryl\\WinSCP 2\\Sessions';"
          "if(Test-Path $ws){Get-ChildItem $ws|ForEach-Object{ if((Get-ItemProperty $_.PSPath).Password){$out+=[pscustomobject]@{App='WinSCP';Item=$_.PSChildName;Secret='Password'}}}};"
          "$snmp='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities';"
          "if(Test-Path $snmp){(Get-ItemProperty $snmp).PSObject.Properties|Where-Object{$_.Name -notlike 'PS*'}|"
          "ForEach-Object{$out+=[pscustomobject]@{App='SNMP';Item=$_.Name;Secret='CommunityString'}}};"
          "$out | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No stored PuTTY/WinSCP/SNMP secrets found")]
        items = "; ".join(f"{r.get('App')}:{r.get('Item')}({r.get('Secret')})" for r in rows)
        has_snmp_default = any(str(r.get("Item", "")).lower() in ("public", "private") for r in rows)
        sev = "HIGH" if has_snmp_default else "MEDIUM"
        return [self.finding(target, "WARN", f"Stored app secret(s): {items}",
                             severity=sev, evidence=str(rows))]


@register
class CachedLogonCount(BaseCheck):
    id = "CRED-CACHED-001"
    title = "Cached domain logon credentials"
    category = CAT
    severity = "LOW"
    reference = "CachedLogonsCount (offline cracking of cached creds)"
    attack = "T1003.005"
    remediation = "Lower CachedLogonsCount (e.g. 0-4) on servers / high-value hosts via GPO."
    ps = ("$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name CachedLogonsCount).CachedLogonsCount;"
          "[pscustomobject]@{CachedLogonsCount=$v} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        val = data.get("CachedLogonsCount") if isinstance(data, dict) else None
        try:
            n = int(str(val))
        except (TypeError, ValueError):
            return [self.finding(target, "INFO", "CachedLogonsCount not set (default 10 applies)")]
        if n > 4:
            return [self.finding(target, "WARN",
                                 f"CachedLogonsCount={n}; cached domain creds recoverable offline",
                                 severity="LOW", evidence=str(data))]
        return [self.finding(target, "PASS", f"CachedLogonsCount={n}", evidence=str(data))]
