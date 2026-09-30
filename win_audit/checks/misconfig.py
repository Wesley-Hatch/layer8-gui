"""Category 1 - Misconfigurations."""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_MISCONFIG, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_MISCONFIG


@register
class FirewallProfiles(BaseCheck):
    id = "MISC-FW-001"
    title = "Windows Firewall enabled on all profiles"
    category = CAT
    severity = "HIGH"
    reference = "CIS Windows: Windows Firewall - Domain/Private/Public"
    remediation = "Enable the firewall for every profile: Set-NetFirewallProfile -All -Enabled True"
    ps = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        disabled = [r["Name"] for r in rows if not r.get("Enabled")]
        if disabled:
            return [self.finding(
                target, "FAIL",
                detail=f"Firewall disabled on profile(s): {', '.join(disabled)}",
                evidence=str(rows))]
        return [self.finding(target, "PASS", "Firewall enabled on all profiles", evidence=str(rows))]


@register
class SmbServerHardening(BaseCheck):
    id = "MISC-SMB-001"
    title = "SMB server hardening (SMBv1 / signing / encryption)"
    category = CAT
    severity = "HIGH"
    reference = "MS: Stop using SMB1; CIS SMB signing"
    remediation = ("Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false) and "
                   "require signing (-RequireSecuritySignature $true).")
    ps = ("$c=Get-SmbServerConfiguration;"
          "[pscustomobject]@{SMB1=$c.EnableSMB1Protocol;RequireSigning=$c.RequireSecuritySignature;"
          "Encrypt=$c.EncryptData} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        if data.get("SMB1"):
            out.append(self.finding(target, "FAIL", "SMBv1 protocol is ENABLED (legacy, exploitable)",
                                    severity="HIGH", evidence=str(data), title="SMBv1 enabled"))
        else:
            out.append(self.finding(target, "PASS", "SMBv1 is disabled", title="SMBv1 enabled"))
        if not data.get("RequireSigning"):
            out.append(self.finding(target, "FAIL", "SMB signing is NOT required (relay/MITM risk)",
                                    severity="MEDIUM", evidence=str(data), title="SMB signing required",
                                    remediation="Set-SmbServerConfiguration -RequireSecuritySignature $true"))
        else:
            out.append(self.finding(target, "PASS", "SMB signing is required", title="SMB signing required"))
        return out


@register
class RdpConfig(BaseCheck):
    id = "MISC-RDP-001"
    title = "Remote Desktop exposure & Network Level Authentication"
    category = CAT
    severity = "HIGH"
    reference = "CIS: Require NLA for RDP"
    remediation = "If RDP is not needed, disable it. If needed, require NLA (UserAuthentication=1)."
    ps = ("$d=(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections;"
          "$n=(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication).UserAuthentication;"
          "[pscustomobject]@{DenyRDP=$d;NLA=$n} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        enabled = data.get("DenyRDP") == 0
        if not enabled:
            return [self.finding(target, "PASS", "RDP is disabled", evidence=str(data))]
        if data.get("NLA") != 1:
            return [self.finding(target, "FAIL", "RDP is enabled WITHOUT Network Level Authentication",
                                 severity="HIGH", evidence=str(data))]
        return [self.finding(target, "WARN", "RDP is enabled (with NLA) - confirm this is intended & firewalled",
                             severity="LOW", evidence=str(data))]


@register
class UacConfig(BaseCheck):
    id = "MISC-UAC-001"
    title = "User Account Control (UAC) enabled"
    category = CAT
    severity = "HIGH"
    reference = "CIS: User Account Control settings"
    remediation = "Set EnableLUA=1 and a prompting ConsentPromptBehaviorAdmin (2 or 5); reboot."
    ps = ("$p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';"
          "[pscustomobject]@{EnableLUA=$p.EnableLUA;ConsentAdmin=$p.ConsentPromptBehaviorAdmin;"
          "FilterAdminToken=$p.FilterAdministratorToken} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if data.get("EnableLUA") != 1:
            return [self.finding(target, "FAIL", "UAC is DISABLED (EnableLUA != 1)",
                                 severity="HIGH", evidence=str(data))]
        if data.get("ConsentAdmin") == 0:
            return [self.finding(target, "WARN", "UAC on, but admins are elevated without prompting",
                                 severity="MEDIUM", evidence=str(data))]
        return [self.finding(target, "PASS", "UAC enabled and prompting", evidence=str(data))]


@register
class LlmnrNbtns(BaseCheck):
    id = "MISC-NET-002"
    title = "LLMNR / NetBIOS name resolution disabled"
    category = CAT
    severity = "MEDIUM"
    reference = "Poisoning (Responder) mitigation"
    remediation = ("Disable LLMNR via GPO (EnableMulticast=0) and set NetBIOS over TCP/IP to Disabled "
                   "on adapters.")
    ps = ("$llmnr=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast).EnableMulticast;"
          "[pscustomobject]@{EnableMulticast=$llmnr} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        val = data.get("EnableMulticast") if isinstance(data, dict) else None
        if val == 0:
            return [self.finding(target, "PASS", "LLMNR is disabled by policy", evidence=str(data))]
        return [self.finding(target, "FAIL",
                             "LLMNR is enabled (or unmanaged) - vulnerable to name-resolution poisoning",
                             evidence=str(data))]


@register
class WdigestLsa(BaseCheck):
    id = "MISC-CRED-001"
    title = "Credential exposure hardening (WDigest / LSA protection)"
    category = CAT
    severity = "HIGH"
    reference = "Mimikatz mitigation: WDigest, RunAsPPL"
    remediation = ("Set WDigest UseLogonCredential=0 and enable LSA protection RunAsPPL=1.")
    ps = ("$w=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential).UseLogonCredential;"
          "$l=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL).RunAsPPL;"
          "[pscustomobject]@{WDigest=$w;RunAsPPL=$l} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        if data.get("WDigest") == 1:
            out.append(self.finding(target, "FAIL", "WDigest credential caching is ENABLED (cleartext creds in LSASS)",
                                    severity="HIGH", evidence=str(data), title="WDigest cleartext creds"))
        else:
            out.append(self.finding(target, "PASS", "WDigest does not cache cleartext credentials",
                                    title="WDigest cleartext creds"))
        if data.get("RunAsPPL") not in (1, 2):
            out.append(self.finding(target, "WARN", "LSA protection (RunAsPPL) is not enabled",
                                    severity="MEDIUM", evidence=str(data), title="LSA protection (RunAsPPL)",
                                    remediation="Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL=1; reboot."))
        else:
            out.append(self.finding(target, "PASS", "LSA protection (RunAsPPL) enabled",
                                    title="LSA protection (RunAsPPL)"))
        return out


@register
class PowerShellV2(BaseCheck):
    id = "MISC-PSV2-001"
    title = "PowerShell v2 engine removed"
    category = CAT
    severity = "MEDIUM"
    reference = "PSv2 bypasses modern logging/AMSI"
    remediation = "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
    ps = ("$f=Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -EA SilentlyContinue;"
          "[pscustomobject]@{State=$f.State} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        state = data.get("State") if isinstance(data, dict) else None
        # State can be int enum or string depending on host.
        enabled = str(state).lower() in ("2", "enabled")
        if enabled:
            return [self.finding(target, "FAIL", "PowerShell v2 engine is installed/enabled (logging bypass)",
                                 evidence=str(data))]
        return [self.finding(target, "PASS", "PowerShell v2 engine not enabled", evidence=str(data))]
