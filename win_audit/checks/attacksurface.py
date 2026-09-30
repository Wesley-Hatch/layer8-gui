"""Category 9 - Coercion / relay / lateral-movement attack surface."""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_ATTACKSURFACE, Finding
from ..transport import CommandResult
from .base import BaseCheck, register


CAT = CATEGORY_ATTACKSURFACE


@register
class PrintSpooler(BaseCheck):
    id = "AS-SPOOLER-001"
    title = "Print Spooler & Point-and-Print (PrintNightmare / PetitPotam)"
    category = CAT
    severity = "HIGH"
    reference = "CVE-2021-34527 PrintNightmare; MS-RPRN coercion"
    attack = "T1068 / T1187"
    remediation = ("Disable the Spooler on servers/DCs that don't print. Set Point-and-Print "
                   "NoWarningNoElevationOnInstall=0 and RestrictDriverInstallationToAdministrators=1.")
    ps = ("$svc=Get-Service Spooler -EA SilentlyContinue;"
          "$pp=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -EA SilentlyContinue;"
          "$role=(Get-CimInstance Win32_ComputerSystem).DomainRole;"
          "[pscustomobject]@{Status=[string]$svc.Status;Start=[string]$svc.StartType;DomainRole=$role;"
          "NoWarnInstall=$pp.NoWarningNoElevationOnInstall;NoWarnUpdate=$pp.NoWarningNoElevationOnUpdate;"
          "RestrictDriverAdmins=$pp.RestrictDriverInstallationToAdministrators} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        running = str(data.get("Status")).lower() == "running"
        is_dc = data.get("DomainRole") in (4, 5)
        if data.get("NoWarnInstall") == 1:
            out.append(self.finding(target, "FAIL",
                                    "Point-and-Print allows non-admin driver install (PrintNightmare RCE/privesc)",
                                    severity="CRITICAL", evidence=str(data), title="Point-and-Print privesc"))
        if running:
            sev = "HIGH" if is_dc else "MEDIUM"
            role = "Domain Controller" if is_dc else "host"
            out.append(self.finding(target, "WARN",
                                    f"Print Spooler is running on this {role} (MS-RPRN/PetitPotam coercion surface)",
                                    severity=sev, evidence=str(data), title="Print Spooler running"))
        if data.get("RestrictDriverAdmins") == 0:
            out.append(self.finding(target, "WARN",
                                    "Driver installation is not restricted to administrators",
                                    severity="MEDIUM", evidence=str(data), title="Unrestricted driver install"))
        if not out:
            out.append(self.finding(target, "PASS", "Spooler stopped / Point-and-Print hardened",
                                    evidence=str(data)))
        return out


@register
class WebClientService(BaseCheck):
    id = "AS-WEBCLIENT-001"
    title = "WebClient (WebDAV) service enables HTTP->NTLM relay"
    category = CAT
    severity = "MEDIUM"
    reference = "WebDAV coercion for NTLM relay"
    attack = "T1187"
    remediation = "Disable the WebClient service where WebDAV is not required."
    ps = ("$svc=Get-Service WebClient -EA SilentlyContinue;"
          "[pscustomobject]@{Present=[bool]$svc;Status=[string]$svc.Status;Start=[string]$svc.StartType} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict) or not data.get("Present"):
            return [self.finding(target, "PASS", "WebClient/WebDAV service not present")]
        if str(data.get("Status")).lower() == "running":
            return [self.finding(target, "FAIL",
                                 "WebClient (WebDAV) is running - enables authenticated HTTP->NTLM relay coercion",
                                 severity="MEDIUM", evidence=str(data))]
        return [self.finding(target, "INFO", f"WebClient present but {data.get('Status')}",
                             evidence=str(data))]


@register
class WsusOverHttp(BaseCheck):
    id = "AS-WSUS-001"
    title = "WSUS served over cleartext HTTP (update MITM -> SYSTEM)"
    category = CAT
    severity = "HIGH"
    reference = "WSUS HTTP MITM (WSUSpect / WSUSpendu)"
    attack = "T1195.002"
    remediation = "Serve WSUS over HTTPS and enable TLS; an HTTP WSUS endpoint can be MITM'd to run code as SYSTEM."
    ps = ("$p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -EA SilentlyContinue;"
          "[pscustomobject]@{WUServer=$p.WUServer;WUStatusServer=$p.WUStatusServer} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        server = (data.get("WUServer") if isinstance(data, dict) else None) or ""
        if not server:
            return [self.finding(target, "INFO", "No WSUS server configured (uses Microsoft/Windows Update)")]
        if server.lower().startswith("http://"):
            return [self.finding(target, "FAIL",
                                 f"WSUS is configured over cleartext HTTP: {server}",
                                 severity="HIGH", evidence=str(data))]
        return [self.finding(target, "PASS", f"WSUS over HTTPS: {server}", evidence=str(data))]


@register
class NtlmCompatibility(BaseCheck):
    id = "AS-NTLM-001"
    title = "Legacy NTLM/LM authentication allowed"
    category = CAT
    severity = "HIGH"
    reference = "LmCompatibilityLevel (NTLMv1/LM downgrade & relay)"
    attack = "T1557.001"
    remediation = "Set LmCompatibilityLevel=5 (send NTLMv2 only, refuse LM & NTLMv1)."
    ps = ("$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel;"
          "[pscustomobject]@{LmCompatibilityLevel=$v} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        val = data.get("LmCompatibilityLevel") if isinstance(data, dict) else None
        if val is None:
            return [self.finding(target, "WARN",
                                 "LmCompatibilityLevel unset (OS default may allow NTLMv1/LM)",
                                 severity="MEDIUM", evidence=str(data))]
        try:
            n = int(val)
        except (TypeError, ValueError):
            return [self._error(target, raw)]
        if n < 3:
            return [self.finding(target, "FAIL",
                                 f"LmCompatibilityLevel={n} permits LM/NTLMv1 (crackable, relayable)",
                                 severity="HIGH", evidence=str(data))]
        if n < 5:
            return [self.finding(target, "WARN",
                                 f"LmCompatibilityLevel={n}; recommend 5 (NTLMv2 only)",
                                 severity="MEDIUM", evidence=str(data))]
        return [self.finding(target, "PASS", f"LmCompatibilityLevel={n} (NTLMv2 only)", evidence=str(data))]


@register
class SmbClientSigning(BaseCheck):
    id = "AS-SMBSIGN-001"
    title = "SMB client signing & SMBv1 client"
    category = CAT
    severity = "MEDIUM"
    reference = "SMB relay via unsigned client sessions"
    attack = "T1557.001"
    remediation = "Require SMB client signing and disable the SMBv1 client."
    ps = ("$c=Get-SmbClientConfiguration;"
          "[pscustomobject]@{RequireSigning=$c.RequireSecuritySignature;SMB1=$c.EnableSMB1Protocol} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        if not data.get("RequireSigning"):
            out.append(self.finding(target, "FAIL", "SMB client signing not required (relay risk)",
                                    severity="MEDIUM", evidence=str(data), title="SMB client signing"))
        else:
            out.append(self.finding(target, "PASS", "SMB client signing required", title="SMB client signing"))
        if data.get("SMB1"):
            out.append(self.finding(target, "FAIL", "SMBv1 client is enabled",
                                    severity="HIGH", evidence=str(data), title="SMBv1 client enabled"))
        return out


@register
class AnonymousEnumeration(BaseCheck):
    id = "AS-NULLSESS-001"
    title = "Anonymous / null-session enumeration"
    category = CAT
    severity = "MEDIUM"
    reference = "RestrictAnonymous / RestrictAnonymousSAM"
    attack = "T1087"
    remediation = "Set RestrictAnonymousSAM=1 and EveryoneIncludesAnonymous=0."
    ps = ("$l=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa';"
          "[pscustomobject]@{RestrictAnonymous=$l.RestrictAnonymous;RestrictAnonymousSAM=$l.RestrictAnonymousSAM;"
          "EveryoneIncludesAnonymous=$l.EveryoneIncludesAnonymous} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        if data.get("RestrictAnonymousSAM") != 1:
            out.append(self.finding(target, "WARN", "RestrictAnonymousSAM not enabled (SAM enumeration)",
                                    severity="MEDIUM", evidence=str(data), title="Anonymous SAM enumeration"))
        if data.get("EveryoneIncludesAnonymous") == 1:
            out.append(self.finding(target, "FAIL", "EveryoneIncludesAnonymous=1 (anonymous gets Everyone rights)",
                                    severity="HIGH", evidence=str(data), title="Anonymous = Everyone"))
        if not out:
            out.append(self.finding(target, "PASS", "Anonymous enumeration restricted", evidence=str(data)))
        return out


@register
class LdapSigning(BaseCheck):
    id = "AS-LDAP-001"
    title = "LDAP signing & channel binding (Domain Controller)"
    category = CAT
    severity = "HIGH"
    reference = "LDAP relay (ADV190023)"
    attack = "T1557.001"
    remediation = "On DCs set LDAPServerIntegrity=2 (require signing) and enforce channel binding."
    ps = ("$role=(Get-CimInstance Win32_ComputerSystem).DomainRole;"
          "$i=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -EA SilentlyContinue).LDAPServerIntegrity;"
          "[pscustomobject]@{DomainRole=$role;LDAPServerIntegrity=$i} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if data.get("DomainRole") not in (4, 5):
            return [self.finding(target, "INFO", "Not a Domain Controller (LDAP signing check N/A)")]
        if data.get("LDAPServerIntegrity") != 2:
            return [self.finding(target, "FAIL",
                                 "DC does not require LDAP signing (LDAP relay risk)",
                                 severity="HIGH", evidence=str(data))]
        return [self.finding(target, "PASS", "DC requires LDAP signing", evidence=str(data))]
