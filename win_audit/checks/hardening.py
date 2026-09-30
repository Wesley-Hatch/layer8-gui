"""Category 10 - Crypto & exploit-mitigation hardening."""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_HARDENING, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_HARDENING


@register
class WeakTlsProtocols(BaseCheck):
    id = "HARD-SCHANNEL-001"
    title = "Weak SSL/TLS protocols enabled (SChannel)"
    category = CAT
    severity = "MEDIUM"
    reference = "SChannel Protocols; POODLE/BEAST/downgrade"
    attack = "T1557 / T1040"
    remediation = "Explicitly disable SSL 2.0/3.0 and TLS 1.0/1.1 (Server Enabled=0, DisabledByDefault=1)."
    ps = ("$base='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols';"
          "$weak=@('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1');$out=@();"
          "foreach($p in $weak){ $k=\"$base\\$p\\Server\"; $en=$null;$dis=$null;"
          "if(Test-Path $k){$pp=Get-ItemProperty $k -EA SilentlyContinue;$en=$pp.Enabled;$dis=$pp.DisabledByDefault};"
          "$out+=[pscustomobject]@{Protocol=$p;Enabled=$en;DisabledByDefault=$dis}};"
          "$out | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        out: List[Finding] = []
        for r in rows:
            proto = r.get("Protocol")
            enabled = r.get("Enabled")
            disabled_default = r.get("DisabledByDefault")
            hardened = (enabled == 0)
            legacy = proto in ("SSL 2.0", "SSL 3.0")
            if hardened:
                continue
            if enabled == 1:
                out.append(self.finding(target, "FAIL", f"{proto} is explicitly ENABLED",
                                        severity="HIGH" if legacy else "MEDIUM",
                                        evidence=str(r), title=f"{proto} enabled"))
            else:
                # Key absent / not explicitly disabled -> depends on OS default.
                out.append(self.finding(target, "WARN",
                                        f"{proto} is not explicitly disabled (relies on OS default)",
                                        severity="MEDIUM" if legacy else "LOW",
                                        evidence=str(r), title=f"{proto} not hardened"))
        if not out:
            return [self.finding(target, "PASS", "SSL2/3 and TLS1.0/1.1 explicitly disabled")]
        return out


@register
class WeakCiphers(BaseCheck):
    id = "HARD-CIPHER-001"
    title = "Weak SChannel ciphers enabled"
    category = CAT
    severity = "MEDIUM"
    reference = "RC4/DES/NULL cipher suites"
    attack = "T1040"
    remediation = "Disable RC4, DES and NULL ciphers in SChannel (Enabled=0)."
    ps = ("$base='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers';$out=@();"
          "if(Test-Path $base){Get-ChildItem $base -EA SilentlyContinue | ForEach-Object{"
          "$en=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).Enabled;"
          "$out+=[pscustomobject]@{Cipher=$_.PSChildName;Enabled=$en}}};"
          "$out | ConvertTo-Json")

    WEAK = ("rc4", "des ", "null", "des 56")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "INFO",
                                 "No explicit SChannel cipher config (OS defaults apply) - verify on internet-facing hosts")]
        bad = [r for r in rows
               if any(w in str(r.get("Cipher", "")).lower() for w in self.WEAK) and r.get("Enabled") != 0]
        if bad:
            names = ", ".join(str(r.get("Cipher")) for r in bad)
            return [self.finding(target, "FAIL", f"Weak cipher(s) enabled: {names}",
                                 severity="MEDIUM", evidence=str(bad))]
        return [self.finding(target, "PASS", "No weak SChannel ciphers explicitly enabled", evidence=str(rows))]


@register
class CredentialGuard(BaseCheck):
    id = "HARD-CG-001"
    title = "Credential Guard / VBS not running"
    category = CAT
    severity = "MEDIUM"
    reference = "LSASS credential protection via VBS"
    attack = "T1003.001"
    remediation = "Enable Virtualization-Based Security and Credential Guard on capable hosts."
    ps = ("$dg=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -EA SilentlyContinue;"
          "[pscustomobject]@{Configured=$dg.SecurityServicesConfigured;Running=$dg.SecurityServicesRunning;"
          "VBS=$dg.VirtualizationBasedSecurityStatus} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self.finding(target, "INFO", "DeviceGuard status unavailable", evidence=str(raw.stdout[:200]))]
        running = data.get("Running") or []
        if isinstance(running, int):
            running = [running]
        # Service id 1 = Credential Guard.
        if 1 in (running or []):
            return [self.finding(target, "PASS", "Credential Guard is running", evidence=str(data))]
        return [self.finding(target, "WARN",
                             "Credential Guard is not running (LSASS credentials less protected)",
                             severity="MEDIUM", evidence=str(data))]


@register
class ExploitMitigations(BaseCheck):
    id = "HARD-MITIG-001"
    title = "System-wide exploit mitigations (DEP / ASLR / SEHOP / CFG)"
    category = CAT
    severity = "MEDIUM"
    reference = "Windows Exploit Protection"
    attack = "T1211"
    remediation = "Enable DEP, mandatory/bottom-up ASLR, SEHOP and CFG in Exploit Protection / GPO."
    ps = ("$m=Get-ProcessMitigation -System -EA SilentlyContinue;"
          "[pscustomobject]@{DEP=[string]$m.Dep.Enable;ASLR_BottomUp=[string]$m.ASLR.BottomUp;"
          "ASLR_ForceRelocate=[string]$m.ASLR.ForceRelocateImages;SEHOP=[string]$m.SEHOP.Enable;"
          "CFG=[string]$m.CFG.Enable} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]

        def off(v):
            return str(v).upper() in ("OFF", "NOTSET", "FALSE", "0", "")

        weak = []
        if off(data.get("DEP")):
            weak.append("DEP")
        if off(data.get("ASLR_BottomUp")):
            weak.append("Bottom-up ASLR")
        if off(data.get("SEHOP")):
            weak.append("SEHOP")
        if off(data.get("CFG")):
            weak.append("CFG")
        if weak:
            return [self.finding(target, "WARN",
                                 f"System mitigation(s) not fully enabled: {', '.join(weak)}",
                                 severity="MEDIUM", evidence=str(data))]
        return [self.finding(target, "PASS", "Core system exploit mitigations enabled", evidence=str(data))]
