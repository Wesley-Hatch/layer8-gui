"""Category 11 - Persistence & compromise hunt.

Unlike the other categories (which find weaknesses), these look for signs an
attacker has *already* established persistence. Hits here are potential active
compromise and should be triaged immediately.
"""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_PERSISTENCE, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register
from .pssnippets import PS_ACL_HELPER


CAT = CATEGORY_PERSISTENCE

ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
                 "displayswitch.exe", "atbroker.exe", "narrator.exe"}


@register
class IfeoDebuggers(BaseCheck):
    id = "PERSIST-IFEO-001"
    title = "Image File Execution Options debugger / SilentProcessExit hijacks"
    category = CAT
    severity = "HIGH"
    reference = "IFEO Debugger & accessibility backdoors"
    attack = "T1546.008 / T1546.012"
    remediation = "Remove Debugger values under IFEO and MonitorProcess under SilentProcessExit; investigate the host."
    ps = ("$base='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options';"
          "$out=@();Get-ChildItem $base -EA SilentlyContinue | ForEach-Object{"
          "$d=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).Debugger; if($d){$out+=[pscustomobject]@{Image=$_.PSChildName;Debugger=$d}}};"
          "$s='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit';$mon=@();"
          "if(Test-Path $s){Get-ChildItem $s -EA SilentlyContinue|ForEach-Object{"
          "$mp=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).MonitorProcess; if($mp){$mon+=[pscustomobject]@{Image=$_.PSChildName;Monitor=$mp}}}};"
          "[pscustomobject]@{Debuggers=@($out);SilentExit=@($mon)} | ConvertTo-Json -Depth 4")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        for r in as_list(data.get("Debuggers")):
            img = str(r.get("Image", "")).lower()
            is_access = img in ACCESSIBILITY
            out.append(self.finding(
                target, "FAIL",
                f"IFEO debugger set on '{r.get('Image')}' -> {r.get('Debugger')}"
                + (" (ACCESSIBILITY BACKDOOR)" if is_access else ""),
                severity="CRITICAL" if is_access else "HIGH",
                evidence=str(r), title=f"IFEO hijack: {r.get('Image')}"))
        for r in as_list(data.get("SilentExit")):
            out.append(self.finding(
                target, "FAIL",
                f"SilentProcessExit monitor on '{r.get('Image')}' -> {r.get('Monitor')}",
                severity="HIGH", evidence=str(r), title=f"SilentProcessExit: {r.get('Image')}"))
        if not out:
            return [self.finding(target, "PASS", "No IFEO/SilentProcessExit hijacks found")]
        return out


@register
class WinlogonHijack(BaseCheck):
    id = "PERSIST-WINLOGON-001"
    title = "Winlogon Shell / Userinit tampering"
    category = CAT
    severity = "HIGH"
    reference = "Winlogon persistence"
    attack = "T1547.004"
    remediation = "Restore Shell=explorer.exe and Userinit to the default userinit.exe path; investigate."
    ps = ("$w=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
          "[pscustomobject]@{Shell=$w.Shell;Userinit=$w.Userinit} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        shell = str(data.get("Shell", "")).strip().lower()
        if shell and shell != "explorer.exe":
            out.append(self.finding(target, "FAIL", f"Winlogon Shell is not explorer.exe: '{data.get('Shell')}'",
                                    severity="CRITICAL", evidence=str(data), title="Winlogon Shell hijack"))
        userinit = str(data.get("Userinit", "")).strip().lower().rstrip(",")
        # Allow the single default entry (path to userinit.exe).
        parts = [p for p in userinit.split(",") if p.strip()]
        extra = [p for p in parts if "userinit.exe" not in p]
        if extra:
            out.append(self.finding(target, "FAIL",
                                    f"Winlogon Userinit has extra command(s): {data.get('Userinit')}",
                                    severity="CRITICAL", evidence=str(data), title="Winlogon Userinit hijack"))
        if not out:
            return [self.finding(target, "PASS", "Winlogon Shell/Userinit are default", evidence=str(data))]
        return out


@register
class AppInitDlls(BaseCheck):
    id = "PERSIST-APPINIT-001"
    title = "AppInit_DLLs injection persistence"
    category = CAT
    severity = "HIGH"
    reference = "AppInit_DLLs loaded into every user process"
    attack = "T1546.010"
    remediation = "Clear AppInit_DLLs and set LoadAppInit_DLLs=0."
    ps = ("$p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' -EA SilentlyContinue;"
          "$p6=Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows' -EA SilentlyContinue;"
          "[pscustomobject]@{AppInit=$p.AppInit_DLLs;Load=$p.LoadAppInit_DLLs;AppInit32=$p6.AppInit_DLLs;Load32=$p6.LoadAppInit_DLLs} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        for dll_key, load_key, label in (("AppInit", "Load", "AppInit_DLLs"),
                                         ("AppInit32", "Load32", "AppInit_DLLs (WOW64)")):
            dlls = str(data.get(dll_key) or "").strip()
            if dlls:
                out.append(self.finding(target, "FAIL",
                                        f"{label} is set: {dlls} (Load={data.get(load_key)})",
                                        severity="HIGH", evidence=str(data), title=label))
        if not out:
            return [self.finding(target, "PASS", "AppInit_DLLs not configured", evidence=str(data))]
        return out


@register
class WmiPersistence(BaseCheck):
    id = "PERSIST-WMI-001"
    title = "WMI permanent event subscription persistence"
    category = CAT
    severity = "HIGH"
    reference = "__EventFilter / CommandLineEventConsumer / ActiveScriptEventConsumer"
    attack = "T1546.003"
    remediation = "Remove unrecognized WMI event consumers/filters/bindings; investigate the host."
    ps = ("$c=Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer -EA SilentlyContinue | "
          "Select-Object Name,__CLASS;"
          "$f=Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -EA SilentlyContinue | "
          "Select-Object Name;"
          "[pscustomobject]@{Consumers=@($c);Filters=@($f)} | ConvertTo-Json -Depth 4")

    RISKY = ("CommandLineEventConsumer", "ActiveScriptEventConsumer")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        consumers = as_list(data.get("Consumers"))
        risky = [c for c in consumers if str(c.get("__CLASS")) in self.RISKY]
        if risky:
            names = "; ".join(f"{c.get('Name')} ({c.get('__CLASS')})" for c in risky)
            return [self.finding(target, "FAIL",
                                 f"Code-executing WMI event consumer(s) present: {names}",
                                 severity="HIGH", evidence=str(consumers))]
        if consumers:
            names = ", ".join(str(c.get("Name")) for c in consumers)
            return [self.finding(target, "INFO",
                                 f"WMI event consumer(s) present (review): {names}",
                                 evidence=str(consumers))]
        return [self.finding(target, "PASS", "No WMI event-subscription persistence found")]


@register
class RogueAutostartServices(BaseCheck):
    id = "PERSIST-SVC-001"
    title = "Auto-start services running from abnormal locations"
    category = CAT
    severity = "HIGH"
    reference = "Service binaries in user-writable / temp paths"
    attack = "T1543.003"
    remediation = "Investigate any service whose binary lives under Users/Temp/AppData/Public/Downloads."
    # Test only the resolved EXE (not command-line args), against genuinely
    # attacker-writable locations. \Windows\ and \Program Files are excluded so
    # legitimate signed services (Defender under ProgramData\...\Platform, NVIDIA
    # under DriverStore) don't false-positive.
    ps = (PS_ACL_HELPER +
          "$susp='\\\\Users\\\\|\\\\AppData\\\\|\\\\Temp\\\\|\\\\Windows\\\\Temp\\\\|\\\\Public\\\\|\\\\Downloads\\\\|\\\\\\$Recycle';"
          "$out=@();"
          "foreach($s in (Get-CimInstance Win32_Service | Where-Object{$_.StartMode -eq 'Auto'})){"
          "$exe=Get-ServiceExe $s.PathName; if(-not $exe){continue}"
          "if($exe -match $susp){"
          "$out+=[pscustomobject]@{Name=$s.Name;State=$s.State;Account=$s.StartName;Exe=$exe;Path=$s.PathName}}};"
          "$out | ConvertTo-Json -Depth 3")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "PASS", "No auto-start services in abnormal locations")]
        out: List[Finding] = []
        for r in rows:
            out.append(self.finding(
                target, "FAIL",
                f"Auto-start service '{r.get('Name')}' runs from abnormal location: {r.get('Exe')}",
                severity="HIGH", evidence=str(r), title=f"Suspicious service: {r.get('Name')}"))
        return out
