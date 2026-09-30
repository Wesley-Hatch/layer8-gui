"""Category 12 - Detection & EDR posture."""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_DETECTION, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_DETECTION


@register
class DefenderExclusions(BaseCheck):
    id = "DET-EXCL-001"
    title = "Microsoft Defender exclusions (blind spots)"
    category = CAT
    severity = "MEDIUM"
    reference = "Attackers add/abuse AV exclusions"
    attack = "T1562.001"
    remediation = ("Review every exclusion; each is a location AV will not scan. Remove broad/unexpected "
                   "exclusions - attackers add these to stage payloads.")
    ps = ("$p=Get-MpPreference -EA SilentlyContinue;"
          "[pscustomobject]@{Paths=@($p.ExclusionPath);Procs=@($p.ExclusionProcess);"
          "Exts=@($p.ExclusionExtension);Ips=@($p.ExclusionIpAddress)} | ConvertTo-Json -Depth 3")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self.finding(target, "INFO", "Defender preferences unavailable (3rd-party AV?)",
                                 evidence=str(raw.stdout[:150]))]
        paths = as_list(data.get("Paths"))
        procs = as_list(data.get("Procs"))
        exts = as_list(data.get("Exts"))
        # Non-admin Get-MpPreference returns a sentinel string instead of the list.
        if any("must be an administrator" in str(v).lower()
               for v in paths + procs + exts):
            return [self.finding(target, "ERROR",
                                 "Defender exclusions require administrator rights to read",
                                 severity="INFO",
                                 remediation="Re-run elevated to enumerate exclusions.")]
        total = len(paths) + len(procs) + len(exts)
        if total == 0:
            return [self.finding(target, "PASS", "No Defender exclusions configured")]
        # Broad/risky exclusions are worse.
        broad = [p for p in paths if str(p).rstrip("\\").lower() in
                 ("c:", "c:\\", "c:\\users", "c:\\windows", "c:\\programdata", "c:\\temp")]
        sev = "HIGH" if broad else "MEDIUM"
        detail = (f"{total} Defender exclusion(s): paths={paths[:8]} procs={procs[:8]} exts={exts[:8]}")
        if broad:
            detail += f"  ** BROAD exclusion(s): {broad} **"
        return [self.finding(target, "WARN", detail, severity=sev,
                             evidence=str({"paths": paths, "procs": procs, "exts": exts}))]


@register
class AsrRules(BaseCheck):
    id = "DET-ASR-001"
    title = "Attack Surface Reduction rules not enforced"
    category = CAT
    severity = "MEDIUM"
    reference = "Defender ASR rules"
    attack = "T1562"
    remediation = "Deploy Defender ASR rules in Block mode (Office child-process, credential theft, LSASS, etc.)."
    ps = ("$p=Get-MpPreference -EA SilentlyContinue;"
          "[pscustomobject]@{Ids=@($p.AttackSurfaceReductionRules_Ids);"
          "Actions=@($p.AttackSurfaceReductionRules_Actions)} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self.finding(target, "INFO", "ASR status unavailable", evidence=str(raw.stdout[:150]))]
        ids = as_list(data.get("Ids"))
        actions = as_list(data.get("Actions"))
        blocking = sum(1 for a in actions if str(a) in ("1", "Block"))
        if not ids:
            return [self.finding(target, "WARN", "No Attack Surface Reduction rules configured",
                                 severity="MEDIUM", evidence=str(data))]
        if blocking == 0:
            return [self.finding(target, "WARN",
                                 f"{len(ids)} ASR rule(s) configured but none in Block mode",
                                 severity="MEDIUM", evidence=str(data))]
        return [self.finding(target, "PASS", f"{blocking} ASR rule(s) in Block mode", evidence=str(data))]


@register
class SysmonPresence(BaseCheck):
    id = "DET-SYSMON-001"
    title = "Sysmon endpoint telemetry"
    category = CAT
    severity = "LOW"
    reference = "Sysinternals Sysmon"
    attack = "T1562"
    remediation = "Deploy Sysmon with a tuned config for deep process/network/registry telemetry."
    ps = ("$svc=Get-Service -Name Sysmon,Sysmon64 -EA SilentlyContinue | Select-Object Name,Status;"
          "[pscustomobject]@{Sysmon=@($svc)} | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        svc = as_list(data.get("Sysmon")) if isinstance(data, dict) else []
        running = [s for s in svc if str(s.get("Status")).lower() == "running"]
        if running:
            return [self.finding(target, "PASS", "Sysmon is running", evidence=str(svc))]
        return [self.finding(target, "WARN",
                             "Sysmon not detected (reduced host telemetry for detection/IR)",
                             severity="LOW", evidence=str(svc))]


@register
class SecurityLogSize(BaseCheck):
    id = "DET-EVTSIZE-001"
    title = "Security event log capacity"
    category = CAT
    severity = "LOW"
    reference = "Log rollover hides attacker activity"
    attack = "T1070.001"
    remediation = "Increase the Security log size (>= 1 GB on servers/DCs) and forward events to a SIEM."
    ps = ("$s=Get-WinEvent -ListLog Security -EA SilentlyContinue;"
          "[pscustomobject]@{MaxMB=[int]($s.MaximumSizeInBytes/1MB);Mode=[string]$s.LogMode;"
          "Records=$s.RecordCount} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        max_mb = data.get("MaxMB")
        try:
            mb = int(max_mb)
        except (TypeError, ValueError):
            return [self.finding(target, "INFO", "Security log size unavailable", evidence=str(data))]
        if mb <= 0:
            return [self.finding(target, "INFO",
                                 "Security log size not readable (run elevated)", evidence=str(data))]
        if mb < 192:
            return [self.finding(target, "WARN",
                                 f"Security log max size is only {mb} MB (fast rollover; forensic gaps)",
                                 severity="LOW", evidence=str(data))]
        return [self.finding(target, "PASS", f"Security log max size {mb} MB", evidence=str(data))]
