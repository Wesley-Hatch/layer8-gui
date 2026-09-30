"""Category 2 - Patch / update status."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List

from ..models import CATEGORY_PATCH, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_PATCH


def _days_since(date_str: str) -> int:
    """Parse yyyy-MM-dd (emitted by the PS scripts) into age in days."""
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            d = datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - d).days
        except (ValueError, AttributeError):
            continue
    return -1


@register
class OsVersion(BaseCheck):
    id = "PATCH-OS-001"
    title = "Operating system version inventory"
    category = CAT
    severity = "MEDIUM"
    reference = "MS Windows lifecycle"
    remediation = "Confirm the build is still in support and on the latest cumulative update."
    ps = ("$o=Get-CimInstance Win32_OperatingSystem;"
          "[pscustomobject]@{Caption=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;"
          "Install=$o.InstallDate.ToString('yyyy-MM-dd');"
          "LastBoot=$o.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        detail = f"{data.get('Caption')} (Version {data.get('Version')}, Build {data.get('Build')})"
        return [self.finding(target, "INFO", detail, evidence=str(data))]


@register
class LastPatch(BaseCheck):
    id = "PATCH-HF-001"
    title = "Recent security updates installed"
    category = CAT
    severity = "HIGH"
    reference = "Patch cadence"
    remediation = "Run Windows Update; investigate why updates have stopped applying."
    ps = ("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 | "
          "ForEach-Object {[pscustomobject]@{HotFixID=$_.HotFixID;"
          "InstalledOn= if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}else{''};"
          "Description=$_.Description}} | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "WARN", "No installed hotfixes reported (Get-HotFix empty)",
                                 severity="MEDIUM")]
        dated = [r for r in rows if r.get("InstalledOn")]
        ages = sorted(_days_since(r["InstalledOn"]) for r in dated if _days_since(r["InstalledOn"]) >= 0)
        newest = ages[0] if ages else -1
        ids = ", ".join(r.get("HotFixID", "?") for r in rows[:5])
        if newest < 0:
            return [self.finding(target, "INFO", f"Hotfixes present but dates unavailable. Recent: {ids}",
                                 evidence=str(rows[:5]))]
        if newest > 90:
            status, sev = "FAIL", "HIGH"
        elif newest > 45:
            status, sev = "WARN", "MEDIUM"
        else:
            status, sev = "PASS", "INFO"
        return [self.finding(target, status,
                             f"Most recent update installed {newest} days ago. Latest: {ids}",
                             severity=sev, evidence=str(rows[:8]))]


@register
class PendingReboot(BaseCheck):
    id = "PATCH-RB-001"
    title = "Pending reboot for updates"
    category = CAT
    severity = "MEDIUM"
    reference = "Patch effectiveness"
    remediation = "Schedule a reboot so pending updates finish applying."
    ps = ("$p=$false;"
          "@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending',"
          "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')"
          "|%{ if(Test-Path $_){$p=$true} };"
          "if((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations).PendingFileRenameOperations){$p=$true};"
          "[pscustomobject]@{PendingReboot=$p} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if isinstance(data, dict) and data.get("PendingReboot"):
            return [self.finding(target, "WARN", "A reboot is pending; some updates are not yet fully applied",
                                 evidence=str(data))]
        return [self.finding(target, "PASS", "No pending reboot detected", evidence=str(data))]


@register
class WindowsUpdateService(BaseCheck):
    id = "PATCH-SVC-001"
    title = "Windows Update service is not disabled"
    category = CAT
    severity = "MEDIUM"
    reference = "Ensure the host can receive updates"
    remediation = "Set wuauserv StartType to Manual (or Automatic) so updates can install."
    ps = "Get-Service wuauserv | Select-Object Name,Status,StartType | ConvertTo-Json -Compress"

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        start = str(data.get("StartType"))
        if start.lower() in ("4", "disabled"):
            return [self.finding(target, "FAIL", "Windows Update service (wuauserv) is DISABLED",
                                 evidence=str(data))]
        return [self.finding(target, "PASS", f"Windows Update service start type: {start}", evidence=str(data))]
