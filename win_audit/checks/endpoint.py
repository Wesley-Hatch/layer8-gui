"""Category 5 (extra) - Endpoint protection & encryption."""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_ENDPOINT, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_ENDPOINT


@register
class DefenderStatus(BaseCheck):
    id = "EP-AV-001"
    title = "Microsoft Defender real-time protection & signatures"
    category = CAT
    severity = "HIGH"
    reference = "Endpoint protection baseline"
    remediation = "Enable real-time protection, tamper protection, and keep signatures current."
    ps = ("$s=Get-MpComputerStatus -EA SilentlyContinue;"
          "if($s){[pscustomobject]@{RealTime=$s.RealTimeProtectionEnabled;AV=$s.AntivirusEnabled;"
          "Tamper=$s.IsTamperProtected;SigAge=$s.AntivirusSignatureAge;AMService=$s.AMServiceEnabled}"
          " | ConvertTo-Json -Compress}else{'null'}")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self.finding(target, "INFO",
                                 "Get-MpComputerStatus unavailable (Defender may be replaced by 3rd-party AV)",
                                 evidence=str(raw.stdout[:200]))]
        out: List[Finding] = []
        if not data.get("RealTime"):
            out.append(self.finding(target, "FAIL", "Defender real-time protection is OFF",
                                    severity="HIGH", evidence=str(data), title="Real-time protection"))
        else:
            out.append(self.finding(target, "PASS", "Real-time protection on", title="Real-time protection"))
        if not data.get("Tamper"):
            out.append(self.finding(target, "WARN", "Tamper protection is off",
                                    severity="MEDIUM", evidence=str(data), title="Tamper protection"))
        age = data.get("SigAge")
        if isinstance(age, (int, float)) and age > 3:
            out.append(self.finding(target, "WARN", f"AV signatures are {age} days old",
                                    severity="MEDIUM", evidence=str(data), title="Signature age"))
        return out


@register
class ThirdPartyAv(BaseCheck):
    id = "EP-AV-002"
    title = "Registered antivirus products (Security Center)"
    category = CAT
    severity = "MEDIUM"
    reference = "root/SecurityCenter2 AntiVirusProduct"
    remediation = "Confirm an up-to-date AV product is present and enabled."
    ps = ("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA SilentlyContinue"
          " | Select-Object displayName,productState | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "WARN", "No antivirus product registered with Security Center",
                                 severity="HIGH")]
        names = ", ".join(str(r.get("displayName")) for r in rows)
        return [self.finding(target, "INFO", f"Registered AV: {names}", evidence=str(rows))]


@register
class BitLockerStatus(BaseCheck):
    id = "EP-ENC-001"
    title = "BitLocker drive encryption on the OS volume"
    category = CAT
    severity = "HIGH"
    reference = "Data-at-rest protection"
    remediation = "Enable BitLocker on the OS drive (and fixed data drives)."
    ps = ("Get-BitLockerVolume -EA SilentlyContinue | "
          "Select-Object MountPoint,VolumeType,ProtectionStatus,EncryptionPercentage | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self.finding(target, "WARN",
                                 "BitLocker status unavailable (feature absent or insufficient rights)",
                                 severity="MEDIUM", evidence=str(raw.stdout[:200]))]
        out: List[Finding] = []
        for r in rows:
            mount = r.get("MountPoint")
            prot = str(r.get("ProtectionStatus"))
            is_os = str(r.get("VolumeType")).lower() in ("operatingsystem", "0")
            protected = prot.lower() in ("on", "1")
            if is_os and not protected:
                out.append(self.finding(target, "FAIL", f"OS volume {mount} is NOT encrypted (BitLocker off)",
                                        severity="HIGH", evidence=str(r), title="OS volume encryption"))
            elif not protected:
                out.append(self.finding(target, "WARN", f"Volume {mount} not BitLocker-protected",
                                        severity="LOW", evidence=str(r), title="Volume encryption"))
        if not out:
            out.append(self.finding(target, "PASS", "All reported volumes are BitLocker-protected",
                                    evidence=str(rows)))
        return out
