"""Category 3 - Accounts & permissions."""

from __future__ import annotations

import re
from typing import Any, List

from ..models import CATEGORY_ACCOUNTS, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_ACCOUNTS


@register
class LocalAdministrators(BaseCheck):
    id = "ACCT-ADM-001"
    title = "Members of the local Administrators group"
    category = CAT
    severity = "MEDIUM"
    reference = "Least privilege"
    remediation = "Remove unnecessary members; keep the Administrators group as small as possible."
    # Query by well-known SID so it works on non-English installs.
    ps = ("Get-LocalGroupMember -SID S-1-5-32-544 | "
          "Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        names = [r.get("Name") for r in rows]
        detail = f"{len(names)} member(s): {', '.join(str(n) for n in names)}"
        status = "WARN" if len(names) > 4 else "INFO"
        sev = "MEDIUM" if len(names) > 4 else "INFO"
        return [self.finding(target, status, detail, severity=sev, evidence=str(rows))]


@register
class LocalUserHygiene(BaseCheck):
    id = "ACCT-USR-001"
    title = "Local account hygiene (guest / blank password / never-expiring)"
    category = CAT
    severity = "HIGH"
    reference = "CIS account policies"
    remediation = ("Disable Guest, require passwords on all enabled accounts, and set password "
                   "expiration on interactive accounts.")
    ps = ("Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,"
          "@{n='PasswordExpires';e={$_.PasswordExpires -ne $null}},SID | ConvertTo-Json")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        rows = as_list(data)
        if not rows:
            return [self._error(target, raw)]
        out: List[Finding] = []

        # Guest account enabled?
        guest = [r for r in rows if str(r.get("SID", "")).endswith("-501")]
        if guest and guest[0].get("Enabled"):
            out.append(self.finding(target, "FAIL", "Guest account is ENABLED",
                                    severity="HIGH", evidence=str(guest[0]), title="Guest account enabled",
                                    remediation="Disable-LocalUser -Name Guest"))
        else:
            out.append(self.finding(target, "PASS", "Guest account disabled", title="Guest account enabled"))

        # Enabled accounts not requiring a password.
        no_pw = [r["Name"] for r in rows if r.get("Enabled") and r.get("PasswordRequired") is False]
        if no_pw:
            out.append(self.finding(target, "FAIL",
                                    f"Enabled account(s) with NO password required: {', '.join(no_pw)}",
                                    severity="CRITICAL", evidence=str(no_pw),
                                    title="Account without password required"))

        # Enabled accounts whose password never expires (built-ins excluded by SID tail).
        never = [r["Name"] for r in rows
                 if r.get("Enabled") and r.get("PasswordExpires") is False
                 and not str(r.get("SID", "")).endswith(("-500", "-501", "-503"))]
        if never:
            out.append(self.finding(target, "WARN",
                                    f"Enabled account(s) with non-expiring password: {', '.join(never)}",
                                    severity="MEDIUM", evidence=str(never),
                                    title="Non-expiring password"))
        return out


@register
class PasswordPolicy(BaseCheck):
    id = "ACCT-POL-001"
    title = "Local password & lockout policy"
    category = CAT
    severity = "HIGH"
    reference = "CIS: password length >= 14, lockout threshold set"
    remediation = "Strengthen via `net accounts` / Local Security Policy / GPO."
    # `net accounts` output is text; capture it raw and parse in Python.
    ps = "[pscustomobject]@{Raw=((net accounts) -join \"`n\")} | ConvertTo-Json -Compress"

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        text = data.get("Raw", "") if isinstance(data, dict) else ""
        if not text:
            return [self._error(target, raw)]
        out: List[Finding] = []

        def _num(label: str):
            m = re.search(label + r"\s*:\s*(\d+)", text)
            return int(m.group(1)) if m else None

        min_len = _num(r"Minimum password length")
        if min_len is not None:
            if min_len < 14:
                out.append(self.finding(target, "FAIL",
                                        f"Minimum password length is {min_len} (recommend >= 14)",
                                        severity="HIGH", title="Minimum password length"))
            else:
                out.append(self.finding(target, "PASS", f"Minimum password length is {min_len}",
                                        title="Minimum password length"))

        lockout = _num(r"Lockout threshold")
        # `net accounts` prints "Never" when disabled -> _num returns None.
        if lockout is None or re.search(r"Lockout threshold\s*:\s*Never", text):
            out.append(self.finding(target, "FAIL",
                                    "Account lockout threshold is not set (Never) - allows password brute force",
                                    severity="MEDIUM", title="Account lockout threshold"))
        elif lockout and lockout > 10:
            out.append(self.finding(target, "WARN", f"Lockout threshold is high ({lockout})",
                                    severity="LOW", title="Account lockout threshold"))
        else:
            out.append(self.finding(target, "PASS", f"Lockout threshold set to {lockout}",
                                    title="Account lockout threshold"))

        out.append(self.finding(target, "INFO", "Raw `net accounts` policy captured",
                                evidence=text[:1200], title="Password policy (raw)"))
        return out


@register
class AlwaysInstallElevated(BaseCheck):
    id = "ACCT-PRIV-001"
    title = "AlwaysInstallElevated privilege escalation setting"
    category = CAT
    severity = "CRITICAL"
    reference = "Windows privilege escalation (MSI as SYSTEM)"
    remediation = "Set AlwaysInstallElevated=0 in both HKLM and HKCU Installer policy keys."
    ps = ("$hklm=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated;"
          "$hkcu=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated;"
          "[pscustomobject]@{HKLM=$hklm;HKCU=$hkcu} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if data.get("HKLM") == 1 and data.get("HKCU") == 1:
            return [self.finding(target, "FAIL",
                                 "AlwaysInstallElevated is enabled in BOTH hives - any user can install MSIs as SYSTEM",
                                 severity="CRITICAL", evidence=str(data))]
        return [self.finding(target, "PASS", "AlwaysInstallElevated not enabled", evidence=str(data))]
