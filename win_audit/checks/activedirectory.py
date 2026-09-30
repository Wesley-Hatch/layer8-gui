"""Category 13 - Active Directory attack surface.

These queries use built-in ADSI ([adsisearcher] / RootDSE) so they work on any
domain-joined host WITHOUT RSAT. On a non-domain host they report N/A. They only
read the directory (which any authenticated user can largely do by default - that
readability is itself part of the attack surface).
"""

from __future__ import annotations

from typing import Any, List

from ..models import CATEGORY_AD, Finding
from ..transport import CommandResult
from .base import BaseCheck, as_list, register


CAT = CATEGORY_AD

# Emitted by scripts when the host is not domain-joined / directory unreachable.
NOT_DOMAIN = "__NOT_DOMAIN__"

# Prefix that safely resolves the domain or bails out with NOT_DOMAIN.
PS_DOMAIN_GUARD = (
    "$cs=Get-CimInstance Win32_ComputerSystem;"
    "if(-not $cs.PartOfDomain){ '{\"NotDomain\":true}' ; return };"
    "try{$root=[ADSI]'LDAP://RootDSE';$dn=$root.defaultNamingContext}"
    "catch{ '{\"NotDomain\":true}' ; return };"
)


class _AdCheck(BaseCheck):
    """Shared handling of the not-domain-joined case."""

    def not_domain(self, target: str) -> List[Finding]:
        return [self.finding(target, "INFO", "Host is not domain-joined (AD check N/A)")]

    def is_not_domain(self, data: Any) -> bool:
        return isinstance(data, dict) and data.get("NotDomain") is True


@register
class DomainRole(_AdCheck):
    id = "AD-DOMAIN-001"
    title = "Domain membership & controller role"
    category = CAT
    severity = "INFO"
    reference = "Environment context"
    attack = ""
    remediation = ""
    ps = ("$cs=Get-CimInstance Win32_ComputerSystem;"
          "[pscustomobject]@{PartOfDomain=$cs.PartOfDomain;Domain=$cs.Domain;Role=$cs.DomainRole} | ConvertTo-Json -Compress")

    ROLE = {0: "Standalone WS", 1: "Member WS", 2: "Standalone Server",
            3: "Member Server", 4: "Backup DC", 5: "Primary DC"}

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if not data.get("PartOfDomain"):
            return [self.finding(target, "INFO", f"Not domain-joined ({self.ROLE.get(data.get('Role'))})",
                                 evidence=str(data))]
        role = self.ROLE.get(data.get("Role"), str(data.get("Role")))
        return [self.finding(target, "INFO", f"Domain-joined to '{data.get('Domain')}' as {role}",
                             evidence=str(data))]


@register
class MachineAccountQuota(_AdCheck):
    id = "AD-MAQ-001"
    title = "ms-DS-MachineAccountQuota allows user-added computers"
    category = CAT
    severity = "MEDIUM"
    reference = "MAQ default 10 -> RBCD / device-based attacks"
    attack = "T1078"
    remediation = "Set ms-DS-MachineAccountQuota to 0; delegate computer joins to a specific group."
    ps = (PS_DOMAIN_GUARD +
          "$d=[ADSI]\"LDAP://$dn\";$q=$d.Properties['ms-DS-MachineAccountQuota'].Value;"
          "[pscustomobject]@{Quota=$q} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        q = data.get("Quota")
        try:
            n = int(q)
        except (TypeError, ValueError):
            return [self.finding(target, "INFO", "MachineAccountQuota not readable", evidence=str(data))]
        if n > 0:
            return [self.finding(target, "FAIL",
                                 f"MachineAccountQuota={n}: any authenticated user can join {n} computer account(s) "
                                 f"(enables RBCD escalation)",
                                 severity="MEDIUM", evidence=str(data))]
        return [self.finding(target, "PASS", "MachineAccountQuota=0", evidence=str(data))]


@register
class KerberoastableAccounts(_AdCheck):
    id = "AD-KERBEROAST-001"
    title = "Kerberoastable service accounts (SPN on user objects)"
    category = CAT
    severity = "HIGH"
    reference = "Kerberoasting"
    attack = "T1558.003"
    remediation = ("Use group Managed Service Accounts (gMSA) or very long (25+ char) random passwords "
                   "for accounts with SPNs; monitor TGS requests.")
    ps = (PS_DOMAIN_GUARD +
          "$s=[adsisearcher]'(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt)))';"
          "$s.PageSize=1000;$s.PropertiesToLoad.Add('samaccountname')|Out-Null;"
          "$s.PropertiesToLoad.Add('serviceprincipalname')|Out-Null;$s.PropertiesToLoad.Add('adminCount')|Out-Null;"
          "$r=$s.FindAll();$out=@();foreach($e in $r){$out+=[pscustomobject]@{"
          "Name=[string]$e.Properties['samaccountname'];AdminCount=[string]$e.Properties['admincount'];"
          "SPNs=[string]($e.Properties['serviceprincipalname'] -join ',')}};"
          "[pscustomobject]@{Accounts=@($out)} | ConvertTo-Json -Depth 4")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        accts = as_list(data.get("Accounts"))
        if not accts:
            return [self.finding(target, "PASS", "No kerberoastable user accounts with SPNs")]
        privileged = [a for a in accts if str(a.get("AdminCount")) == "1"]
        names = ", ".join(str(a.get("Name")) for a in accts[:15])
        if privileged:
            pv = ", ".join(str(a.get("Name")) for a in privileged)
            return [self.finding(target, "FAIL",
                                 f"{len(accts)} kerberoastable account(s), incl. PRIVILEGED (adminCount=1): {pv}",
                                 severity="CRITICAL", evidence=str(accts[:25]),
                                 title="Kerberoastable privileged accounts")]
        return [self.finding(target, "FAIL",
                             f"{len(accts)} kerberoastable service account(s): {names}",
                             severity="HIGH", evidence=str(accts[:25]))]


@register
class AsRepRoastable(_AdCheck):
    id = "AD-ASREP-001"
    title = "AS-REP roastable accounts (no Kerberos pre-auth)"
    category = CAT
    severity = "HIGH"
    reference = "AS-REP roasting (DONT_REQ_PREAUTH)"
    attack = "T1558.004"
    remediation = "Require Kerberos pre-authentication on all accounts (clear DONT_REQ_PREAUTH)."
    ps = (PS_DOMAIN_GUARD +
          "$s=[adsisearcher]'(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))';"
          "$s.PageSize=1000;$s.PropertiesToLoad.Add('samaccountname')|Out-Null;"
          "$r=$s.FindAll();$out=@();foreach($e in $r){$out+=[string]$e.Properties['samaccountname']};"
          "[pscustomobject]@{Accounts=@($out)} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        accts = as_list(data.get("Accounts"))
        if not accts:
            return [self.finding(target, "PASS", "No AS-REP roastable accounts")]
        return [self.finding(target, "FAIL",
                             f"{len(accts)} account(s) without Kerberos pre-auth (AS-REP roastable): "
                             f"{', '.join(str(a) for a in accts[:15])}",
                             severity="HIGH", evidence=str(accts[:25]))]


@register
class DelegationPrincipals(_AdCheck):
    id = "AD-DELEG-001"
    title = "Unconstrained Kerberos delegation principals"
    category = CAT
    severity = "HIGH"
    reference = "Unconstrained delegation -> TGT capture"
    attack = "T1558 / T1550"
    remediation = "Eliminate unconstrained delegation; use constrained/RBCD, and mark admins 'sensitive, cannot be delegated'."
    ps = (PS_DOMAIN_GUARD +
          "$s=[adsisearcher]'(&(|(samAccountType=805306368)(samAccountType=805306369))(userAccountControl:1.2.840.113556.1.4.803:=524288))';"
          "$s.PageSize=1000;$s.PropertiesToLoad.Add('samaccountname')|Out-Null;"
          "$r=$s.FindAll();$out=@();foreach($e in $r){$out+=[string]$e.Properties['samaccountname']};"
          "[pscustomobject]@{Accounts=@($out)} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        accts = as_list(data.get("Accounts"))
        # Exclude DCs (they legitimately have unconstrained delegation) by name heuristic is unreliable;
        # report all and note DCs are expected.
        if not accts:
            return [self.finding(target, "PASS", "No unconstrained-delegation principals found")]
        non_dc = [a for a in accts if not str(a).endswith("$") or True]  # keep all, annotate
        return [self.finding(target, "WARN",
                             f"{len(accts)} principal(s) with unconstrained delegation (DCs expected; "
                             f"any non-DC here is critical): {', '.join(str(a) for a in accts[:15])}",
                             severity="HIGH", evidence=str(accts[:25]))]


@register
class LapsDeployment(_AdCheck):
    id = "AD-LAPS-001"
    title = "LAPS (managed local administrator passwords)"
    category = CAT
    severity = "MEDIUM"
    reference = "LAPS prevents shared local-admin passwords"
    attack = "T1078.003"
    remediation = "Deploy Windows LAPS so every machine has a unique, rotated local admin password."
    ps = (PS_DOMAIN_GUARD +
          "$legacy=0;$modern=0;"
          "try{$s=[adsisearcher]'(ms-Mcs-AdmPwdExpirationTime=*)';$s.PageSize=1;$legacy=@($s.FindAll()).Count}catch{}"
          "try{$s2=[adsisearcher]'(msLAPS-PasswordExpirationTime=*)';$s2.PageSize=1;$modern=@($s2.FindAll()).Count}catch{}"
          "[pscustomobject]@{Legacy=$legacy;Modern=$modern} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if (data.get("Legacy") or 0) > 0 or (data.get("Modern") or 0) > 0:
            return [self.finding(target, "PASS", "LAPS-managed local admin passwords detected",
                                 evidence=str(data))]
        return [self.finding(target, "WARN",
                             "No LAPS-managed passwords found - local admin passwords may be shared/static",
                             severity="MEDIUM", evidence=str(data))]


@register
class DomainPasswordPolicy(_AdCheck):
    id = "AD-PWPOLICY-001"
    title = "Domain password policy"
    category = CAT
    severity = "HIGH"
    reference = "Weak domain password policy enables spraying"
    attack = "T1110.003"
    remediation = "Enforce >= 14-char minimum, a lockout threshold, and reasonable max age via the Default Domain Policy / fine-grained policies."
    ps = (PS_DOMAIN_GUARD +
          "$d=[ADSI]\"LDAP://$dn\";"
          "$minLen=$d.Properties['minPwdLength'].Value;"
          "$lockout=$d.Properties['lockoutThreshold'].Value;"
          "$maxAge=$d.Properties['maxPwdAge'].Value;"
          "[pscustomobject]@{MinLen=$minLen;Lockout=$lockout} | ConvertTo-Json -Compress")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        out: List[Finding] = []
        try:
            min_len = int(data.get("MinLen"))
        except (TypeError, ValueError):
            min_len = None
        try:
            lockout = int(data.get("Lockout"))
        except (TypeError, ValueError):
            lockout = None
        if min_len is not None and min_len < 14:
            out.append(self.finding(target, "FAIL", f"Domain minimum password length is {min_len} (< 14)",
                                    severity="HIGH", evidence=str(data), title="Domain min password length"))
        if lockout == 0:
            out.append(self.finding(target, "FAIL", "Domain has no account lockout threshold (spray-friendly)",
                                    severity="HIGH", evidence=str(data), title="Domain lockout threshold"))
        if not out:
            out.append(self.finding(target, "PASS",
                                    f"Domain policy: min length {min_len}, lockout {lockout}", evidence=str(data)))
        return out


@register
class PrivilegedGroups(_AdCheck):
    id = "AD-PRIVGROUP-001"
    title = "Privileged AD group membership size"
    category = CAT
    severity = "MEDIUM"
    reference = "Excessive Tier-0 membership"
    attack = "T1078.002"
    remediation = "Minimize Domain Admins / Enterprise Admins membership; use tiered admin & PAWs."
    ps = (PS_DOMAIN_GUARD +
          "$out=@();foreach($g in @('Domain Admins','Enterprise Admins','Administrators')){"
          "$s=[adsisearcher]\"(&(objectClass=group)(cn=$g))\";$s.PageSize=1;$e=$s.FindOne();"
          "if($e){$m=@($e.Properties['member']).Count;$out+=[pscustomobject]@{Group=$g;Members=$m}}};"
          "[pscustomobject]@{Groups=@($out)} | ConvertTo-Json -Depth 3")

    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        if self.is_not_domain(data):
            return self.not_domain(target)
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        groups = as_list(data.get("Groups"))
        if not groups:
            return [self.finding(target, "INFO", "Privileged group membership not readable", evidence=str(data))]
        out: List[Finding] = []
        for g in groups:
            n = g.get("Members") or 0
            name = g.get("Group")
            status = "WARN" if (name in ("Domain Admins", "Enterprise Admins") and n > 5) else "INFO"
            sev = "MEDIUM" if status == "WARN" else "INFO"
            out.append(self.finding(target, status, f"{name}: {n} direct member(s)",
                                    severity=sev, evidence=str(g), title=f"{name} membership"))
        return out
