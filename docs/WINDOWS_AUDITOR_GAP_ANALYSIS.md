# Windows Auditor — Tool Audit & Adversary-Grade Gap Analysis

**Question asked:** *audit all the tools and see what improvements can be made to
make them a more invasive search — find exploitable weaknesses before a skilled
attacker does.*

This document is the audit. It records (1) what the existing tooling covered,
(2) the gaps a competent intruder would have walked straight through, and (3) the
deep-profile checks now implemented to close them. Every added check is
read-only detection mapped to a **MITRE ATT&CK** technique.

> Scope: authorized defensive auditing of your own agency assets, lab, and
> clients who have requested it. Nothing here exploits a target — it finds the
> door before someone else opens it.

---

## 1. What existed before (audit of prior coverage)

| Tool / method | What it did | Verdict |
|---|---|---|
| `scanner_tools.py :: win_audit()` | Dumps `systeminfo`, `net localgroup administrators`, `netstat -an`, `wmic qfe`, `set`. Logs raw text; no evaluation, no severity. | **Baseline only.** Amateur tier — lists data, decides nothing. |
| `scanner_tools.py :: firewall_audit()` | Firewall state. | Narrow. |
| `scanner_tools.py :: linpeas/auditd` | Linux privesc/audit. | Not Windows. |
| `win_audit/` (v1, prior turn) | 25 evaluated checks, 6 categories, CSV/JSON. | Good baseline; still **config-level**, not attack-path level. |

**Coverage search result:** a keyword sweep of the whole codebase for the
techniques a real attacker uses — `autologon`, `cpassword`, `kerberoast`,
`spooler`, `wsus`, `lmcompat`, `restrictanonymous`, `schannel`, `credential
guard`, `seimpersonate`, `defender exclusion`, `delegation`, `laps`,
`machineaccountquota`, `appinit`, `ifeo`, `sethc`, `sysmon` — returned **zero
hits**. None of the exploitation paths below were detected anywhere.

**The core gap:** the old tooling answered *"is this box configured to a
checklist?"* It did **not** answer *"how does someone go from a foothold to
Domain Admin here, and are they already inside?"* That second question is the one
that matters for a Sheriff's office.

---

## 2. The attacker's playbook vs. what we now detect

A skilled intruder against a Windows environment runs a predictable kill chain.
Here is that chain, and the deep-profile category that now catches each stage
*before* they do.

| Attacker stage | What they actually do | New category / checks |
|---|---|---|
| **Local escalation** | Hijack a writable SYSTEM service binary/registry key, plant a DLL in a writable PATH dir, abuse `SeImpersonate` (Potato), `AlwaysInstallElevated` | **Cat 7 Privilege Escalation** (`PRIV-*`) |
| **Credential harvest** | Read autologon password, `cmdkey` blobs, GPP `cpassword`, unattend files, Wi-Fi keys, PowerShell history, cached domain creds | **Cat 8 Credential Access** (`CRED-*`) |
| **Coercion & relay** | Coerce auth via Print Spooler/WebDAV, relay NTLM (no SMB/LDAP signing), downgrade to NTLMv1, MITM WSUS-over-HTTP | **Cat 9 Coercion/Relay** (`AS-*`) |
| **Defeat protections** | Strip TLS to weak ciphers, dump LSASS (no Credential Guard), exploit missing DEP/ASLR/CFG | **Cat 10 Hardening** (`HARD-*`) |
| **Domain takeover** | Kerberoast SPNs, AS-REP roast, abuse unconstrained delegation, add machine accounts (MAQ) for RBCD, spray a weak domain policy | **Cat 13 Active Directory** (`AD-*`) |
| **Persist & hide** | IFEO/sethc backdoor, Winlogon/AppInit, WMI event subs, rogue autostart, add Defender exclusions, shrink logs | **Cat 11 Persistence** + **Cat 12 Detection** |

---

## 3. Highlights — the "wasn't even thinking about that" checks

These are the ones that catch real, chained compromise — not checklist items.

### Privilege escalation you can actually walk (Cat 7)
- **`PRIV-SVCBIN-001` / `PRIV-SVCREG-001`** — enumerates every service and uses
  `Get-Acl` to find binaries, directories, *and registry keys* that a
  low-privileged user can **write**. A writable SYSTEM-service binary = instant
  SYSTEM. This is the single most common real-world Windows local privesc, and
  nothing checked it before.
- **`PRIV-PATH-001`** — user-writable directory in the machine `PATH` → DLL /
  binary planting into anything that resolves by name.
- **`PRIV-TOKEN-001`** — parses `whoami /priv`; flags `SeImpersonate` /
  `SeAssignPrimaryToken` / `SeDebug` / `SeBackup` held by a **non-admin** context
  (Potato-family → SYSTEM; SeBackup → read the SAM).
- **`PRIV-TASK-001` / `PRIV-RUN-001`** — writable scheduled-task and autorun
  target binaries that run as SYSTEM/another user.

### Secrets sitting on disk (Cat 8) — reported *without* dumping the value
- **`CRED-AUTOLOGON-001`** — cleartext autologon password in the registry (CRITICAL).
- **`CRED-GPP-001`** — cached Group Policy Preferences `cpassword`; the AES key is
  public, so this is a trivially decrypted domain credential (CRITICAL).
- **`CRED-CMDKEY-001` / `CRED-APP-001`** — Credential Manager entries and
  reversible PuTTY/WinSCP/SNMP secrets. *(This already surfaced 53 stored
  credentials on the test host.)*
- **`CRED-UNATTEND-001` / `CRED-PSHIST-001` / `CRED-WIFI-001`** — deployment
  answer-file passwords, secrets left in PowerShell history, recoverable Wi-Fi PSKs.
- **Design choice:** these report the *presence and location* of each secret,
  never the plaintext — the audit artifact must not itself become a credential dump.

### Coercion / relay — how one box becomes the whole domain (Cat 9)
- **`AS-SPOOLER-001`** — Print Spooler running (PrintNightmare RCE + MS-RPRN /
  PetitPotam coercion), escalated to **HIGH on Domain Controllers**, plus the
  Point-and-Print non-admin-driver-install privesc.
- **`AS-WEBCLIENT-001` / `AS-WSUS-001`** — WebDAV enabling HTTP→NTLM relay; WSUS
  over cleartext HTTP that can be MITM'd to run code as SYSTEM.
- **`AS-NTLM-001` / `AS-SMBSIGN-001` / `AS-NULLSESS-001` / `AS-LDAP-001`** —
  NTLMv1/LM allowed, SMB client signing not required, anonymous SAM enumeration,
  and (on DCs) LDAP signing not enforced — the exact conditions that make NTLM
  relay work.

### Are they already in? (Cat 11)
- **`PERSIST-IFEO-001`** — IFEO debugger hijacks, with **accessibility backdoors**
  (`sethc.exe` / `utilman.exe` at the logon screen) flagged CRITICAL.
- **`PERSIST-WMI-001`** — code-executing WMI event-subscription persistence, the
  classic fileless foothold most scanners miss.
- **`PERSIST-WINLOGON-001` / `PERSIST-APPINIT-001` / `PERSIST-SVC-001`** —
  Winlogon/Userinit tampering, AppInit_DLL injection, and auto-start services
  running from user-writable locations.

### Active Directory takeover paths (Cat 13) — no RSAT required
Uses built-in `[adsisearcher]`/`RootDSE`, so it runs on any domain member with
just the audit account (much of this is readable by *any* authenticated user —
which is itself the point):
- **`AD-KERBEROAST-001`** — SPN-bearing user accounts, with **privileged
  (adminCount=1) kerberoastable accounts flagged CRITICAL**.
- **`AD-ASREP-001`** — accounts without Kerberos pre-auth (offline-crackable).
- **`AD-DELEG-001`** — unconstrained-delegation principals (TGT capture → DA).
- **`AD-MAQ-001`** — `MachineAccountQuota > 0` lets any user add computers → RBCD.
- **`AD-LAPS-001` / `AD-PWPOLICY-001` / `AD-PRIVGROUP-001`** — no LAPS (shared
  local admin passwords), weak domain password policy, bloated Tier-0 groups.

---

## 4. Coverage: before vs. after

| | Before | After |
|---|---|---|
| Evaluated checks | 25 | **67** |
| Categories | 6 (config only) | **13** (config + full attack chain) |
| Local privilege-escalation detection | none | 6 checks (ACL-based) |
| Credential-at-rest detection | none | 8 checks (redacted) |
| Coercion / relay detection | none | 7 checks |
| Persistence / compromise hunt | none | 5 checks |
| Active Directory attack surface | none | 8 checks (ADSI) |
| MITRE ATT&CK tagging | none | every actionable finding |

Full deep run on the test workstation: **67 checks in ~50 s**, no crashes, false
positives eliminated (e.g. signed Defender/NVIDIA services no longer flagged).

---

## 5. Honest limitations (so results are trusted)

- **Elevation matters.** Run as Administrator. Unprivileged runs degrade
  gracefully — admin-only checks (`auditpol`, Defender exclusions, Security-log
  size, BitLocker) report `ERROR`/`INFO` ("run elevated"), never a false finding.
- **AD checks need a domain member + a readable directory.** On a workstation
  they correctly report N/A.
- **ACL checks reflect the audit account's view** of principals — best run with a
  standard account's or the machine's own perspective for "who can write."
- **Not exploitation.** This finds the primitives; it does not fire them. It also
  will not replace a full pentest, a driver-blocklist (BYOVD) check, or AD CS
  (ESC) template analysis — those are on the roadmap.

---

## 6. What to fix first (based on the test-host run)

Prioritize by how directly it hands over control:

1. **Any `CRITICAL`** — writable SYSTEM service binary/key, autologon/GPP
   cleartext password, accessibility backdoor, privileged kerberoastable account.
2. **Coercion/relay `HIGH`** on servers/DCs — Spooler on a DC, NTLMv1, missing
   SMB/LDAP signing, WSUS-over-HTTP.
3. **Credential hygiene** — clear stored creds, deploy LAPS, enable Credential Guard.
4. **Detection** — remove unexpected Defender exclusions, deploy ASR in Block
   mode + Sysmon, grow the Security log and forward to a SIEM.

Run it, sort the CSV by `severity`, and work top-down. See
[`WINDOWS_AUDIT_COMMAND_CHECKLIST.md`](WINDOWS_AUDIT_COMMAND_CHECKLIST.md) for the
per-command detail and [`WINDOWS_AUDITOR_BUILD_GUIDE.md`](WINDOWS_AUDITOR_BUILD_GUIDE.md)
for architecture and how to add the next check.
