# Layer8 Windows Vulnerability Auditor — Build Guide

**Component:** `win_audit/` (Python package)
**Status:** working, tested locally on Windows 11
**Audience:** Layer8 developers / IRCSO IT building and maintaining the tool

> **Authorized use only.** This tool is a *read-only* configuration and
> vulnerability auditor. Run it only against systems you own or are explicitly
> authorized to assess (your own agency assets, your lab, or a client that has
> requested and authorized the assessment). It does not exploit, change, or
> disable anything on the target.

---

## 1. Scope & purpose

### What it is
A comprehensive Windows security **audit** tool. It runs a curated list of
built-in Windows/PowerShell queries against a host, interprets the output, and
tells you **what specifically is misconfigured or exposed** — with a severity,
evidence, and a remediation for each finding.

### What it does
- Audits **the local machine** (default) or a **remote host over WinRM**
  (PowerShell Remoting).
- Runs **67 checks across 13 categories**, one category at a time. Two profiles:
  - **`baseline`** — the 6 fast configuration categories:
    1. **Misconfigurations** (firewall, SMBv1, RDP/NLA, UAC, LLMNR, WDigest/LSA, PSv2)
    2. **Patch / update status** (OS build, last update age, pending reboot, WU service)
    3. **Accounts & permissions** (local admins, guest/blank/never-expiring accounts, password & lockout policy, AlwaysInstallElevated)
    4. **Network & services** (listening ports, unquoted service paths, open shares, autoruns)
    5. **Endpoint protection & encryption** (Defender, registered AV, BitLocker)
    6. **Logging & audit policy** (advanced audit policy, PowerShell logging, cmdline auditing)
  - **`deep`** (default) — everything in `baseline` **plus** the adversary-grade categories:
    7. **Privilege escalation** (dangerous token privileges, writable service binaries/registry keys, writable PATH dirs, writable task/autorun binaries)
    8. **Credential access & secrets at rest** (autologon password, cmdkey, saved Wi-Fi keys, GPP cpassword, unattend secrets, PowerShell history, PuTTY/WinSCP/SNMP, cached logons)
    9. **Coercion / relay / lateral movement** (Print Spooler, WebClient/WebDAV, WSUS-over-HTTP, NTLM/LmCompat, SMB client signing, null-session, LDAP signing)
    10. **Crypto & exploit-mitigation hardening** (weak TLS/ciphers, Credential Guard, DEP/ASLR/SEHOP/CFG)
    11. **Persistence & compromise hunt** (IFEO/accessibility backdoors, Winlogon/AppInit, WMI event subscriptions, rogue autostart services)
    12. **Detection & EDR posture** (Defender exclusions, ASR rules, Sysmon, Security-log size)
    13. **Active Directory attack surface** (Kerberoast, AS-REP roast, delegation, MachineAccountQuota, LAPS, domain policy, privileged groups) — via built-in ADSI, no RSAT
- Every finding is tagged with its **MITRE ATT&CK** technique id.
- Writes results to **CSV and/or JSON**.
- Returns a **non-zero exit code when any check FAILs** — so it drops cleanly
  into scheduled/automated runs.

### What it deliberately does NOT do
- No exploitation, password cracking, or "active" attacks.
- No changes to the target (no remediation is applied automatically).
- No third-party binaries required — it uses what ships with Windows.

### Where it fits in Layer8
It reuses the platform's existing building blocks:
- `input_validator.InputValidator` — validates remote targets (IP/host/CIDR).
- `secure_logger.get_logger` — redacting, structured logging.

It is intentionally a **separate, self-contained package** rather than more code
piled into `scanner_tools.py`, so checks are easy to add, read, and test.

---

## 2. Requirements

- **Python 3.11+** (matches the rest of Layer8).
- **Local audits:** no extra packages — just the standard library + PowerShell
  (built into Windows).
- **Remote audits (`--winrm`):** `pip install pywinrm` (already added to
  `requirements.txt`).
- **Privileges:** run **elevated (Administrator)** for full coverage. A few
  checks (e.g. `auditpol`, BitLocker) require admin and will report `ERROR`/`WARN`
  rather than crash when run unprivileged.
- **Remote prerequisites on the target:** WinRM enabled (`Enable-PSRemoting`),
  the auditing account is a local admin on the target, and 5985/5986 reachable.

---

## 3. How it's built in Python (architecture)

```
win_audit/
├── __init__.py            # version
├── __main__.py            # CLI (argparse) — python -m win_audit
├── models.py              # Finding + AuditReport dataclasses, category order
├── transport.py           # LocalTransport / WinRMTransport (run PowerShell -> text)
├── runner.py              # AuditRunner: iterate categories, collect Findings
├── reporting.py           # CSV / JSON writers + console summary
└── checks/
    ├── __init__.py        # registry wiring (imports all check modules)
    ├── base.py            # BaseCheck + @register + JSON helpers
    ├── pssnippets.py      # shared PowerShell (ACL-writability helpers)
    ├── misconfig.py       # Cat 1  Misconfigurations
    ├── patches.py         # Cat 2  Patch status
    ├── accounts.py        # Cat 3  Accounts & permissions
    ├── network.py         # Cat 4  Network & services
    ├── endpoint.py        # Cat 5  Endpoint protection
    ├── logging_audit.py   # Cat 6  Logging & audit policy
    ├── privesc.py         # Cat 7  Privilege escalation
    ├── credaccess.py      # Cat 8  Credential access
    ├── attacksurface.py   # Cat 9  Coercion / relay / lateral
    ├── hardening.py       # Cat 10 Crypto & exploit mitigation
    ├── persistence.py     # Cat 11 Persistence / compromise hunt
    ├── detection.py       # Cat 12 Detection & EDR posture
    └── activedirectory.py # Cat 13 AD attack surface (ADSI)
```

### The core idea: one uniform contract
**Every check is a PowerShell script that prints JSON.** That single decision is
what makes the tool robust and identical for local and remote:

1. A **check** (`BaseCheck` subclass) exposes:
   - metadata: `id`, `title`, `category`, `severity` (used when it FAILs),
     `reference`, `remediation`
   - `ps`: a PowerShell string ending in `ConvertTo-Json`
   - `evaluate(data, raw, target)`: turns the parsed JSON into one or more
     `Finding` objects (`PASS` / `FAIL` / `WARN` / `INFO` / `ERROR`).

2. A **transport** runs that script and returns raw stdout:
   - `LocalTransport` → `subprocess.run(["powershell", "-NoProfile",
     "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ...],
     shell=False)`.
   - `WinRMTransport` → `winrm.Session(...).run_ps(...)`.
   - Both prepend a prelude that silences progress/errors and forces UTF-8 so the
     JSON parses cleanly.

3. The **runner** walks `CATEGORY_ORDER`, runs each check, and sorts findings so
   `FAIL`s (highest severity first) float to the top.

4. **Reporting** serializes to CSV (`utf-8-sig` so Excel opens it correctly) and
   JSON (with run metadata + a summary block).

### Why JSON instead of screen-scraping
`ConvertTo-Json` gives structured, typed output (booleans, nulls, arrays), so
`evaluate()` is real logic (`if data["EnableSMB1"]:`) rather than fragile regex
on human-readable text. For the few commands that only emit text (`net accounts`,
`auditpol`), the script wraps the raw text in a JSON object and we parse it in
Python.

### Security properties baked in
- `shell=False` everywhere; check scripts are **static constants**, not built
  from user input, so there's no command-injection surface.
- Remote targets are validated with `InputValidator.validate_target`.
- Passwords come from a prompt or `WIN_AUDIT_PASSWORD` env var, never logged;
  `secure_logger` redacts sensitive context.
- Read-only: every command is a `Get-*` / query. Nothing is set or removed.

---

## 4. Windows commands the tool drives

These are the actual commands behind the checks (full detail, per check, is in
[`WINDOWS_AUDIT_COMMAND_CHECKLIST.md`](WINDOWS_AUDIT_COMMAND_CHECKLIST.md)).

| Category | Primary commands / cmdlets |
|---|---|
| Misconfigurations | `Get-NetFirewallProfile`, `Get-SmbServerConfiguration`, RDP/UAC/WDigest/LSA/LLMNR registry via `Get-ItemProperty`, `Get-WindowsOptionalFeature` |
| Patch status | `Get-CimInstance Win32_OperatingSystem`, `Get-HotFix`, reboot-pending registry keys, `Get-Service wuauserv` |
| Accounts & permissions | `Get-LocalGroupMember -SID S-1-5-32-544`, `Get-LocalUser`, `net accounts`, Installer policy registry |
| Network & services | `Get-NetTCPListener`, `Get-CimInstance Win32_Service`, `Get-SmbShare` / `Get-SmbShareAccess`, Run-key registry |
| Endpoint | `Get-MpComputerStatus`, `Get-CimInstance root/SecurityCenter2 AntiVirusProduct`, `Get-BitLockerVolume` |
| Logging | `auditpol /get /category:*`, PowerShell logging registry, cmdline-audit registry |
| Privilege escalation | `whoami /priv`, `Get-Acl` on service exes/dirs/registry keys, PATH dirs, `Get-ScheduledTask`, Run-key targets |
| Credential access | Winlogon registry, `cmdkey /list`, `netsh wlan show profile key=clear`, unattend/GPP file scans, PSReadLine history, PuTTY/WinSCP/SNMP registry |
| Coercion / relay | `Get-Service Spooler/WebClient`, Point-and-Print registry, WSUS `WUServer`, `LmCompatibilityLevel`, `Get-SmbClientConfiguration`, RestrictAnonymous, NTDS LDAPServerIntegrity |
| Hardening | SCHANNEL Protocols/Ciphers registry, `Win32_DeviceGuard`, `Get-ProcessMitigation -System` |
| Persistence | IFEO/SilentProcessExit registry, Winlogon Shell/Userinit, AppInit_DLLs, `root\subscription` WMI classes, auto-start service paths |
| Detection | `Get-MpPreference` (exclusions/ASR), `Get-Service Sysmon`, `Get-WinEvent -ListLog Security` |
| Active Directory | `[ADSI]RootDSE`, `[adsisearcher]` (SPNs, UAC bit filters, delegation, MAQ, LAPS attrs, domain policy, privileged groups) |

Legacy equivalents still valid on older hosts (used by the wider Layer8 scanner):
`systeminfo`, `wmic qfe list`, `wmic service get ...`, `net localgroup
administrators`, `netstat -ano`, `netsh advfirewall show allprofiles`.

---

## 5. Running it

```powershell
# From the repo root, in the venv (run PowerShell as Administrator for full coverage)
.venv\Scripts\Activate.ps1

# Local machine, FULL deep audit (all 13 categories), CSV + JSON to reports\<host>-<ts>.*
python -m win_audit

# Fast baseline only (the 6 configuration categories)
python -m win_audit --profile baseline

# List every check without running anything
python -m win_audit --list-checks

# Only the attack-path categories, JSON only, custom output prefix
python -m win_audit --categories privesc,credaccess,attacksurface --format json --out C:\reports\dc01

# Remote host over WinRM (prompts for password)
python -m win_audit --target 10.0.0.15 --winrm --username "AGENCY\svc_audit"

# Remote over HTTPS, skip the interactive authorization prompt (scripted run)
python -m win_audit --target dc01 --winrm --ssl --username "AGENCY\svc_audit" --yes
```

Useful flags: `--only ID1,ID2`, `--exclude ID1`, `--auth kerberos`, `--no-verify`
(skip TLS validation), `--timeout 180`, `--quiet`.

**Exit codes:** `0` clean · `1` aborted/authorization declined · `2` bad args ·
`3` completed with one or more `FAIL` findings.

---

## 6. Adding a new check (the whole recipe)

1. Pick the category module (e.g. `checks/misconfig.py`).
2. Add a class decorated with `@register`:

```python
@register
class MyNewCheck(BaseCheck):
    id = "MISC-XYZ-001"
    title = "Short human title"
    category = CAT                      # the module's category constant
    severity = "HIGH"                   # severity applied when it FAILs
    reference = "CIS / MS docs pointer"
    remediation = "Exact fix command or GPO path."
    ps = "Get-Something | Select-Object A,B | ConvertTo-Json -Compress"

    def evaluate(self, data, raw, target):
        if not isinstance(data, dict):
            return [self._error(target, raw)]
        if data.get("A") == "bad":
            return [self.finding(target, "FAIL", "Explain what was found",
                                 evidence=str(data))]
        return [self.finding(target, "PASS", "Explain what's OK")]
```

Rules of thumb:
- End every `ps` with `ConvertTo-Json` (add `-Depth 4` for nested objects).
- Handle the unprivileged / no-data case → return `self._error(...)`, never throw.
- A check may return **several** findings (see `SmbServerHardening`).
- It auto-registers and appears in `--list-checks`; no other wiring needed.

---

## 7. Testing & verification

- `python -m win_audit --list-checks` — confirms all checks import/register.
- `python -m win_audit --yes --out %TEMP%\audit` — full local run; open the CSV.
- Validate JSON: `python -c "import json;json.load(open(r'...json'))"`.
- Try a single check while iterating: `--only MISC-FW-001`.
- Confirm elevation behavior: run non-admin and check that admin-only checks
  degrade to `ERROR`/`WARN` (they do — e.g. `auditpol` returns 0x522).

---

## 8. Roadmap / possible extensions

Much of the original roadmap (client SMB signing, cached creds, LAPS, ASR,
Defender exclusions, task-binary ACLs, WSUS, SChannel, delegation, MAQ) is now
**implemented** in the deep profile. Remaining ideas:

- **AD CS (ESC1-ESC8)** certificate-template misconfig enumeration on CAs.
- **Firewall rule review** — flag overly broad inbound allow rules (any/any).
- **Vulnerable-driver (BYOVD)** presence check against the MS blocklist.
- **CIS/STIG mapping** per finding for formal compliance reports.
- **HTML report writer** (reuse the JSON) and a Layer8 GUI "Windows Audit" panel.
- **Multi-host sweep** — accept a CIDR/host list, fan out over WinRM with a
  thread pool, one CSV/JSON per host plus a roll-up.
- **Signature/hash verification** of autostart binaries against known-good.

See [`WINDOWS_AUDITOR_GAP_ANALYSIS.md`](WINDOWS_AUDITOR_GAP_ANALYSIS.md) for the
full audit of prior coverage and the rationale behind every deep-profile check.
