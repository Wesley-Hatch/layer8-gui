# Windows Vulnerability Audit — Command Checklist

A go-down-the-list reference of the exact Windows commands used to determine
**what specifically exposes a host to risk**. For each item: the check ID (as
implemented in `win_audit`), the command(s), **what a vulnerable result looks
like**, the severity, and how to fix it.

> **Authorized, read-only use only.** Every command below is a query (`Get-*` /
> read). None of them change the system. Run an elevated PowerShell for full
> coverage. To run one command against a remote host, wrap it:
> `Invoke-Command -ComputerName HOST -ScriptBlock { <command> }`.

**Severity key:** 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · ⚪ Info
**Legend:** *Vulnerable if* = the condition that makes it a finding.

---

## Category 1 — Misconfigurations

### 1.1 Windows Firewall state · `MISC-FW-001` · 🟠 High
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
netsh advfirewall show allprofiles state     # legacy equivalent
```
**Vulnerable if:** any profile (Domain/Private/Public) shows `Enabled = False`.
**Fix:** `Set-NetFirewallProfile -All -Enabled True`.

### 1.2 SMBv1 / signing / encryption · `MISC-SMB-001` · 🟠 High
```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData
```
**Vulnerable if:** `EnableSMB1Protocol = True` (legacy, EternalBlue-class) or
`RequireSecuritySignature = False` (SMB relay / MITM).
**Fix:** `Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true`.

### 1.3 RDP exposure & NLA · `MISC-RDP-001` · 🟠 High
```powershell
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
```
**Vulnerable if:** `fDenyTSConnections = 0` (RDP on) **and** `UserAuthentication = 0`
(no Network Level Authentication).
**Fix:** disable RDP if unused; otherwise set `UserAuthentication = 1` and firewall 3389.

### 1.4 User Account Control · `MISC-UAC-001` · 🟠 High
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, FilterAdministratorToken
```
**Vulnerable if:** `EnableLUA ≠ 1` (UAC off) or `ConsentPromptBehaviorAdmin = 0`
(admins elevate silently).
**Fix:** `EnableLUA = 1`, `ConsentPromptBehaviorAdmin = 2` (or 5); reboot.

### 1.5 LLMNR / NetBIOS name resolution · `MISC-NET-002` · 🟡 Medium
```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast).EnableMulticast
```
**Vulnerable if:** value is missing or ≠ `0` (LLMNR on → Responder poisoning &
NTLM capture).
**Fix:** GPO *Turn off multicast name resolution* = Enabled (`EnableMulticast = 0`);
set NetBIOS over TCP/IP to *Disabled* on adapters.

### 1.6 Credential exposure (WDigest / LSA protection) · `MISC-CRED-001` · 🟠 High
```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential).UseLogonCredential
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL).RunAsPPL
```
**Vulnerable if:** `UseLogonCredential = 1` (cleartext creds in LSASS, Mimikatz)
or `RunAsPPL` not `1`/`2` (LSASS not protected).
**Fix:** `UseLogonCredential = 0`; `RunAsPPL = 1`; reboot.

### 1.7 PowerShell v2 engine · `MISC-PSV2-001` · 🟡 Medium
```powershell
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root | Select-Object State
```
**Vulnerable if:** `State = Enabled` (PSv2 bypasses AMSI & script-block logging).
**Fix:** `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`.

---

## Category 2 — Patch / Update Status

### 2.1 OS version & support · `PATCH-OS-001` · ⚪ Info→🟡
```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, InstallDate
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"    # legacy equivalent
```
**Vulnerable if:** build is past end-of-support (e.g. old Win10 feature update).
**Fix:** upgrade to a supported build/feature update.

### 2.2 Last update installed · `PATCH-HF-001` · 🟠 High
```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn, Description
wmic qfe list brief /format:table     # legacy equivalent
```
**Vulnerable if:** newest update > 45 days old (🟡) or > 90 days (🟠) — patching
has stalled.
**Fix:** run Windows Update; investigate WU/WSUS failures.

### 2.3 Pending reboot · `PATCH-RB-001` · 🟡 Medium
```powershell
Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations).PendingFileRenameOperations
```
**Vulnerable if:** any path exists / value present — updates aren't fully applied.
**Fix:** schedule a reboot.

### 2.4 Windows Update service · `PATCH-SVC-001` · 🟡 Medium
```powershell
Get-Service wuauserv | Select-Object Name, Status, StartType
```
**Vulnerable if:** `StartType = Disabled` (host can't receive updates).
**Fix:** `Set-Service wuauserv -StartupType Manual`.

---

## Category 3 — Accounts & Permissions

### 3.1 Local Administrators members · `ACCT-ADM-001` · 🟡 Medium
```powershell
Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name, ObjectClass, PrincipalSource
net localgroup administrators     # legacy equivalent
```
**Vulnerable if:** unexpected users, or a large membership (>4) — excessive
privilege / lateral-movement surface.
**Fix:** remove unneeded members; keep the group minimal.

### 3.2 Account hygiene (guest / blank / never-expiring) · `ACCT-USR-001` · 🔴/🟠
```powershell
Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordExpires, SID
```
**Vulnerable if:** Guest (`SID …-501`) `Enabled = True` (🟠); any enabled account
with `PasswordRequired = False` (🔴 — blank-password logon); enabled accounts
with non-expiring passwords (🟡).
**Fix:** `Disable-LocalUser Guest`; require passwords; set expiration.

### 3.3 Password & lockout policy · `ACCT-POL-001` · 🟠 High
```powershell
net accounts
secedit /export /cfg C:\temp\secpol.cfg   # deeper: exports full policy
```
**Vulnerable if:** `Minimum password length < 14`; `Lockout threshold : Never`
(unlimited password guessing).
**Fix:** raise minimum length ≥ 14; set a lockout threshold (e.g. 5–10) via GPO /
Local Security Policy.

### 3.4 AlwaysInstallElevated · `ACCT-PRIV-001` · 🔴 Critical
```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated
(Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated
```
**Vulnerable if:** **both** hives = `1` — any user can install an MSI as SYSTEM
(instant privilege escalation).
**Fix:** set both to `0` (or remove the policy).

---

## Category 4 — Network & Services

### 4.1 Listening TCP ports · `NET-PORT-001` · 🟡/🟠/🔴 (per port)
```powershell
Get-NetTCPListener -State Listen |
  ForEach-Object { $p = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
    [pscustomobject]@{ Addr=$_.LocalAddress; Port=$_.LocalPort; PID=$_.OwningProcess; Proc=$p.ProcessName } }
netstat -ano | findstr LISTENING     # legacy equivalent
```
**Vulnerable if:** risky services listening on `0.0.0.0`/`::` — Telnet 23 (🔴),
FTP 21 (🟠), RDP 3389 (🟠), VNC 5900 (🟠), SMB 445 / RPC 135 / NetBIOS 139 /
MSSQL 1433 / MySQL 3306 / WinRM-HTTP 5985 (🟡).
**Fix:** stop or firewall the service; bind to loopback where possible.

### 4.2 Unquoted service paths · `NET-SVC-001` · 🟠 High
```powershell
Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode, StartName |
  Where-Object { $_.PathName -notlike '"*' -and $_.PathName -like '* *' }
wmic service get name,pathname,startmode     # legacy equivalent
```
**Vulnerable if:** a service `PathName` contains a space, isn't quoted, and lives
outside `C:\Windows\` — a writable parent folder lets an attacker plant an EXE
that runs with the service's privileges.
**Fix:** `sc.exe config <svc> binPath= "\"C:\Path With Spaces\svc.exe\""`.

### 4.3 SMB shares & permissions · `NET-SHARE-001` · 🟠 High
```powershell
Get-SmbShare | Select-Object Name, Path, Description
Get-SmbShareAccess -Name <ShareName> | Select-Object AccountName, AccessControlType, AccessRight
net share     # legacy equivalent
```
**Vulnerable if:** a non-default share grants `Everyone` / `Authenticated Users`
`Full`/`Change` — broad data exposure or write access.
**Fix:** remove broad ACEs; scope to specific groups; least privilege.

### 4.4 Autorun persistence · `NET-RUN-001` · 🟡 Medium (review)
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
```
**Vulnerable if:** unrecognized programs, or entries pointing at writable/temp
paths — common malware persistence.
**Fix:** remove unknown entries; verify each program's legitimacy.

---

## Category 5 — Endpoint Protection & Encryption (extra)

### 5.1 Microsoft Defender status · `EP-AV-001` · 🟠 High
```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, IsTamperProtected, AntivirusSignatureAge, AMServiceEnabled
```
**Vulnerable if:** `RealTimeProtectionEnabled = False`, tamper protection off, or
signatures > 3 days old.
**Fix:** enable real-time + tamper protection; update signatures
(`Update-MpSignature`). (Skip if a 3rd-party AV replaces Defender — see 5.2.)

### 5.2 Registered AV products · `EP-AV-002` · 🟡 Medium
```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState
```
**Vulnerable if:** no AV registered, or the product is disabled/out of date.
**Fix:** ensure an enabled, current AV is present.

### 5.3 BitLocker on OS volume · `EP-ENC-001` · 🟠 High
```powershell
Get-BitLockerVolume | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage
manage-bde -status     # legacy equivalent
```
**Vulnerable if:** OS volume `ProtectionStatus = Off` — data readable if the disk
is stolen. *(Requires admin to read; unprivileged → WARN.)*
**Fix:** `Enable-BitLocker` on the OS drive (and fixed data drives).

---

## Category 6 — Logging & Audit Policy (extra)

### 6.1 Advanced audit policy · `LOG-POL-001` · 🟡 Medium *(admin required)*
```powershell
auditpol /get /category:*
```
**Vulnerable if:** key subcategories (Logon, Logoff, Special Logon, Credential
Validation, Audit Policy Change, Sensitive Privilege Use, Process Creation) show
`No Auditing` — attacks won't be logged.
**Fix:** enable Success/Failure for those subcategories via GPO or `auditpol /set`.

### 6.2 PowerShell logging · `LOG-PS-001` · 🟡 Medium
```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging).EnableScriptBlockLogging
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging).EnableModuleLogging
```
**Vulnerable if:** `EnableScriptBlockLogging ≠ 1` — malicious PowerShell isn't
recorded.
**Fix:** enable Script Block Logging (and Module Logging) via GPO.

### 6.3 Command-line process auditing · `LOG-CMD-001` · 🔵 Low
```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled).ProcessCreationIncludeCmdLine_Enabled
```
**Vulnerable if:** value ≠ `1` — 4688 events omit command lines (weaker forensics).
**Fix:** enable *Include command line in process creation events* + Audit Process
Creation.

---

# Deep profile — adversary attack-path commands

The categories below are what a skilled intruder actually uses. They are in the
`deep` profile (default). ATT&CK ids in brackets.

## Category 7 — Privilege Escalation Vectors

### 7.1 Dangerous token privileges · `PRIV-TOKEN-001` · 🟠/🔴 [T1134/T1068]
```powershell
whoami /priv
```
**Vulnerable if:** a **non-admin/service** context holds `SeImpersonatePrivilege`,
`SeAssignPrimaryTokenPrivilege` (Potato → SYSTEM), `SeDebugPrivilege` (dump LSASS),
`SeBackupPrivilege` (read SAM), `SeRestore`/`SeTakeOwnership`/`SeLoadDriver`.
**Fix:** remove the privilege from that principal.

### 7.2 Writable service binaries / dirs · `PRIV-SVCBIN-001` · 🔴 [T1543.003]
```powershell
# For each service, resolve the exe and test its ACL + its folder's ACL
Get-CimInstance Win32_Service | Select Name,PathName,StartName
Get-Acl "<service exe>" | Format-List   # look for Users/Everyone/Authenticated Users = Write/Modify/FullControl
```
**Vulnerable if:** a low-privileged principal can write the service exe or its
directory (esp. a SYSTEM service) → replace the binary → SYSTEM.
**Fix:** re-ACL the binary/folder to admins/SYSTEM only.

### 7.3 Writable service registry keys · `PRIV-SVCREG-001` · 🔴 [T1574.011]
```powershell
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\<svc>" | Format-List
```
**Vulnerable if:** a non-admin has `SetValue`/`WriteKey`/`FullControl` → change
`ImagePath` → SYSTEM. **Fix:** restrict the key's ACL.

### 7.4 Writable PATH directories · `PRIV-PATH-001` · 🟠 [T1574.007]
```powershell
[Environment]::GetEnvironmentVariable('Path','Machine') -split ';'
Get-Acl "<each dir>"    # user-writable + in PATH = DLL/binary planting
```
**Fix:** remove user-writable dirs from the machine PATH or lock their ACLs.

### 7.5 Writable scheduled-task / autorun binaries · `PRIV-TASK-001` / `PRIV-RUN-001` · 🟠/🔴 [T1053.005/T1547.001]
```powershell
Get-ScheduledTask | ForEach-Object { $_.Principal.UserId; $_.Actions.Execute }
Get-Acl "<task or Run-key target exe>"
```
**Vulnerable if:** the target binary (running as SYSTEM/another user) is writable.

## Category 8 — Credential Access & Secrets at Rest

### 8.1 Cleartext autologon password · `CRED-AUTOLOGON-001` · 🔴 [T1552.002]
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
  Select AutoAdminLogon, DefaultUserName, DefaultPassword
```
**Vulnerable if:** `DefaultPassword`/`AltDefaultPassword` present → cleartext creds.

### 8.2 GPP cpassword · `CRED-GPP-001` · 🔴 [T1552.006]
```powershell
Select-String -Path (Get-ChildItem 'C:\ProgramData\Microsoft\Group Policy\History' -Recurse -Include *.xml).FullName -Pattern cpassword
findstr /S /I cpassword \\<domain>\SYSVOL\<domain>\Policies\*.xml    # domain-wide
```
**Vulnerable if:** any `cpassword` found — the AES key is public, trivially decrypted.

### 8.3 Stored credentials & app secrets · `CRED-CMDKEY-001` / `CRED-APP-001` · 🟡/🟠 [T1555]
```powershell
cmdkey /list
# PuTTY proxy pw / WinSCP saved pw / SNMP community strings:
Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
Get-ChildItem 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
```

### 8.4 Answer files / PS history / Wi-Fi keys · `CRED-UNATTEND/PSHIST/WIFI` · 🟠/🟡 [T1552.001]
```powershell
Get-Content C:\Windows\Panther\Unattend.xml           # <Password> fields
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
netsh wlan show profile name="<SSID>" key=clear        # Key Content = cleartext PSK
```

### 8.5 Cached domain logons · `CRED-CACHED-001` · 🔵 [T1003.005]
```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount).CachedLogonsCount
```
**Vulnerable if:** high count → more domain creds recoverable offline.

## Category 9 — Coercion / Relay / Lateral Movement

### 9.1 Print Spooler & Point-and-Print · `AS-SPOOLER-001` · 🟠/🔴 [T1068/T1187]
```powershell
Get-Service Spooler
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
```
**Vulnerable if:** Spooler running (MS-RPRN/PetitPotam coercion; HIGH on a DC) or
`NoWarningNoElevationOnInstall=1` (PrintNightmare). **Fix:** disable Spooler off
print servers; harden Point-and-Print.

### 9.2 WebDAV / WSUS-over-HTTP · `AS-WEBCLIENT-001` / `AS-WSUS-001` · 🟡/🟠 [T1187/T1195.002]
```powershell
Get-Service WebClient
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer
```
**Vulnerable if:** WebClient running (HTTP→NTLM relay) or `WUServer` is `http://`
(update MITM → SYSTEM).

### 9.3 NTLM / SMB / anonymous / LDAP signing · `AS-NTLM/SMBSIGN/NULLSESS/LDAP` · 🟠 [T1557.001]
```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel).LmCompatibilityLevel
Get-SmbClientConfiguration | Select RequireSecuritySignature, EnableSMB1Protocol
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select RestrictAnonymousSAM, EveryoneIncludesAnonymous
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity).LDAPServerIntegrity  # DC
```
**Vulnerable if:** `LmCompatibilityLevel<5` (NTLMv1/LM), client signing not
required, anonymous SAM enumeration allowed, or a DC not requiring LDAP signing.

## Category 10 — Crypto & Exploit-Mitigation Hardening

### 10.1 Weak TLS / ciphers · `HARD-SCHANNEL-001` / `HARD-CIPHER-001` · 🟡/🟠 [T1040]
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
```
**Vulnerable if:** SSL2/3 or TLS1.0/1.1 not disabled, or RC4/DES/NULL enabled.

### 10.2 Credential Guard / exploit mitigations · `HARD-CG-001` / `HARD-MITIG-001` · 🟡 [T1003.001/T1211]
```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | Select SecurityServicesRunning
Get-ProcessMitigation -System | Select-Object -Property *   # DEP/ASLR/SEHOP/CFG
```
**Vulnerable if:** Credential Guard not running (LSASS dumpable) or core
mitigations OFF.

## Category 11 — Persistence & Compromise Hunt

### 11.1 IFEO / accessibility backdoors · `PERSIST-IFEO-001` · 🟠/🔴 [T1546.008]
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  ForEach-Object { (Get-ItemProperty $_.PSPath).Debugger }
```
**Vulnerable if:** any `Debugger` set — CRITICAL for `sethc.exe`/`utilman.exe`
(logon-screen SYSTEM shell).

### 11.2 Winlogon / AppInit / WMI / rogue services · `PERSIST-WINLOGON/APPINIT/WMI/SVC` · 🟠 [T1547/T1546]
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select Shell, Userinit
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select AppInit_DLLs, LoadAppInit_DLLs
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer   # CommandLine/ActiveScript = bad
Get-CimInstance Win32_Service | Where StartMode -eq Auto | Select Name, PathName  # exe under Users/Temp/AppData = suspicious
```
**Vulnerable if:** Shell≠explorer.exe, Userinit altered, AppInit_DLLs set,
code-executing WMI consumers present, or auto-start services in user-writable paths.

## Category 12 — Detection & EDR Posture

### 12.1 Defender exclusions / ASR / Sysmon / log size · `DET-EXCL/ASR/SYSMON/EVTSIZE` · 🟡/🔵 [T1562]
```powershell
Get-MpPreference | Select ExclusionPath, ExclusionProcess, ExclusionExtension
Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
Get-Service Sysmon,Sysmon64 -EA SilentlyContinue
(Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1MB
```
**Vulnerable if:** unexpected/broad AV exclusions (attackers hide here), no ASR in
Block mode, no Sysmon, or a tiny Security log (activity rolls off).

## Category 13 — Active Directory Attack Surface (built-in ADSI, no RSAT)

### 13.1 Kerberoast / AS-REP / delegation · `AD-KERBEROAST/ASREP/DELEG` · 🟠/🔴 [T1558]
```powershell
([adsisearcher]'(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt)))').FindAll()   # Kerberoastable
([adsisearcher]'(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))').FindAll() # AS-REP roastable
([adsisearcher]'(userAccountControl:1.2.840.113556.1.4.803:=524288)').FindAll()                               # Unconstrained delegation
```
**Vulnerable if:** SPN-bearing user accounts (CRITICAL if adminCount=1), accounts
without pre-auth, or non-DC principals with unconstrained delegation.

### 13.2 MachineAccountQuota / LAPS / policy / groups · `AD-MAQ/LAPS/PWPOLICY/PRIVGROUP` · 🟡/🟠 [T1078]
```powershell
([ADSI]"LDAP://$(([ADSI]'LDAP://RootDSE').defaultNamingContext)").'ms-DS-MachineAccountQuota'
([adsisearcher]'(ms-Mcs-AdmPwdExpirationTime=*)').FindAll().Count      # LAPS deployed?
# domain minPwdLength / lockoutThreshold from the domain object; Domain Admins .member count
```
**Vulnerable if:** MAQ>0 (users add computers → RBCD), no LAPS (shared local admin
pw), weak domain policy, or oversized Domain/Enterprise Admins.

---

## Running the whole list at once

The `win_audit` tool runs **every command above, in this order**, interprets the
output, and writes the findings to CSV/JSON:

```powershell
python -m win_audit                                   # local host
python -m win_audit --target HOST --winrm --username "AGENCY\svc_audit"   # remote
python -m win_audit --list-checks                     # see the mapping above
```

Findings are sorted with `FAIL`s (highest severity first) at the top of the
report. See [`WINDOWS_AUDITOR_BUILD_GUIDE.md`](WINDOWS_AUDITOR_BUILD_GUIDE.md) for
the build/architecture details and how to add new checks.
