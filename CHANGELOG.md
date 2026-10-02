# Changelog

All notable changes to Layer8 Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Linux support.** The release workflow now builds a Linux executable
  alongside Windows and publishes both; `build.py` is Linux-aware, and the
  README has Linux download/run/build instructions.

### Changed
- **Sign-in is now verified by the Layer8 web console** ([access_client.py](access_client.py)).
  The app no longer connects to a local/MySQL database to authenticate — users
  sign in with the email and access key issued from the web console, and the
  website controls suspend / revoke / expire / seat limits / version floor /
  maintenance at sign-in.
- **Runs out of the box.** Removed the startup MySQL diagnostic splash and the
  "Test Connection" step; the app opens straight to the web-console login.
- Admin Panel now links to the web console (where users are managed) instead of
  editing a database directly.
- Build runs through `build.py`; the release workflow publishes the Windows
  `.exe` to GitHub Releases on version tags (DB secret injection removed).

### Removed
- Local database setup and code: `db_connection.py`, `secure_config.py`, the
  setup wizard, credential/reset utilities, and the MySQL/DB test scripts.
- Unused Django scaffolding and internal setup docs.
- Dependencies no longer needed: `pymysql`, `keyring`, `argon2-cffi`,
  `pycryptodome`.

### Planned
- Additional scanning tools
- Enhanced AI analysis features

---

## [1.5.4] - 2026-10-01

### Changed
- **Custom Cmd now supports URLs with query strings.** The argument metacharacter
  filter blocked `?` and `&`, so commands like `curl "http://host/path?a=1&b=2"`
  were rejected. Those two characters are now allowed on the Custom Cmd path.
  This is safe because the app executes with `shell=False`, where `?`/`&` are
  literal argument characters, not shell operators. Command chaining /
  substitution / redirection characters (`;`, `|`, `` ` ``, `$`, `<`, `>`, `{`, `}`,
  ...) remain blocked, and the shared validator's default behavior is unchanged
  for every other caller ([input_validator.py](input_validator.py),
  [scanner_tools.py](scanner_tools.py)).

---

## [1.5.3] - 2026-10-01

### Added
- **Install hints for missing tools.** When a command isn't found, the message now
  tells you where to get it (e.g. nmap, sqlmap, nikto, hydra, masscan, wireshark,
  metasploit, john, dig, ...) with the download URL and the Linux package command.
  Hints live in `ToolChecker.INSTALL_HINTS` ([tool_checker.py](tool_checker.py));
  unknown commands fall back to a generic "install it / check PATH" message.
  (Third-party tools are intentionally not bundled - most aren't freely
  redistributable and shipping offensive binaries trips antivirus.)

---

## [1.5.2] - 2026-10-01

### Fixed
- **Standard commands (curl, ping, nslookup, …) now work.** The Custom Cmd / Web
  Fetch / NSLookup tools previously rejected these with "not in the allowed list"
  because only 10 third-party security tools were permitted. These utilities ship
  with the OS (Windows System32 / standard on Linux) and did not need bundling —
  they were simply being blocked.
  - [tool_checker.py](tool_checker.py): added a `SYSTEM_TOOLS` set (curl, ping,
    nslookup, tracert, ipconfig, arp, netstat, netsh, whoami, net, dig, wget, ssh,
    …) resolved via PATH; version-probing is skipped for them (no `--version` /
    avoids hangs), keeping startup fast.
  - [scanner_tools.py](scanner_tools.py): Custom Cmd now resolves any installed
    binary via PATH (not just the allowlist), so it truly runs any command-line
    tool. `shell=False` and the argument metacharacter filter are retained. A
    missing command now gives a clear "not found — install it / check PATH" message.

---

## [1.5.1] - 2026-09-29

### Added
- **"Scan own machine" checkbox** on each tool screen. When ticked, the scan runs
  against this machine (`127.0.0.1`) regardless of the target box, which is locked
  to make it unambiguous. Enforced at scan launch ([gui_app.pyw](gui_app.pyw)).
- **Per-tool "Use Case" info panel.** Every tool screen (and the DDoS screen) now
  has an `ℹ USE CASE` button that opens a themed panel explaining the tool's
  purpose, when to use it, how to use it, its capabilities, and its caveats/cautions
  — including an authorization reminder. Content lives in a new [tool_docs.py](tool_docs.py)
  module (33 tools documented) and is bundled into the build.

### Changed
- `build.py`: bundle `tool_docs.py` (and add it as a hidden import) so the Use Case
  panel works in the frozen executable.

---

## [1.5.0] - 2026-09-29

### Added
- **Windows Vulnerability Auditor** (`win_audit/`) — a read-only, authorized
  configuration and vulnerability auditor for Windows hosts. Runs **67 checks
  across 13 categories**, locally or against a remote host over **WinRM**, and
  writes findings to **CSV/JSON**. Every finding carries a severity and a
  **MITRE ATT&CK** technique id.
  - **Baseline profile (6 categories):** misconfigurations, patch status,
    accounts & permissions, network & services, endpoint protection, logging &
    audit policy.
  - **Deep profile (7 more, default):** privilege-escalation vectors (writable
    service binaries/registry keys, PATH/DLL hijack, dangerous token
    privileges), credential access & secrets at rest (autologon/GPP
    cpassword/cmdkey/Wi-Fi/unattend — reported without dumping plaintext),
    coercion/relay/lateral movement (Spooler/WebDAV/WSUS-HTTP/NTLM/SMB & LDAP
    signing), crypto & exploit-mitigation hardening, persistence & compromise
    hunt (IFEO/accessibility backdoors, Winlogon/AppInit, WMI subscriptions),
    detection & EDR posture (Defender exclusions, ASR, Sysmon), and Active
    Directory attack surface (Kerberoast, AS-REP, delegation, MAQ, LAPS) via
    built-in ADSI (no RSAT).
  - CLI: `python -m win_audit` (`--profile baseline|deep`, `--winrm`,
    `--categories`, `--only/--exclude`, `--format csv|json|both`); non-zero exit
    on any FAIL for scheduled runs. Reuses Layer8's `input_validator` and
    `secure_logger`. Docs in `docs/WINDOWS_AUDITOR_*`.

### Changed
- `requirements.txt`: added optional `pywinrm` (remote WinRM auditing only).
- `.gitignore`: ignore generated `reports/` audit output.

---

## [1.0.1] - 2026-01-30

### Added
- Modern dark theme with refined color palette
- Hover effects on buttons and interactive elements
- Improved login window design
- Auto-update functionality via GitHub releases
- Comprehensive updater module
- Background update checker
- Version management system

### Changed
- Updated GUI styling across all components
- Improved typography with Segoe UI font family
- Enhanced visual hierarchy and spacing
- Refined neon green accent color (#00ff88)
- Deeper black backgrounds for better contrast

### Fixed
- GUI launch issues after theme modernization
- Environment variable naming inconsistencies
- Argon2 parameter mismatches between PHP and Python
- Base64 validation errors in password encryption
- ModernTheme import scoping issues

### Security
- Updated encryption key handling
- Improved password hashing alignment with PHP backend
- Enhanced fallback mechanisms for crypto operations

---

## [1.0.0] - 2026-01-25

### Added
- Initial release of Layer8 Security Platform
- MySQL database authentication system
- Argon2id password hashing
- AES-256-GCM and NaCl encryption support
- Network scanning tools
- Vulnerability assessment capabilities
- AI-powered analysis with Claude API
- Admin panel for user management
- Offline diagnostic mode
- Traffic monitoring tools
- WiFi security analysis
- System auditing features

### Features
- **Authentication**
  - Secure login with encrypted password storage
  - Rate limiting and account lockout
  - Session management
  - Admin and user roles

- **Security Tools**
  - Port scanning
  - Network discovery
  - Vulnerability detection
  - Traffic analysis
  - WiFi security assessment

- **UI/UX**
  - Dark theme interface
  - Custom title bar
  - Responsive layout
  - Debug launcher with diagnostics

- **Database**
  - MySQL support with connection pooling
  - SQLite fallback for offline mode
  - Automatic table creation
  - User management

---

## Version History

- **v1.0.1** - Modern UI update, auto-updater, bug fixes
- **v1.0.0** - Initial public release

---

## Release Notes Template

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features
- New capabilities

### Changed
- Updates to existing features
- Improvements

### Deprecated
- Features to be removed in future versions

### Removed
- Removed features

### Fixed
- Bug fixes
- Issue resolutions

### Security
- Security updates
- Vulnerability patches
```

---

[Unreleased]: https://github.com/Wesley-Hatch/layer8-gui/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Wesley-Hatch/layer8-gui/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Wesley-Hatch/layer8-gui/releases/tag/v1.0.0
