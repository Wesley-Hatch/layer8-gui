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

## [1.7.1] - 2026-10-02

### Added
- **Compliance mapping in the AI report.** `generate_report` now includes a
  CJIS / CIS v8 / NIST 800-53 compliance section (findings mapped to controls +
  a per-framework pass/fail rollup), using a self-contained control catalog so it
  works in the frozen app. The offline report points to the `win_audit`
  `.compliance.csv` for a structured mapping.
- **Live AI status line.** The AI Operator shows what the AI is doing at all times
  - "AI is thinking... (Ns)" with a heartbeat, "running tool: …", "tool finished",
  "AI finished - awaiting your input", "stopped by user" - so it never looks frozen.

### Changed
- **Explicit refusals / no silent stops.** The AI is instructed to say so if it
  cannot or will not complete a request. Responses are checked for the `refusal`
  stop reason and empty completions and surfaced as clear messages
  ("[AI DECLINED THIS REQUEST] …", "[AI returned no content …]") with a red status,
  instead of a blank reply ([ai_analyzer.py](ai_analyzer.py), [gui_app.pyw](gui_app.pyw)).

---

## [1.7.0] - 2026-10-02

### Added
- **AI Operator (bring-your-own-key).** The agentic AI assistant is now available
  to all users (not just admins) via the new **AI OPERATOR** button, with the AI
  FEEDBACK assistant unchanged.
  - **Own API key:** enter your Anthropic API key and **Save Key** to persist it
    in your per-user config dir (`%APPDATA%/Layer8`) for future sessions.
  - **Feedback:** the AI reviews the session's real findings and advises.
  - **Runs the real tools:** the AI can drive Layer8's **native tools**
    (`port_scan`, `nikto`, `cve_search`, `win_audit`, `sqlmap`, `hydra`, … via
    `scanner.ai_run_tool`) against the operator-set target, not just CLI commands;
    each run's output is fed back to the AI. Commands require per-use confirmation
    unless Autonomous mode is on; **DDoS is intentionally not AI-runnable**.
  - **Writes a report:** **Save Report** generates a full Markdown pentest report
    (Executive Summary, Findings w/ severity, Attack Path, Remediation) from the
    session's real data and saves it to a file; works offline (rule-based) without
    a key.
  - Current model IDs (`claude-opus-5-5` default, `claude-sonnet-5-5`,
    `claude-haiku-4-5`, `claude-opus-4-8`); removed stale IDs that would fail API
    calls. Updated the AI's platform knowledge (no simulated tools).

---

## [1.6.0] - 2026-10-02

### Added
- **Compliance-mapped reporting (CJIS / CIS v8 / NIST 800-53)** in the Windows
  auditor. Every finding is mapped to the relevant controls and rolled up per
  control (PASS / REVIEW / FAIL), emitted as a console summary, a
  `<prefix>.compliance.csv`, and a `compliance` block in the JSON. On by default;
  disable with `--no-compliance` ([win_audit/compliance.py](win_audit/compliance.py),
  reporting + CLI wiring).

### Fixed / Changed (tool legitimacy)
- **Removed all simulated/fabricated tool output.** Audited every scanner tool.
  - **Nmap/Nessus:** when nmap isn't installed it no longer prints a fake nmap
    banner or fabricated "Sneaky/Loud" findings. It now says nmap is missing
    (with install guidance) and runs the real built-in TCP port + web/FTP scan.
  - Deleted `tool_simulator.py` (the fake-output module) and its build reference.
  - **CVE Search:** the CIRCL external CVE API it used is deprecated (HTTP 404),
    so it depended on a dead external service. Rewritten to real, **fully offline**
    service/version fingerprinting (TCP banners + HTTP Server headers) with no
    external API; it lists product/version strings to check against NVD.
- No tool requires an external/third-party API; every tool does real work against
  the target or via local tools/libraries. (Other tools audited as already real:
  port/ping scan, nikto/dirbrute/wpscan, SQLi/NoSQLi/XSS probes, FTP/Hydra brute,
  subdomains, camera finder, metasploit module suggestions, etc.)

---

## [1.5.7] - 2026-10-02

### Added
- **Custom wordlist support for John the Ripper.** John cracking now prefers a
  user-provided wordlist in `tools/john/wordlists/` (`rockyou.txt` if present,
  else the first `.txt`/`.lst` there) and falls back to John's bundled
  `password.lst` ([scanner_tools.py](scanner_tools.py)). Documented how to add
  rockyou (from Kali or SecLists) in [tools/john/README.md](tools/john/README.md).

---

## [1.5.6] - 2026-10-02

### Added
- **Real John the Ripper integration.** The "John The Ripper" tool previously ran
  a ~30-line Python MD5 matcher with a tiny hardcoded wordlist. It now drives the
  **actual John the Ripper (jumbo)** when present: locates `john` on PATH or under
  a `tools/john` folder next to the app, runs wordlist + rules cracking, parses
  `john --show`, and reports each cracked credential ([scanner_tools.py](scanner_tools.py)).
  - **Format-aware:** type a format in the tool's box for raw hashes (e.g. Raw-MD5,
    raw-sha1, NT) — auto-detect on bare hashes can pick LM and never crack.
  - **Time-budgeted** (scales with intensity) so it can never hang the GUI; the
    Terminate button also works. No longer requires a target.
  - Clear install guidance when John is missing; updated the Use Case panel and the
    install hint. John is **not bundled** (large, GPL, AV-flagged) — download the
    official `winX64_1_JtR.zip` from openwall/john-packages into `tools/john`
    (see [tools/john/README.md](tools/john/README.md)).

### Fixed
- **Help always showed v1.4.2.** `gui_app.pyw` passed a hardcoded `current_version`
  that was never bumped per release. It now reads the version from `version.json`
  (which `build.py` writes from the git tag and ships next to the executable), so
  Help, About and the updater always reflect the actual release and stop
  re-prompting for updates immediately after updating ([gui_app.pyw](gui_app.pyw)).

---

## [1.5.5] - 2026-10-01

### Fixed
- **Crash after auto-update restart** (`ImportError: DLL load failed while importing
  _tkinter`, followed by "Failed to remove temporary directory _MEIxxxx"). The
  restart used `os.execl`, which inherited PyInstaller's onefile bootstrap
  environment (`_MEIPASS2` / `_PYI_*`); the relaunched exe then reused the old
  process's temp-extraction dir instead of extracting its own, and when the old
  process exited and deleted that dir the new process lost its bundled Tcl/Tk DLLs.
  The restart now strips those variables, launches a fresh detached process, and
  hard-exits the old one so its temp dir is cleaned up normally
  ([updater_gui.py](updater_gui.py)).
- **Stale in-app version.** `current_version` was pinned to `1.4.2`, so the app
  always considered itself outdated and re-prompted for updates immediately after
  updating. Bumped to match the release ([gui_app.pyw](gui_app.pyw)).

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
