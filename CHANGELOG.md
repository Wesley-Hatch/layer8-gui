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
