# Layer8 Security Platform

<div align="center">

![Layer8 Logo](Layer8/Media/Layer8-logo.png)

**Enterprise-Grade Security Analysis & Network Monitoring**

[![Release](https://img.shields.io/github/v/release/Wesley-Hatch/layer8-gui)](https://github.com/Wesley-Hatch/layer8-gui/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

[Download](https://github.com/YOUR_USERNAME/layer8-gui/releases/latest) • [Documentation](RELEASE.md) • [Changelog](CHANGELOG.md)

</div>

---

## 🎯 Overview

Layer8 is a comprehensive security platform that provides network analysis, vulnerability assessment, and AI-powered security insights. Built with a modern dark theme interface, it combines powerful security tools with an intuitive user experience.

### ✨ Key Features

- 🔐 **Secure Authentication** - Argon2id password hashing with AES-256-GCM encryption
- 🌐 **Network Scanning** - Port scanning, service detection, and network discovery
- 🛡️ **Vulnerability Assessment** - Identify and analyze security weaknesses
- 🤖 **AI Analysis** - Claude-powered intelligent security analysis
- 📊 **Traffic Monitoring** - Real-time network traffic analysis with TLS SNI detection
- 📡 **WiFi Security** - Wireless network assessment and penetration testing
- 🎨 **Modern UI** - Sleek dark theme with smooth animations
- 🔄 **Auto-Updates** - Automatic update checking and installation

---

## 📸 Screenshots

<div align="center">

### Login Screen
![Login](docs/screenshots/login.png)

### Main Dashboard
![Dashboard](docs/screenshots/dashboard.png)

### Network Scanner
![Scanner](docs/screenshots/scanner.png)

</div>

---

## 🚀 Quick Start

### Download Pre-Built Executable

1. Go to [Releases](https://github.com/YOUR_USERNAME/layer8-gui/releases/latest)
2. Download the ZIP for your platform:
   - **Windows**: `layer8-gui-windows.zip`
   - **Linux**: `layer8-gui-linux.zip`
   - **macOS**: `layer8-gui-macos.zip`
3. Extract and run `Layer8-GUI`

### Run from Source

**Prerequisites (all platforms)**

- **Python 3.11 or 3.12** — recommended. Newer releases (3.13+) may not yet ship
  wheels for every dependency. Check with `python --version` (or `python3 --version`).
- **git**
- **For the live packet-capture tools** (Sniffer, Traffic Monitor, Packet Interceptor,
  WiFi Analyzer) you also need a capture driver, and the app must run elevated:
  - **Windows:** install [Npcap](https://npcap.com/#download) with *"Install Npcap in
    WinPcap API-compatible Mode"* checked, then launch the app **as Administrator**.
  - **Linux:** `sudo apt install libpcap-dev tcpdump` (Debian/Ubuntu) and run with `sudo`.
  - **macOS:** libpcap is built in; run the capture tools with `sudo`.

**Windows (PowerShell)**

```powershell
git clone https://github.com/Wesley-Hatch/layer8-gui.git
cd layer8-gui
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python gui_app.pyw
```

**Linux / macOS**

```bash
git clone https://github.com/Wesley-Hatch/layer8-gui.git
cd layer8-gui
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 gui_app.pyw
```

On first launch a **Setup Wizard** collects your database details (or lets you skip for
offline mode) and stores them securely in your OS keychain — Windows Credential Manager,
macOS Keychain, or Linux Secret Service — so you are not asked again. To preseed the
configuration instead, copy `.env.example` to `.env` and fill it in (see
[Configuration](#-configuration)).

---

## 🔧 Configuration

### Database Setup (Optional)

Layer8 supports both MySQL and offline mode:

**MySQL Configuration** (`.env`):
```bash
L8_DB_HOST=your-mysql-host
L8_DB_PORT=3306
L8_DB_NAME=your-database
MYSQL_USER=your-username
MYSQL_PASSWORD=your-password
```

**Encryption Keys**:
```bash
L8_PEPPER=your-random-pepper-string
L8_PWD_KEY_B64=your-base64-encoded-32-byte-key
```

Generate encryption keys:
```bash
python generate_encryption_keys.py
```

### API Keys (Optional)

For AI analysis features:
```bash
ANTHROPIC_API_KEY=your-anthropic-api-key
```

---

## 🛠️ Development

### Prerequisites

- Python 3.11 or 3.12 (3.13+ may lack wheels for some dependencies)
- pip
- Git

### Setup Development Environment

**Linux / macOS**

```bash
git clone https://github.com/Wesley-Hatch/layer8-gui.git
cd layer8-gui
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pyinstaller pytest black flake8   # dev tools
python3 gui_app.pyw
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/Wesley-Hatch/layer8-gui.git
cd layer8-gui
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pyinstaller pytest black flake8   # dev tools
python gui_app.pyw
```

### Building Executable

```bash
# Automated build
python build.py

# Or manually with PyInstaller
pyinstaller Layer8-GUI.spec
```

See [RELEASE.md](RELEASE.md) for detailed build instructions.

---

## 📦 Project Structure

```
layer8-gui/
├── gui_app.pyw              # Main application entry point
├── modern_theme.py          # Modern UI theme and components
├── db_connection.py         # Database connectivity
├── config.py                # Configuration management
├── updater.py               # Auto-update functionality
├── scanner_tools.py         # Network scanning tools
├── ai_analyzer.py           # AI-powered analysis
├── Layer8/
│   ├── Media/               # Images and icons
│   └── ...                  # Additional resources
├── .github/
│   └── workflows/
│       └── release.yml      # GitHub Actions CI/CD
├── requirements.txt         # Python dependencies
├── build.py                 # Build script
├── RELEASE.md              # Release documentation
├── CHANGELOG.md            # Version history
└── README.md               # This file
```

---

## 🔒 Security Features

### Authentication
- **Argon2id** password hashing (128 MB memory, 3 iterations)
- **Pepper** + password for additional security layer
- **AES-256-GCM** / **NaCl** encryption for stored hashes
- **Rate limiting** with account lockout
- **Session management** with secure tokens

### Network Security
- Port scanning with service detection
- Vulnerability assessment
- Traffic interception and analysis
- WiFi security auditing
- TLS/SSL inspection

### Data Protection
- Encrypted password storage
- Environment variable separation
- Secure key management
- Automatic backup before updates

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings to functions
- Keep functions focused and small

---

## 📋 Requirements

### System Requirements
- **OS**: Windows 10+, Linux (Ubuntu 20.04+), macOS 11+
- **RAM**: 4 GB minimum, 8 GB recommended
- **Storage**: 500 MB available space
- **Network**: Internet connection for cloud features

### Python Dependencies
See [requirements.txt](requirements.txt) for complete list.

Key dependencies:
- `Pillow` - Image processing
- `pymysql` - Database connectivity (pure-Python MySQL client)
- `PyNaCl` - Cryptography
- `argon2-cffi` - Password hashing
- `anthropic` - AI analysis
- `scapy` - Network scanning

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Modern UI** inspired by Cyberpunk aesthetics
- **Encryption** standards from OWASP
- **Network tools** powered by Scapy
- **AI analysis** by Anthropic Claude

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Wesley-Hatch/layer8-gui/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Wesley-Hatch/layer8-gui/discussions)
- **Email**: your-email@example.com

---

## 🗺️ Roadmap

### Version 1.1.0
- [ ] Enhanced AI analysis features
- [ ] Additional scanning tools
- [ ] Mobile companion app
- [ ] Cloud sync capabilities
- [ ] Custom plugin system

### Version 2.0.0
- [ ] Complete UI redesign
- [ ] Real-time collaboration
- [ ] Advanced threat intelligence
- [ ] Automated remediation
- [ ] Enterprise dashboard

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. Users are responsible for complying with all applicable laws and regulations. Unauthorized access to computer systems is illegal.

---

<div align="center">

**Made with ❤️ for the security community**

[⬆ Back to top](#layer8-security-platform)

</div>
