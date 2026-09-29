# Layer8 Security Platform

<div align="center">

![Layer8 Logo](Layer8/Media/Layer8-logo.png)

**Security analysis & network monitoring, in one desktop app.**

[![Release](https://img.shields.io/github/v/release/Wesley-Hatch/layer8-gui)](https://github.com/Wesley-Hatch/layer8-gui/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)]()

[**Download the latest release**](https://github.com/Wesley-Hatch/layer8-gui/releases/latest) • [Changelog](CHANGELOG.md)

</div>

---

## Download & run (no setup)

Grab the build for your OS from the [**latest release**](https://github.com/Wesley-Hatch/layer8-gui/releases/latest),
then sign in with the **email** and **access key** issued to you from the Layer8
web console. There's nothing to install and no database to configure — the app
verifies your access over the internet each sign-in and auto-updates on startup.

### Windows

1. Download **`layer8-gui-windows.zip`** and extract it anywhere.
2. Run **`Layer8-GUI.exe`**.

> Windows may warn about an unrecognized app the first time (SmartScreen).
> Choose **More info → Run anyway**.

### Linux

1. Download **`layer8-gui-linux.zip`** and extract it:
   ```bash
   unzip layer8-gui-linux.zip
   ```
2. Make the binary executable and run it:
   ```bash
   chmod +x Layer8-GUI
   ./Layer8-GUI
   ```
3. The live packet-capture tools (traffic monitor, sniffer, Wi-Fi) need libpcap
   and root privileges:
   ```bash
   sudo apt install libpcap0.8      # Debian/Ubuntu; use your distro's package otherwise
   sudo ./Layer8-GUI
   ```

> Built and tested against Ubuntu/Debian x86_64. A few Windows-only audit tools
> (those that call `wmic`/`netsh`) don't apply on Linux; everything else works.

---

## Features

- **Web-console sign-in** — access is issued, suspended, revoked, expired and
  seat-limited from the Layer8 web console. Every answer is Ed25519-signed, with
  an offline grace period for short outages.
- **Network scanning** — port scanning, service detection, host discovery.
- **Vulnerability probing** — surface common weaknesses on a target.
- **Traffic monitoring** — live traffic view with website/TLS SNI detection.
- **Wi-Fi assessment** — interface detection, SSID scanning, network probing.
- **AI analysis** — optional Claude-powered log/finding analysis.
- **Auto-updates** — one-click update to the newest release.
- **Modern dark UI.**

> Use Layer8 only against systems you own or are explicitly authorized to test.

---

## Accounts & access

There is no local sign-up. Accounts are created and managed in the **Layer8 web
console**; users sign in here with the email + access key they were given. Admins
manage users (create / suspend / revoke / plans / device seats) in that console —
the in-app **Admin Panel** links straight to it.

---

## Build from source (optional)

You only need this if you want to build the executable yourself or run from
source. **Requirements:** Python 3.11+.

**Windows (PowerShell):**

```powershell
git clone https://github.com/Wesley-Hatch/layer8-gui.git
cd layer8-gui
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_gui.py
```

**Linux:**

```bash
sudo apt install libpcap-dev python3-tk        # Debian/Ubuntu build/runtime deps
git clone https://github.com/Wesley-Hatch/layer8-gui.git
cd layer8-gui
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run_gui.py                              # sudo for the packet-capture tools
```

Build a standalone executable for the OS you're on (output lands in `release/`):

```bash
pip install pyinstaller
python build.py        # produces layer8-gui-windows.zip or layer8-gui-linux.zip
```

Optional configuration (AI feature, dev endpoint) lives in a local `.env` —
see [`.env.example`](.env.example). None of it is required to run.

---

## Releasing

Pushing a version tag builds the Windows **and** Linux executables and publishes
a GitHub Release with both automatically
(see [`.github/workflows/release.yml`](.github/workflows/release.yml)):

```bash
git tag v1.4.3
git push origin v1.4.3
```
