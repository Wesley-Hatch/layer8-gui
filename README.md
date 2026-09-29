# Layer8 Security Platform

<div align="center">

![Layer8 Logo](Layer8/Media/Layer8-logo.png)

**Security analysis & network monitoring, in one desktop app.**

[![Release](https://img.shields.io/github/v/release/Wesley-Hatch/Layer8-GUI)](https://github.com/Wesley-Hatch/Layer8-GUI/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Windows-blue)]()

[**Download the latest release**](https://github.com/Wesley-Hatch/Layer8-GUI/releases/latest) • [Changelog](CHANGELOG.md)

</div>

---

## Download & run (no setup)

1. Go to the [**latest release**](https://github.com/Wesley-Hatch/Layer8-GUI/releases/latest).
2. Download **`layer8-gui-windows.zip`**.
3. Extract it anywhere and run **`Layer8-GUI.exe`**.
4. Sign in with the **email** and **access key** issued to you from the Layer8 web console.

That's it — there is nothing to install and no database to configure. The app
verifies your access with the web console over the internet each time you sign
in, and checks for updates automatically on startup.

> Windows may warn about an unrecognized app the first time you run it
> (SmartScreen). Choose **More info → Run anyway**.

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

You only need this if you want to build the `.exe` yourself or run from source.

**Requirements:** Windows, Python 3.11+.

```bash
git clone https://github.com/Wesley-Hatch/Layer8-GUI.git
cd Layer8-GUI
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Run from source:

```bash
python run_gui.py
```

Build a standalone executable (output lands in `release/`):

```bash
pip install pyinstaller
python build.py
```

Optional configuration (AI feature, dev endpoint) lives in a local `.env` —
see [`.env.example`](.env.example). None of it is required to run.

---

## Releasing

Pushing a version tag builds the Windows executable and publishes a GitHub
Release automatically (see [`.github/workflows/release.yml`](.github/workflows/release.yml)):

```bash
git tag v1.4.3
git push origin v1.4.3
```
