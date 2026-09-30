#!/usr/bin/env python3
"""
Layer8 GUI Build Script
Builds standalone executables for Windows, macOS, and Linux
"""

import os
import sys
import subprocess
import shutil
import zipfile
from pathlib import Path
import json
from datetime import datetime

# Make stdout/stderr tolerant of non-ASCII on Windows consoles (cp1252), so
# build logs (including captured PyInstaller output) never crash the build.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Configuration
APP_NAME = "Layer8-GUI"
# Version comes from the git tag in CI (L8_VERSION, e.g. "v1.4.2"); falls back
# to this constant for local builds. Update the constant for each release.
_raw_version = os.environ.get("L8_VERSION", "1.4.3")
VERSION = _raw_version[1:] if _raw_version.startswith("v") else _raw_version
ICON_PATH = "Layer8/Media/Layer8-logo.ico"
MAIN_SCRIPT = "gui_app.pyw"

# Directories
ROOT_DIR = Path(__file__).parent
DIST_DIR = ROOT_DIR / "dist"
BUILD_DIR = ROOT_DIR / "build"
RELEASE_DIR = ROOT_DIR / "release"

# Data files to include (bundled alongside the app; imported dynamically)
DATA_FILES = [
    ("Layer8", "Layer8"),
    ("modern_theme.py", "."),
    ("access_client.py", "."),
    ("scanner_tools.py", "."),
    ("ai_analyzer.py", "."),
    ("updater.py", "."),
    ("updater_gui.py", "."),
    ("secure_logger.py", "."),
    ("input_validator.py", "."),
    ("safe_executor.py", "."),
    ("tool_checker.py", "."),
    ("tool_simulator.py", "."),
    ("tool_docs.py", "."),
]

# Hidden imports (modules that PyInstaller might miss)
HIDDEN_IMPORTS = [
    "PIL",
    "PIL._imaging",
    "dotenv",
    "tool_docs",
    "nacl",
    "nacl.signing",
    "nacl.encoding",
    # PyNaCl's compiled libsodium bindings. Without this the import of
    # nacl.signing throws at runtime inside the frozen app, _HAVE_NACL becomes
    # False, and every signed answer from the access console reads as
    # "untrusted". Explicitly naming it (plus --collect-all nacl below) ensures
    # the _sodium shared library is bundled on every platform, especially Linux.
    "nacl._sodium",
    "_cffi_backend",
    "anthropic",
    "scapy",
    "scapy.all",
    "requests",
    "tkinter",
]

# Packages whose submodules, data files, AND compiled shared libraries must all
# be pulled in. `nacl` ships libsodium as a binary extension that PyInstaller's
# static analysis misses; --collect-all is the reliable way to include it.
COLLECT_ALL = [
    "nacl",
    "cffi",
]


def clean_build():
    """Clean previous build artifacts"""
    print("[clean] Cleaning previous builds...")

    for directory in [DIST_DIR, BUILD_DIR, RELEASE_DIR]:
        if directory.exists():
            shutil.rmtree(directory)
            print(f"   Removed {directory}")

    # Remove spec file
    spec_file = ROOT_DIR / f"{APP_NAME}.spec"
    if spec_file.exists():
        spec_file.unlink()
        print(f"   Removed {spec_file}")


def create_version_file():
    """Create version.json file"""
    version_data = {
        "version": VERSION,
        "build_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": sys.platform
    }

    DIST_DIR.mkdir(exist_ok=True)
    version_file = DIST_DIR / "version.json"

    with open(version_file, 'w') as f:
        json.dump(version_data, f, indent=2)

    print(f"[ok] Created version file: {version_file}")


def build_executable():
    """Build executable using PyInstaller"""
    print(f"[build] Building {APP_NAME} v{VERSION}...")

    # Build PyInstaller command. Invoke via the current interpreter so it works
    # whether or not the "pyinstaller" console script is on PATH.
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", APP_NAME,
        "--onefile",
        "--windowed",
    ]

    # Add icon (Windows/macOS embed it; PyInstaller ignores --icon on Linux,
    # so skip it there to avoid a build warning).
    if sys.platform != "linux":
        if sys.platform == "darwin":
            icon = "Layer8/Media/Layer8-logo.png"
        else:
            icon = ICON_PATH
        if Path(icon).exists():
            cmd.extend(["--icon", icon])

    # Add data files
    for src, dest in DATA_FILES:
        if Path(src).exists():
            cmd.extend(["--add-data", f"{src}{os.pathsep}{dest}"])

    # Add hidden imports
    for module in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", module])

    # Collect everything (code + data + binaries) for packages whose native
    # libraries would otherwise be dropped from the frozen app.
    for package in COLLECT_ALL:
        cmd.extend(["--collect-all", package])

    # Add main script
    cmd.append(MAIN_SCRIPT)

    # Run PyInstaller
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("[error] Build failed!")
        print(result.stderr)
        return False

    print("[ok] Build successful!")
    return True


def package_release():
    """Package the release into a zip file"""
    print("[package] Packaging release...")

    RELEASE_DIR.mkdir(exist_ok=True)

    # Determine platform suffix
    if sys.platform == 'win32':
        platform = 'windows'
        exe_ext = '.exe'
    elif sys.platform == 'darwin':
        platform = 'macos'
        exe_ext = ''
    else:
        platform = 'linux'
        exe_ext = ''

    zip_name = f"layer8-gui-{platform}.zip"
    zip_path = RELEASE_DIR / zip_name

    # Create zip file
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add executable
        exe_name = f"{APP_NAME}{exe_ext}"
        exe_path = DIST_DIR / exe_name

        if exe_path.exists():
            zipf.write(exe_path, exe_name)
            print(f"   Added {exe_name}")

        # Add version file
        version_file = DIST_DIR / "version.json"
        if version_file.exists():
            zipf.write(version_file, "version.json")
            print(f"   Added version.json")

        # Add README
        readme = ROOT_DIR / "README.md"
        if readme.exists():
            zipf.write(readme, "README.md")
            print(f"   Added README.md")

    print(f"[ok] Created release package: {zip_path}")
    return zip_path


def main():
    """Main build process"""
    print("=" * 60)
    print(f"Layer8 GUI Build Script")
    print(f"Version: {VERSION}")
    print(f"Platform: {sys.platform}")
    print("=" * 60)

    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("[error] PyInstaller not found!")
        print("Install it with: pip install pyinstaller")
        return 1

    # Step 1: Clean
    clean_build()

    # Step 2: Build
    if not build_executable():
        return 1

    # Step 3: Create version file
    create_version_file()

    # Step 4: Package
    zip_path = package_release()

    print("\n" + "=" * 60)
    print("[ok] BUILD COMPLETE!")
    print("=" * 60)
    print(f"Executable: {DIST_DIR / APP_NAME}")
    print(f"Package: {zip_path}")
    print(f"Size: {zip_path.stat().st_size / 1024 / 1024:.2f} MB")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
