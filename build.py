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

# Configuration
APP_NAME = "Layer8-GUI"
# Version comes from the git tag in CI (L8_VERSION, e.g. "v1.4.2"); falls back
# to this constant for local builds. Update the constant for each release.
_raw_version = os.environ.get("L8_VERSION", "1.4.2")
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
]

# Hidden imports (modules that PyInstaller might miss)
HIDDEN_IMPORTS = [
    "PIL",
    "PIL._imaging",
    "dotenv",
    "nacl",
    "nacl.signing",
    "nacl.encoding",
    "anthropic",
    "scapy",
    "scapy.all",
    "requests",
    "tkinter",
]


def clean_build():
    """Clean previous build artifacts"""
    print("🧹 Cleaning previous builds...")

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

    print(f"✅ Created version file: {version_file}")


def build_executable():
    """Build executable using PyInstaller"""
    print(f"🔨 Building {APP_NAME} v{VERSION}...")

    # Build PyInstaller command
    cmd = [
        "pyinstaller",
        "--name", APP_NAME,
        "--onefile",
        "--windowed",
    ]

    # Add icon if exists
    if Path(ICON_PATH).exists():
        cmd.extend(["--icon", ICON_PATH])

    # Add data files
    for src, dest in DATA_FILES:
        if Path(src).exists():
            cmd.extend(["--add-data", f"{src}{os.pathsep}{dest}"])

    # Add hidden imports
    for module in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", module])

    # Add main script
    cmd.append(MAIN_SCRIPT)

    # Run PyInstaller
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Build failed!")
        print(result.stderr)
        return False

    print("✅ Build successful!")
    return True


def package_release():
    """Package the release into a zip file"""
    print("📦 Packaging release...")

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

    print(f"✅ Created release package: {zip_path}")
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
        print("❌ PyInstaller not found!")
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
    print("✅ BUILD COMPLETE!")
    print("=" * 60)
    print(f"Executable: {DIST_DIR / APP_NAME}")
    print(f"Package: {zip_path}")
    print(f"Size: {zip_path.stat().st_size / 1024 / 1024:.2f} MB")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
