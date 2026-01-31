# Layer8 GUI - Release Guide

## 🚀 Release Process

### Prerequisites

1. **GitHub Repository Setup**
   ```bash
   # Initialize git if not already done
   git init
   git add .
   git commit -m "Initial commit"

   # Create repository on GitHub, then:
   git remote add origin https://github.com/Wesley-Hatch/layer8-gui.git
   git branch -M main
   git push -u origin main
   ```

2. **Required Secrets** (None needed for public repos)
   - `GITHUB_TOKEN` is automatically provided by GitHub Actions

3. **Local Development Setup**
   ```bash
   # Install dependencies
   pip install -r requirements.txt

   # Install build tools
   pip install pyinstaller
   ```

---

## 📋 Creating a Release

### Step 1: Update Version Number

Update the version in multiple places:

1. **gui_app.pyw** (line ~2520)
   ```python
   current_version = "1.0.2"  # Update this
   ```

2. **build.py** (line ~14)
   ```python
   VERSION = "1.0.2"  # Update this
   ```

3. **updater.py** (line ~588) - Update example version if needed

### Step 2: Update Changelog

Create or update `CHANGELOG.md`:

```markdown
# Changelog

## [1.0.2] - 2026-01-30

### Added
- New feature X
- Enhancement to Y

### Fixed
- Bug fix Z
- Issue with W

### Changed
- Improved performance of ABC
```

### Step 3: Test Locally

```bash
# Run tests (if you have them)
python -m pytest

# Test the GUI
python gui_app.pyw

# Build locally to verify
python build.py
```

### Step 4: Commit Changes

```bash
git add .
git commit -m "Release v1.0.2: Brief description of changes"
git push origin main
```

### Step 5: Create Git Tag

```bash
# Create annotated tag
git tag -a v1.0.2 -m "Release version 1.0.2"

# Push tag to GitHub (this triggers the build)
git push origin v1.0.2
```

### Step 6: Monitor Build

1. Go to: `https://github.com/Wesley-Hatch/layer8-gui/actions`
2. Watch the build progress
3. If it fails, check the logs and fix issues
4. Delete the tag if needed: `git tag -d v1.0.2 && git push origin :refs/tags/v1.0.2`
5. Recreate the tag after fixes

### Step 7: Verify Release

1. Go to: `https://github.com/Wesley-Hatch/layer8-gui/releases`
2. Verify all three platform builds are present:
   - `layer8-gui-windows.zip`
   - `layer8-gui-linux.zip`
   - `layer8-gui-macos.zip`
3. Download and test each build

---

## 🔄 Auto-Update Configuration

### In gui_app.pyw

Add this code to enable auto-updates:

```python
# Near the top of main() function
from updater import Layer8Updater
import threading

current_version = "1.0.2"
update_url = "https://api.github.com/repos/Wesley-Hatch/layer8-gui/releases/latest"

# Initialize updater
updater = Layer8Updater(
    current_version=current_version,
    update_url=update_url,
    app_directory=Path(__file__).parent
)

# Check for updates in background
def check_updates():
    try:
        if updater.check_for_updates():
            # Show notification to user
            response = messagebox.askyesno(
                "Update Available",
                f"Version {updater.latest_version} is available.\n"
                f"Current version: {current_version}\n\n"
                "Download and install now?"
            )

            if response:
                # Show progress window (use updater_gui.py)
                from updater_gui import UpdaterGUI
                UpdaterGUI(updater).show()
    except Exception as e:
        logging.error(f"Update check failed: {e}")

# Start background check
threading.Thread(target=check_updates, daemon=True).start()
```

---

## 🛠️ Manual Build Process

If you need to build manually without GitHub Actions:

### Windows

```powershell
# Clean previous builds
python build.py

# Or manually with PyInstaller
pyinstaller --name "Layer8-GUI" `
  --onefile `
  --windowed `
  --icon="Layer8/Media/Layer8-logo.ico" `
  --add-data "Layer8;Layer8" `
  --add-data "modern_theme.py;." `
  --add-data "db_connection.py;." `
  --hidden-import=PIL `
  --hidden-import=mysql.connector `
  gui_app.pyw
```

### Linux / macOS

```bash
# Clean previous builds
python build.py

# Or manually with PyInstaller
pyinstaller --name "Layer8-GUI" \
  --onefile \
  --windowed \
  --add-data "Layer8:Layer8" \
  --add-data "modern_theme.py:." \
  --add-data "db_connection.py:." \
  --hidden-import=PIL \
  --hidden-import=mysql.connector \
  gui_app.pyw
```

---

## 📦 Release Checklist

Before creating a release, verify:

- [ ] Version numbers updated in all files
- [ ] Changelog updated with changes
- [ ] All features tested locally
- [ ] Database connection tested
- [ ] Encryption/authentication working
- [ ] No sensitive data in repository (.env ignored)
- [ ] Requirements.txt is up to date
- [ ] README is accurate
- [ ] License file included
- [ ] Icon file exists at correct path
- [ ] GitHub repository is public or secrets configured
- [ ] Previous release was successful (if applicable)

---

## 🐛 Troubleshooting

### Build Fails on GitHub Actions

**Problem**: Workflow fails with import errors

**Solution**: Add missing modules to `HIDDEN_IMPORTS` in `.github/workflows/release.yml`

### Auto-Update Not Working

**Problem**: App doesn't detect updates

**Solution**:
1. Check GitHub repository is public OR GitHub token is configured
2. Verify update URL is correct
3. Check logs in `updater.log`

### Executable Won't Run

**Problem**: Built executable crashes on startup

**Solution**:
1. Check PyInstaller warnings during build
2. Add missing `--add-data` or `--hidden-import` flags
3. Test with `--onedir` instead of `--onefile` for debugging

### Icon Not Showing

**Problem**: Windows executable has default icon

**Solution**: Convert PNG to ICO format first:
```bash
pip install pillow
python -c "from PIL import Image; Image.open('logo.png').save('logo.ico')"
```

---

## 📝 Version Numbering

Follow Semantic Versioning (SemVer):

- **Major** (1.x.x): Breaking changes
- **Minor** (x.1.x): New features, backward compatible
- **Patch** (x.x.1): Bug fixes

Examples:
- `v1.0.0` - Initial release
- `v1.0.1` - Bug fix
- `v1.1.0` - New feature
- `v2.0.0` - Major rewrite

---

## 🔐 Security Considerations

1. **Never commit**:
   - `.env` files
   - API keys
   - Database passwords
   - Encryption keys

2. **Use GitHub Secrets** for:
   - Private repository access tokens
   - Code signing certificates
   - Deployment credentials

3. **Review releases** before publishing:
   - Check ZIP contents
   - Verify no sensitive files included
   - Test on clean machine

---

## 📚 Additional Resources

- [PyInstaller Documentation](https://pyinstaller.org/)
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Semantic Versioning](https://semver.org/)
- [GitHub Releases Guide](https://docs.github.com/en/repositories/releasing-projects-on-github)

---

## 🎯 Quick Reference

```bash
# Full release workflow
git add .
git commit -m "Release v1.0.2"
git push origin main
git tag -a v1.0.2 -m "Version 1.0.2"
git push origin v1.0.2

# Watch build
# Visit: https://github.com/Wesley-Hatch/layer8-gui/actions

# Test release
# Visit: https://github.com/Wesley-Hatch/layer8-gui/releases
```
