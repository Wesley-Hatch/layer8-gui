# 🚀 Layer8 GUI - Quick Start Guide

## Setup in 5 Minutes

### Option 1: Automated Setup (Linux/macOS)

```bash
# Run the setup script
chmod +x setup_github.sh
./setup_github.sh

# Follow the prompts
```

### Option 2: Manual Setup (All Platforms)

#### 1. Create GitHub Repository

1. Go to https://github.com/new
2. Repository name: `layer8-gui`
3. Description: `Layer8 Security Platform - GUI Application`
4. **Public** repository (required for free GitHub Actions)
5. **DO NOT** initialize with README
6. Click "Create repository"

#### 2. Push Your Code

```bash
# Initialize git (if not already done)
git init

# Add remote
git remote add origin https://github.com/YOUR_USERNAME/layer8-gui.git

# Set main branch
git branch -M main

# Add all files
git add .

# Commit
git commit -m "Initial commit: Layer8 Security Platform v1.0.1"

# Push
git push -u origin main
```

#### 3. Create First Release

```bash
# Create tag
git tag -a v1.0.1 -m "Release version 1.0.1"

# Push tag (this triggers the build!)
git push origin v1.0.1
```

#### 4. Monitor Build

1. Go to: `https://github.com/YOUR_USERNAME/layer8-gui/actions`
2. Watch the workflow run (takes ~10-15 minutes)
3. ✅ All green = success!

#### 5. Download Your Release

1. Go to: `https://github.com/YOUR_USERNAME/layer8-gui/releases`
2. Download the ZIP for your platform
3. Extract and run!

---

## 🔄 Making Future Releases

### Quick Version

```bash
# 1. Update version numbers in:
#    - gui_app.pyw (line ~2520)
#    - build.py (line ~14)

# 2. Update CHANGELOG.md

# 3. Commit and tag
git add .
git commit -m "Release v1.0.2: Description"
git push origin main
git tag -a v1.0.2 -m "Version 1.0.2"
git push origin v1.0.2

# 4. Wait for build to complete
# 5. Check releases page for new version
```

### Detailed Version

See [RELEASE.md](RELEASE.md) for comprehensive instructions.

---

## 🐛 Common Issues

### Build Fails

**Problem**: GitHub Actions workflow fails

**Fix**:
1. Check the error in Actions tab
2. Usually missing dependencies - update `requirements.txt`
3. Delete tag: `git tag -d v1.0.1 && git push origin :refs/tags/v1.0.1`
4. Fix and recreate tag

### Auto-Update Not Working

**Problem**: App doesn't check for updates

**Fix**: Update `gui_app.pyw` with updater integration (see [RELEASE.md](RELEASE.md#auto-update-configuration))

### .env File Committed

**Problem**: Accidentally committed secrets

**Fix**:
```bash
# Remove from git (keeps local file)
git rm --cached .env

# Add to .gitignore
echo ".env" >> .gitignore

# Commit
git add .gitignore
git commit -m "Remove .env from tracking"
git push origin main

# IMPORTANT: Rotate any exposed secrets!
```

---

## 📚 Documentation

- **RELEASE.md** - Comprehensive release process
- **CHANGELOG.md** - Version history
- **README.md** - Project overview
- **requirements.txt** - Python dependencies
- **.github/workflows/release.yml** - CI/CD configuration

---

## 🎯 Checklist

Before first release:

- [ ] GitHub repository created
- [ ] Code pushed to main branch
- [ ] `.env` in `.gitignore`
- [ ] Version numbers updated
- [ ] CHANGELOG updated
- [ ] Icon file exists at `Layer8/Media/Layer8-logo.ico`
- [ ] Tested GUI locally
- [ ] Ready to create tag

---

## 💡 Tips

1. **Test Locally First**
   ```bash
   python build.py
   # Test the executable in dist/
   ```

2. **Use Semantic Versioning**
   - v1.0.0 = Major
   - v1.1.0 = Minor (new features)
   - v1.0.1 = Patch (bug fixes)

3. **Keep Secrets Safe**
   - Never commit `.env` files
   - Use GitHub Secrets for sensitive data
   - Review `.gitignore` before each commit

4. **Monitor Builds**
   - Failed builds don't create releases
   - Check logs for detailed errors
   - You can re-run failed builds

---

## 🆘 Need Help?

1. Check [RELEASE.md](RELEASE.md) for detailed instructions
2. Review GitHub Actions logs
3. Check [GitHub Actions Documentation](https://docs.github.com/en/actions)
4. Search existing issues on GitHub

---

## ✅ Success!

Once you see the green checkmark in Actions and your release appears with all three platform ZIPs, you're done! 🎉

Your users can now:
1. Download the ZIP for their platform
2. Extract and run Layer8-GUI executable
3. Get automatic updates when you release new versions

---

**Happy Releasing!** 🚀
