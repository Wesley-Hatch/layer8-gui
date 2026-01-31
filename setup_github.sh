#!/bin/bash
# Layer8 GUI - GitHub Setup Script
# This script helps you quickly set up GitHub repository and first release

set -e  # Exit on error

echo "=================================================="
echo "Layer8 GUI - GitHub Repository Setup"
echo "=================================================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Get GitHub username
read -p "Enter your GitHub username: " GITHUB_USER

if [ -z "$GITHUB_USER" ]; then
    echo "❌ GitHub username is required"
    exit 1
fi

REPO_NAME="layer8-gui"
REPO_URL="https://github.com/$GITHUB_USER/$REPO_NAME.git"

echo ""
echo "Repository will be: $REPO_URL"
echo ""

# Initialize git if not already
if [ ! -d .git ]; then
    echo "📁 Initializing git repository..."
    git init
    echo "✅ Git initialized"
else
    echo "✅ Git repository already initialized"
fi

# Update URLs in documentation
echo ""
echo "📝 Updating documentation with your GitHub username..."

# Update RELEASE.md
if [ -f "RELEASE.md" ]; then
    sed -i "s/YOUR_USERNAME/$GITHUB_USER/g" RELEASE.md 2>/dev/null || \
    sed -i "" "s/YOUR_USERNAME/$GITHUB_USER/g" RELEASE.md 2>/dev/null
    echo "   Updated RELEASE.md"
fi

# Update CHANGELOG.md
if [ -f "CHANGELOG.md" ]; then
    sed -i "s/YOUR_USERNAME/$GITHUB_USER/g" CHANGELOG.md 2>/dev/null || \
    sed -i "" "s/YOUR_USERNAME/$GITHUB_USER/g" CHANGELOG.md 2>/dev/null
    echo "   Updated CHANGELOG.md"
fi

# Update updater.py
if [ -f "updater.py" ]; then
    sed -i "s/Wesley-Hatch/$GITHUB_USER/g" updater.py 2>/dev/null || \
    sed -i "" "s/Wesley-Hatch/$GITHUB_USER/g" updater.py 2>/dev/null
    sed -i "s/Layer8-GUI/$REPO_NAME/g" updater.py 2>/dev/null || \
    sed -i "" "s/Layer8-GUI/$REPO_NAME/g" updater.py 2>/dev/null
    echo "   Updated updater.py"
fi

# Update gui_app.pyw update URL
if [ -f "gui_app.pyw" ]; then
    # This is optional - you can manually update gui_app.pyw with the updater integration
    echo "   ⚠️  Remember to manually update gui_app.pyw with updater integration (see RELEASE.md)"
fi

echo "✅ Documentation updated"

# Check for .env file
echo ""
if [ -f ".env" ]; then
    echo "⚠️  WARNING: .env file detected!"
    echo "   Make sure .env is in .gitignore to avoid committing secrets"

    if ! grep -q ".env" .gitignore 2>/dev/null; then
        echo "   ❌ .env is NOT in .gitignore!"
        read -p "   Add .env to .gitignore? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo ".env" >> .gitignore
            echo "   ✅ Added .env to .gitignore"
        fi
    else
        echo "   ✅ .env is already in .gitignore"
    fi
fi

# Add all files
echo ""
echo "📦 Staging files for commit..."
git add .

# Create initial commit if needed
if ! git log -1 &> /dev/null; then
    echo ""
    echo "📝 Creating initial commit..."
    git commit -m "Initial commit: Layer8 Security Platform v1.0.1

- Modern dark theme GUI
- MySQL authentication with Argon2id
- Auto-update functionality
- Network security scanning tools
- AI-powered analysis
- Comprehensive documentation
"
    echo "✅ Initial commit created"
else
    echo "✅ Repository already has commits"
fi

# Set main branch
echo ""
echo "🌿 Setting up main branch..."
git branch -M main
echo "✅ Main branch ready"

# Instructions for GitHub
echo ""
echo "=================================================="
echo "Next Steps:"
echo "=================================================="
echo ""
echo "1. Create repository on GitHub:"
echo "   Visit: https://github.com/new"
echo "   - Repository name: $REPO_NAME"
echo "   - Description: Layer8 Security Platform - GUI Application"
echo "   - Make it public (or private if you prefer)"
echo "   - DO NOT initialize with README, .gitignore, or license"
echo ""
echo "2. After creating the repository, run:"
echo "   git remote add origin $REPO_URL"
echo "   git push -u origin main"
echo ""
echo "3. Create your first release:"
echo "   git tag -a v1.0.1 -m 'Release version 1.0.1'"
echo "   git push origin v1.0.1"
echo ""
echo "4. Monitor the build:"
echo "   Visit: https://github.com/$GITHUB_USER/$REPO_NAME/actions"
echo ""
echo "5. Check your release:"
echo "   Visit: https://github.com/$GITHUB_USER/$REPO_NAME/releases"
echo ""
echo "=================================================="
echo "✅ Setup complete! Follow the steps above."
echo "=================================================="
