# GitHub Secrets Setup Guide

## Overview

To build the Layer8 GUI executable with your actual database credentials, you need to add your `.env` values as GitHub Secrets. This ensures the credentials are bundled into the executable while keeping them secure and not committed to the repository.

## Required Secrets

Go to your GitHub repository:
1. Click **Settings**
2. Click **Secrets and variables** → **Actions**
3. Click **New repository secret**

Add the following secrets (use the values from your local `.env` file):

### Database Configuration

| Secret Name | Value from .env | Example |
|------------|----------------|---------|
| `L8_DB_HOST` | Your database host | `82.197.82.156` |
| `L8_DB_PORT` | Your database port | `3306` |
| `L8_DB_NAME` | Your database name | `u844677182_app` |
| `L8_DB_USER` | Your database user | `u844677182_Layer8Database` |
| `L8_DB_PASS` | Your database password | `Layer8WJA` |

### Security Configuration

| Secret Name | Value from .env | Example |
|------------|----------------|---------|
| `L8_PEPPER` | Your pepper value | `zVtR89WKPvDDtsHzt5sEqMiMcel9/qzbTVZwoD8JgXM=` |
| `L8_PWD_KEY_B64` | Your password key | `3rdl6s7Wnu9vBB4pNmooWUEArzEFPwBbjuBRUuv30rs=` |

### API Keys (Optional but recommended)

| Secret Name | Value from .env | Example |
|------------|----------------|---------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key | `sk-ant-api03-...` |
| `CLAUDE_API_KEY` | Your Claude API key | `sk-ant-api03-...` |

## Step-by-Step Instructions

### 1. Open Your Local .env File

Open the `.env` file in your project directory and copy the values you need.

### 2. Add Each Secret to GitHub

For **each** secret listed above:

1. Go to: `https://github.com/YOUR_USERNAME/layer8-gui/settings/secrets/actions`
2. Click **New repository secret**
3. Enter the **Name** exactly as shown in the table (e.g., `L8_DB_HOST`)
4. Paste the **Value** from your `.env` file
5. Click **Add secret**

### 3. Verify All Secrets Are Added

After adding all secrets, you should see them listed on the secrets page:

```
✅ L8_DB_HOST
✅ L8_DB_PORT
✅ L8_DB_NAME
✅ L8_DB_USER
✅ L8_DB_PASS
✅ L8_PEPPER
✅ L8_PWD_KEY_B64
✅ ANTHROPIC_API_KEY
✅ CLAUDE_API_KEY
```

### 4. Trigger a New Build

Once all secrets are added:

```bash
git tag -a v1.0.7 -m "Release with bundled credentials from secrets"
git push origin v1.0.7
```

The GitHub Actions workflow will now:
1. Create a `.env` file using your secrets
2. Bundle it with the PyInstaller executable
3. Downloaded executables will connect to the database automatically!

## How It Works

### During Build (GitHub Actions)

The workflow creates a `.env` file from your secrets:

```yaml
- name: Create .env with actual credentials
  run: |
    cat > .env << EOF
    L8_DB_HOST=${{ secrets.L8_DB_HOST }}
    L8_DB_PORT=${{ secrets.L8_DB_PORT }}
    # ... etc
    EOF
```

### In the Executable

PyInstaller bundles the `.env` file inside the executable. When users run it, `config.py` loads the configuration from the bundled `.env` file.

## Security Notes

✅ **Secure**: Secrets are encrypted in GitHub and never exposed in logs
✅ **Not in Git**: The actual `.env` file is still in `.gitignore`
✅ **Controlled Access**: Only repository admins can see/edit secrets
✅ **Build-Time Only**: Secrets are only used during the build process

⚠️ **Important**: The built executables will contain your credentials embedded in the `.env` file. Only distribute to trusted users or your own team.

## Troubleshooting

### Build Fails with "Secret not found"

**Problem**: One or more secrets are missing or misspelled.

**Solution**:
1. Check the Actions log to see which secret is missing
2. Verify the secret name matches exactly (case-sensitive)
3. Add the missing secret and re-run the build

### Database Still Shows "Offline"

**Problem**: Secrets might have wrong values or formatting issues.

**Solution**:
1. Double-check each secret value matches your local `.env`
2. Ensure no extra spaces or newlines in secret values
3. Re-add any suspicious secrets
4. Trigger a new build

### How to Update a Secret

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click on the secret name
3. Click **Update secret**
4. Enter the new value
5. Click **Update secret**
6. Trigger a new build/release

## Example: Adding L8_DB_HOST

1. Open your local `.env` file
2. Find the line: `L8_DB_HOST=82.197.82.156`
3. Copy the value: `82.197.82.156`
4. Go to GitHub repository → Settings → Secrets → New secret
5. Name: `L8_DB_HOST`
6. Value: `82.197.82.156`
7. Click **Add secret**

Repeat for all required secrets!

## Verification

After setting up all secrets and building a release:

1. Download the executable from GitHub Releases
2. Run it
3. The database status should show **Online** ✅
4. Login should work with your credentials

---

**Once this is complete, your executables will have working database connectivity right out of the box!** 🎉
