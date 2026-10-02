# John the Ripper — drop the real tool here

The Layer8 **John The Ripper** tool runs the *real* John the Ripper if it can
find it. It is **not bundled** with Layer8 (it's ~150 MB extracted, GPL, and a
password cracker that antivirus/SmartScreen would flag inside the app), so you
install it here once.

## Windows (recommended)

1. Download the official prebuilt build **`winX64_1_JtR.zip`** from the openwall
   packages release:
   https://github.com/openwall/john-packages/releases/latest
   (direct: `https://github.com/openwall/john-packages/releases/download/v1.9.1-ce/winX64_1_JtR.zip`)
2. Extract it **into this folder** (`tools/john/`) — next to `Layer8-GUI.exe` in
   your install. After extracting you should have:
   ```
   tools/john/JtR/run/john.exe
   ```
   (The exact subfolder name doesn't matter — Layer8 searches recursively for
   `john.exe` under `tools/john/`.)

The `.7z` package (`winX64_1_JtR.7z`, ~27 MB) is smaller if you have 7-Zip.

## Linux

Install from your package manager (gives the jumbo build on most distros):
```bash
sudo apt install john
```
or build from source: https://github.com/openwall/john

## Using the tool

- Put the hashes you want to crack in a file named **`hashes.txt`** next to the
  app (one per line, or `user:hash`), **or** type the full path to a hash file in
  the tool's input box.
- For **raw** hashes (md5 / sha1 / sha256 / NTLM) type the **format** in the
  input box so John loads them correctly and fast, e.g. `Raw-MD5`, `raw-sha1`,
  `raw-sha256`, `NT`. Leave the box blank to let John auto-detect (good for
  shadow files, PWDUMP/NTLM dumps, and `*2john` output; ambiguous for bare raw
  hashes).
- The included `run/` folder also has all the `*2john` converters
  (`zip2john`, `rar2john`, `ssh2john`, `keepass2john`, …) for turning files into
  crackable hashes.

> Authorized use only — crack only hashes you own or are permitted to test.
