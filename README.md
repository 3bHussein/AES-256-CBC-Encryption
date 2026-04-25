# AES-256-CBC Tool v2 - EXE Builder

A Python build script that converts the `aes256_gui_v2.py` GUI application into a standalone Windows executable (`.exe`) using **PyInstaller**.

---

## 📋 What This Script Does

| Step | Action |
|------|--------|
| 1 | Installs required Python packages (`pyinstaller`, `cryptography`) |
| 2 | Runs PyInstaller with optimized flags |
| 3 | Creates a single `.exe` file in the `dist/` folder |

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.7+** installed on Windows
- **pip** (comes with Python)

### Step 1: Install Dependencies (Optional)
The script can auto-install dependencies, or you can pre-install them:

```bash
pip install pyinstaller cryptography
```

### Step 2: Run the Build Script

```bash
python build_exe_v2.py
```

When prompted:
```
Install requirements first? (y/n): y
```

Type `y` to let the script install PyInstaller and cryptography automatically.

### Step 3: Find Your EXE

After successful build:
```
dist/
└── AES256-CBC-Tool-v2.exe   ← Your standalone executable!
```

---

## 🔧 Build Configuration

The script uses these PyInstaller flags:

| Flag | Purpose |
|------|---------|
| `--onefile` | Creates a single `.exe` file (no extra files needed) |
| `--windowed` | No console window pops up (pure GUI app) |
| `--name AES256-CBC-Tool-v2` | Output filename |
| `--clean` | Removes old build files before building |
| `--noconfirm` | Overwrites existing build without asking |
| `--hidden-import` | Ensures cryptography modules are included |

---

## 📦 Hidden Imports

The script explicitly includes these cryptography submodules to prevent import errors:

- `cryptography`
- `cryptography.hazmat.primitives.ciphers`
- `cryptography.hazmat.primitives.ciphers.algorithms`
- `cryptography.hazmat.primitives.ciphers.modes`
- `cryptography.hazmat.backends`
- `cryptography.hazmat.primitives.padding`

---

## 📁 File Structure

```
your-folder/
├── aes256_gui_v2.py      ← Main GUI application (required)
├── build_exe_v2.py       ← This build script
└── dist/                 ← Created after build
    └── AES256-CBC-Tool-v2.exe
```

> **Note:** `aes256_gui_v2.py` must be in the same folder as `build_exe_v2.py`.

---

## ⚠️ Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.7 or higher |
| PyInstaller | 6.0+ |
| cryptography | 41.0+ |

---

## 🛠️ Manual Build (Alternative)

If you prefer running PyInstaller directly:

```bash
pyinstaller \
    --onefile \
    --windowed \
    --name "AES256-CBC-Tool-v2" \
    --clean \
    --noconfirm \
    --hidden-import cryptography \
    --hidden-import cryptography.hazmat.primitives.ciphers \
    --hidden-import cryptography.hazmat.primitives.ciphers.algorithms \
    --hidden-import cryptography.hazmat.primitives.ciphers.modes \
    --hidden-import cryptography.hazmat.backends \
    --hidden-import cryptography.hazmat.primitives.padding \
    aes256_gui_v2.py
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `pyinstaller not found` | Run `pip install pyinstaller` |
| `cryptography not found` | Run `pip install cryptography` |
| Build fails with import errors | Make sure `aes256_gui_v2.py` is in the same folder |
| EXE is too large | Normal — includes Python + all dependencies (~15-20 MB) |
| Antivirus flags the EXE | False positive — add to exclusions or use `--onedir` instead |

---

## 📄 License

Provided as-is for educational and personal use.

---

**Built with PyInstaller + Python cryptography**
