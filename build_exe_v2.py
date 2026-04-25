#!/usr/bin/env python3
"""
Build script to convert AES-256-CBC GUI v2 to executable
"""

import subprocess
import sys
import os

def install_requirements():
    packages = ["pyinstaller", "cryptography"]
    for pkg in packages:
        print(f"Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

def build_exe():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "AES256-CBC-Tool-v2",
        "--clean",
        "--noconfirm",
        "--hidden-import", "cryptography",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.algorithms",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.modes",
        "--hidden-import", "cryptography.hazmat.backends",
        "--hidden-import", "cryptography.hazmat.primitives.padding",
        "aes256_gui_v2.py"
    ]

    print("Building executable...")
    print("Command:", " ".join(cmd))
    subprocess.check_call(cmd)

    print("\n" + "="*50)
    print("✅ Build complete!")
    print("="*50)
    print("\nExecutable location: dist/AES256-CBC-Tool-v2.exe")

if __name__ == "__main__":
    print("AES-256-CBC Tool v2 Builder")
    print("="*50)

    choice = input("Install requirements first? (y/n): ").lower().strip()
    if choice == 'y':
        install_requirements()

    build_exe()
