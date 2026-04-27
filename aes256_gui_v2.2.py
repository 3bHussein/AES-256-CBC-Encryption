#!/usr/bin/env python3
"""
AES-256-CBC Encryption/Decryption Tool
With selectable padding: PKCS7, PKCS5, Zero, ISO10126, ANSI X.923
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import hashlib
import os
import base64
import secrets

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class PaddingHandler:
    """Handle different padding schemes for AES encryption."""

    BLOCK_SIZE = 16  # AES block size in bytes

    @classmethod
    def pad(cls, data: bytes, method: str) -> bytes:
        """Pad data using the specified method."""
        if method == "Pkcs7":
            return cls._pkcs7_pad(data)
        elif method == "Pkcs5":
            return cls._pkcs5_pad(data)
        elif method == "Zero":
            return cls._zero_pad(data)
        elif method == "ISO10126":
            return cls._iso10126_pad(data)
        elif method == "ANSIX923":
            return cls._ansix923_pad(data)
        else:
            raise ValueError(f"Unknown padding method: {method}")

    @classmethod
    def unpad(cls, data: bytes, method: str) -> bytes:
        """Unpad data using the specified method."""
        if method == "Pkcs7":
            return cls._pkcs7_unpad(data)
        elif method == "Pkcs5":
            return cls._pkcs5_unpad(data)
        elif method == "Zero":
            return cls._zero_unpad(data)
        elif method == "ISO10126":
            return cls._iso10126_unpad(data)
        elif method == "ANSIX923":
            return cls._ansix923_unpad(data)
        else:
            raise ValueError(f"Unknown padding method: {method}")

    # --- PKCS7 Padding ---
    @classmethod
    def _pkcs7_pad(cls, data: bytes) -> bytes:
        padder = padding.PKCS7(cls.BLOCK_SIZE * 8).padder()
        return padder.update(data) + padder.finalize()

    @classmethod
    def _pkcs7_unpad(cls, data: bytes) -> bytes:
        unpadder = padding.PKCS7(cls.BLOCK_SIZE * 8).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    # --- PKCS5 Padding (same as PKCS7 but for 8-byte blocks; we use 16-byte for AES compatibility) ---
    @classmethod
    def _pkcs5_pad(cls, data: bytes) -> bytes:
        # For AES, PKCS5 is treated the same as PKCS7 with 16-byte blocks
        # Many tools use "PKCS5" label for AES even though technically PKCS7
        return cls._pkcs7_pad(data)

    @classmethod
    def _pkcs5_unpad(cls, data: bytes) -> bytes:
        return cls._pkcs7_unpad(data)

    # --- Zero Padding ---
    @classmethod
    def _zero_pad(cls, data: bytes) -> bytes:
        pad_len = cls.BLOCK_SIZE - (len(data) % cls.BLOCK_SIZE)
        if pad_len == cls.BLOCK_SIZE:
            pad_len = 0
        return data + b'\x00' * pad_len

    @classmethod
    def _zero_unpad(cls, data: bytes) -> bytes:
        return data.rstrip(b'\x00')

    # --- ISO10126 Padding ---
    @classmethod
    def _iso10126_pad(cls, data: bytes) -> bytes:
        pad_len = cls.BLOCK_SIZE - (len(data) % cls.BLOCK_SIZE)
        if pad_len == 0:
            pad_len = cls.BLOCK_SIZE
        # Random bytes for padding, last byte = pad length
        random_pad = secrets.token_bytes(pad_len - 1)
        return data + random_pad + bytes([pad_len])

    @classmethod
    def _iso10126_unpad(cls, data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > cls.BLOCK_SIZE:
            raise ValueError("Invalid ISO10126 padding")
        return data[:-pad_len]

    # --- ANSI X.923 Padding ---
    @classmethod
    def _ansix923_pad(cls, data: bytes) -> bytes:
        pad_len = cls.BLOCK_SIZE - (len(data) % cls.BLOCK_SIZE)
        if pad_len == 0:
            pad_len = cls.BLOCK_SIZE
        # Zero bytes + last byte = pad length
        return data + b'\x00' * (pad_len - 1) + bytes([pad_len])

    @classmethod
    def _ansix923_unpad(cls, data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > cls.BLOCK_SIZE:
            raise ValueError("Invalid ANSI X.923 padding")
        # Verify preceding bytes are zeros
        for i in range(1, pad_len):
            if data[-(i+1)] != 0:
                raise ValueError("Invalid ANSI X.923 padding")
        return data[:-pad_len]


class AES256CBC:
    """AES-256-CBC encryption handler with selectable padding."""

    def __init__(self):
        self.block_size = 16
        self.key_size = 32

    def _derive_key(self, password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, self.key_size)
        return key, salt

    def encrypt(self, plaintext: bytes, password: str, padding_method: str = "Pkcs7") -> bytes:
        salt = os.urandom(16)
        key, _ = self._derive_key(password, salt)
        iv = os.urandom(16)

        padded_data = PaddingHandler.pad(plaintext, padding_method)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Format: salt(16) + iv(16) + padding_method(1 byte as ASCII) + ciphertext
        pad_byte = padding_method.encode('ascii')[0]
        return salt + iv + bytes([pad_byte]) + ciphertext

    def decrypt(self, encrypted_data: bytes, password: str) -> tuple:
        if len(encrypted_data) < 33:
            raise ValueError("Invalid encrypted data: too short")

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        pad_byte = encrypted_data[32]
        ciphertext = encrypted_data[33:]

        padding_method = chr(pad_byte)
        # Map single char to full name if needed
        pad_map = {'P': 'Pkcs7', '5': 'Pkcs5', 'Z': 'Zero', 'I': 'ISO10126', 'A': 'ANSIX923'}
        if padding_method in pad_map:
            padding_method = pad_map[padding_method]

        key, _ = self._derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        data = PaddingHandler.unpad(padded_data, padding_method)
        return data, padding_method


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256-CBC Encryption Tool")
        self.root.geometry("850x720")
        self.root.minsize(750, 600)

        self.bg_color = "#1e1e2e"
        self.card_color = "#313244"
        self.accent_color = "#89b4fa"
        self.text_color = "#cdd6f4"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"

        self.root.configure(bg=self.bg_color)
        self.aes = AES256CBC()

        if not HAS_CRYPTO:
            messagebox.showerror("Error", "Install 'cryptography' library first:\npip install cryptography")
            root.destroy()
            return

        self.setup_styles()
        self.create_widgets()
        self.center_window()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        style.configure("TButton", background=self.accent_color, foreground="#1e1e2e",
                       font=('Segoe UI', 10, 'bold'), padding=6)
        style.map("TButton", background=[('active', '#b4befe'), ('pressed', '#74c7ec')])

    def center_window(self):
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    def create_widgets(self):
        main = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=15)
        main.pack(fill=tk.BOTH, expand=True)

        # Title
        tk.Label(main, text="🔐 AES-256-CBC Encryption", font=('Segoe UI', 20, 'bold'),
                fg=self.accent_color, bg=self.bg_color).pack()
        tk.Label(main, text="Secure file & text encryption with selectable padding", 
                font=('Segoe UI', 9), fg="#6c7086", bg=self.bg_color).pack()
        tk.Label(main, text="© 2026 @3bHussein", 
                font=('Segoe UI', 8), fg="#6c7086", bg=self.bg_color).pack(pady=(0, 15))

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # === TEXT TAB ===
        text_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(text_tab, text="  📝 Text  ")
        self.create_text_tab(text_tab)

        # === FILE TAB ===
        file_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(file_tab, text="  📁 File  ")
        self.create_file_tab(file_tab)

        # === ABOUT TAB ===
        about_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(about_tab, text="  ℹ️ About  ")
        self.create_about_tab(about_tab)

    def create_text_tab(self, parent):
        # ===== SETTINGS FRAME (Key Size, Mode, Padding) =====
        settings_frame = tk.LabelFrame(parent, text=" Settings ", bg=self.card_color, fg=self.accent_color,
                                      font=('Segoe UI', 10, 'bold'), padx=12, pady=10)
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        # Key Size
        tk.Label(settings_frame, text="Key Size", font=('Segoe UI', 10), 
                fg=self.text_color, bg=self.card_color).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.key_size_var = tk.StringVar(value="256 Bits")
        key_size_combo = ttk.Combobox(settings_frame, textvariable=self.key_size_var, 
                                      values=["256 Bits"], state="readonly", width=15, font=('Segoe UI', 10))
        key_size_combo.grid(row=0, column=1, sticky="w", padx=(0, 30))

        # Mode
        tk.Label(settings_frame, text="Mode", font=('Segoe UI', 10),
                fg=self.text_color, bg=self.card_color).grid(row=0, column=2, sticky="w", padx=(0, 10))
        self.mode_var = tk.StringVar(value="CBC")
        mode_combo = ttk.Combobox(settings_frame, textvariable=self.mode_var,
                                  values=["CBC"], state="readonly", width=15, font=('Segoe UI', 10))
        mode_combo.grid(row=0, column=3, sticky="w", padx=(0, 30))

        # Padding - THE NEW FEATURE
        tk.Label(settings_frame, text="Padding", font=('Segoe UI', 10, 'bold'),
                fg="#fab387", bg=self.card_color).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        self.padding_var = tk.StringVar(value="Pkcs7")
        padding_combo = ttk.Combobox(settings_frame, textvariable=self.padding_var,
                                     values=["Pkcs7", "Pkcs5", "Zero", "ISO10126", "ANSIX923"],
                                     state="readonly", width=15, font=('Segoe UI', 10))
        padding_combo.grid(row=1, column=1, sticky="w", padx=(0, 30), pady=(10, 0))

        # Key Type
        tk.Label(settings_frame, text="Key Type", font=('Segoe UI', 10),
                fg=self.text_color, bg=self.card_color).grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(10, 0))
        self.key_type_var = tk.StringVar(value="PBKDF2")
        key_type_combo = ttk.Combobox(settings_frame, textvariable=self.key_type_var,
                                      values=["PBKDF2"], state="readonly", width=15, font=('Segoe UI', 10))
        key_type_combo.grid(row=1, column=3, sticky="w", pady=(10, 0))

        # ===== PASSWORD FRAME =====
        pwd_frame = tk.LabelFrame(parent, text=" Passphrase ", bg=self.card_color, fg=self.accent_color,
                                 font=('Segoe UI', 10, 'bold'), padx=10, pady=8)
        pwd_frame.pack(fill=tk.X, pady=(0, 10))

        self.text_password = tk.Entry(pwd_frame, show="•", font=('Segoe UI', 11),
                                     bg="#45475a", fg=self.text_color, insertbackground=self.text_color,
                                     relief=tk.FLAT, bd=8)
        self.text_password.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))

        # Generate random password button
        tk.Button(pwd_frame, text="🎲 Random", command=self.generate_random_password,
                 bg="#cba6f7", fg="#1e1e2e", font=('Segoe UI', 9, 'bold'),
                 relief=tk.FLAT, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))

        self.show_pwd_var = tk.BooleanVar()
        tk.Checkbutton(pwd_frame, text="Show", variable=self.show_pwd_var,
                      command=self.toggle_text_password, bg=self.card_color, fg=self.text_color,
                      selectcolor=self.card_color, activebackground=self.card_color,
                      activeforeground=self.accent_color).pack(side=tk.RIGHT)

        # ===== INPUT TEXT =====
        input_frame = tk.LabelFrame(parent, text=" Input Text ", bg=self.card_color, fg=self.accent_color,
                                   font=('Segoe UI', 10, 'bold'), padx=10, pady=8)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, font=('Consolas', 10),
                                                     bg="#45475a", fg=self.text_color,
                                                     insertbackground=self.text_color,
                                                     relief=tk.FLAT, padx=8, pady=8, height=6)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # ===== ACTION BUTTONS =====
        btn_frame = tk.Frame(parent, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Button(btn_frame, text="🔒 ENCRYPT TEXT", command=self.encrypt_text,
                 bg="#89b4fa", fg="#1e1e2e", font=('Segoe UI', 11, 'bold'),
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2",
                 activebackground="#b4befe").pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="🔓 DECRYPT TEXT", command=self.decrypt_text,
                 bg="#a6e3a1", fg="#1e1e2e", font=('Segoe UI', 11, 'bold'),
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2",
                 activebackground="#c8f7c5").pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="🧹 CLEAR", command=self.clear_text,
                 bg="#f38ba8", fg="#1e1e2e", font=('Segoe UI', 11, 'bold'),
                 relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                 activebackground="#fab387").pack(side=tk.RIGHT)

        # ===== OUTPUT TEXT =====
        output_frame = tk.LabelFrame(parent, text=" Output (Base64) ", bg=self.card_color, fg=self.accent_color,
                                    font=('Segoe UI', 10, 'bold'), padx=10, pady=8)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, font=('Consolas', 10),
                                                      bg="#45475a", fg=self.success_color,
                                                      insertbackground=self.text_color,
                                                      relief=tk.FLAT, padx=8, pady=8, height=5)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Copy button
        tk.Button(parent, text="📋 Copy Output to Clipboard", command=self.copy_output,
                 bg="#cba6f7", fg="#1e1e2e", font=('Segoe UI', 10, 'bold'),
                 relief=tk.FLAT, padx=15, pady=6, cursor="hand2",
                 activebackground="#e0b0ff").pack(pady=(8, 0))

    def create_file_tab(self, parent):
        # ===== SETTINGS FRAME =====
        settings_frame = tk.LabelFrame(parent, text=" Settings ", bg=self.card_color, fg=self.accent_color,
                                      font=('Segoe UI', 10, 'bold'), padx=12, pady=10)
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(settings_frame, text="Key Size", font=('Segoe UI', 10),
                fg=self.text_color, bg=self.card_color).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.file_key_size_var = tk.StringVar(value="256 Bits")
        ttk.Combobox(settings_frame, textvariable=self.file_key_size_var,
                     values=["256 Bits"], state="readonly", width=15, font=('Segoe UI', 10)).grid(
            row=0, column=1, sticky="w", padx=(0, 30))

        tk.Label(settings_frame, text="Mode", font=('Segoe UI', 10),
                fg=self.text_color, bg=self.card_color).grid(row=0, column=2, sticky="w", padx=(0, 10))
        self.file_mode_var = tk.StringVar(value="CBC")
        ttk.Combobox(settings_frame, textvariable=self.file_mode_var,
                     values=["CBC"], state="readonly", width=15, font=('Segoe UI', 10)).grid(
            row=0, column=3, sticky="w", padx=(0, 30))

        tk.Label(settings_frame, text="Padding", font=('Segoe UI', 10, 'bold'),
                fg="#fab387", bg=self.card_color).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        self.file_padding_var = tk.StringVar(value="Pkcs7")
        ttk.Combobox(settings_frame, textvariable=self.file_padding_var,
                     values=["Pkcs7", "Pkcs5", "Zero", "ISO10126", "ANSIX923"],
                     state="readonly", width=15, font=('Segoe UI', 10)).grid(
            row=1, column=1, sticky="w", padx=(0, 30), pady=(10, 0))

        tk.Label(settings_frame, text="Key Type", font=('Segoe UI', 10),
                fg=self.text_color, bg=self.card_color).grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(10, 0))
        self.file_key_type_var = tk.StringVar(value="PBKDF2")
        ttk.Combobox(settings_frame, textvariable=self.file_key_type_var,
                     values=["PBKDF2"], state="readonly", width=15, font=('Segoe UI', 10)).grid(
            row=1, column=3, sticky="w", pady=(10, 0))

        # ===== FILE SELECTION =====
        file_frame = tk.LabelFrame(parent, text=" File Selection ", bg=self.card_color, fg=self.accent_color,
                                  font=('Segoe UI', 10, 'bold'), padx=10, pady=8)
        file_frame.pack(fill=tk.X, pady=(0, 10))

        self.file_path_var = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.file_path_var, state="readonly", font=('Segoe UI', 10),
                bg="#45475a", fg=self.text_color, relief=tk.FLAT, bd=8).pack(
            fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))

        tk.Button(file_frame, text="📂 Browse", command=self.browse_file,
                 bg=self.accent_color, fg="#1e1e2e", font=('Segoe UI', 10, 'bold'),
                 relief=tk.FLAT, padx=12, pady=4, cursor="hand2").pack(side=tk.RIGHT)

        # ===== PASSWORD =====
        pwd_frame = tk.LabelFrame(parent, text=" Passphrase ", bg=self.card_color, fg=self.accent_color,
                                 font=('Segoe UI', 10, 'bold'), padx=10, pady=8)
        pwd_frame.pack(fill=tk.X, pady=(0, 15))

        self.file_password = tk.Entry(pwd_frame, show="•", font=('Segoe UI', 11),
                                     bg="#45475a", fg=self.text_color, insertbackground=self.text_color,
                                     relief=tk.FLAT, bd=8)
        self.file_password.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))

        tk.Button(pwd_frame, text="🎲 Random", command=self.generate_file_random_password,
                 bg="#cba6f7", fg="#1e1e2e", font=('Segoe UI', 9, 'bold'),
                 relief=tk.FLAT, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))

        self.show_file_pwd_var = tk.BooleanVar()
        tk.Checkbutton(pwd_frame, text="Show", variable=self.show_file_pwd_var,
                      command=self.toggle_file_password, bg=self.card_color, fg=self.text_color,
                      selectcolor=self.card_color, activebackground=self.card_color,
                      activeforeground=self.accent_color).pack(side=tk.RIGHT)

        # ===== ACTION BUTTONS =====
        action_frame = tk.Frame(parent, bg=self.bg_color)
        action_frame.pack(fill=tk.X, pady=15)

        tk.Button(action_frame, text="🔒 ENCRYPT FILE", command=self.encrypt_file,
                 bg="#89b4fa", fg="#1e1e2e", font=('Segoe UI', 12, 'bold'),
                 relief=tk.FLAT, padx=25, pady=10, cursor="hand2",
                 activebackground="#b4befe").pack(side=tk.LEFT, padx=(0, 15))

        tk.Button(action_frame, text="🔓 DECRYPT FILE", command=self.decrypt_file,
                 bg="#a6e3a1", fg="#1e1e2e", font=('Segoe UI', 12, 'bold'),
                 relief=tk.FLAT, padx=25, pady=10, cursor="hand2",
                 activebackground="#c8f7c5").pack(side=tk.LEFT)

        # Status
        self.status_var = tk.StringVar(value="Ready - Select a file to begin")
        tk.Label(parent, textvariable=self.status_var, font=('Segoe UI', 10),
                fg="#6c7086", bg=self.bg_color).pack(pady=(15, 0))

        self.progress = ttk.Progressbar(parent, mode='determinate', length=500)
        self.progress.pack(pady=(10, 0))

    def create_about_tab(self, parent):
        about_text = """🔐 AES-256-CBC Encryption Tool v2.0

© 2026 @3bHussein. All rights reserved.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 FEATURES:
• AES-256-CBC symmetric encryption
• Password-based key derivation (PBKDF2)
• Random salt and IV for each operation
• Selectable padding schemes:
  - PKCS7 (RFC 5652) - Standard for AES
  - PKCS5 - Legacy DES padding (AES-compatible)
  - Zero - Null byte padding
  - ISO10126 - Random bytes + length indicator
  - ANSI X.923 - Zero bytes + length indicator
• Base64 encoding for text output
• File encryption with .enc extension

🔒 SECURITY:
• 256-bit encryption keys
• 100,000 PBKDF2 iterations
• Unique salt per encryption
• Random IV per operation

⚠️ IMPORTANT:
• Keep your password safe! Lost passwords cannot be recovered.
• Encrypted files use the .enc extension.
• The original file is preserved during encryption.
• Padding method is stored in encrypted data for auto-detection.

📦 REQUIREMENTS:
• Python 3.7+
• cryptography library (pip install cryptography)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

        text_widget = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Consolas', 10),
                                                bg=self.card_color, fg=self.text_color,
                                                relief=tk.FLAT, padx=15, pady=15)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(tk.END, about_text)
        text_widget.configure(state=tk.DISABLED)

    # --- Password utilities ---
    def generate_random_password(self):
        pwd = secrets.token_urlsafe(24)
        self.text_password.delete(0, tk.END)
        self.text_password.insert(0, pwd)
        self.show_pwd_var.set(True)
        self.toggle_text_password()

    def generate_file_random_password(self):
        pwd = secrets.token_urlsafe(24)
        self.file_password.delete(0, tk.END)
        self.file_password.insert(0, pwd)
        self.show_file_pwd_var.set(True)
        self.toggle_file_password()

    def toggle_text_password(self):
        self.text_password.configure(show="" if self.show_pwd_var.get() else "•")

    def toggle_file_password(self):
        self.file_password.configure(show="" if self.show_file_pwd_var.get() else "•")

    # --- Text operations ---
    def encrypt_text(self):
        password = self.text_password.get()
        plaintext = self.input_text.get("1.0", tk.END).strip()
        padding_method = self.padding_var.get()

        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter text to encrypt")
            return

        try:
            encrypted = self.aes.encrypt(plaintext.encode('utf-8'), password, padding_method)
            b64_encoded = base64.b64encode(encrypted).decode('ascii')

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", b64_encoded)

            messagebox.showinfo("Success", f"Text encrypted successfully!\nPadding: {padding_method}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

    def decrypt_text(self):
        password = self.text_password.get()
        ciphertext = self.input_text.get("1.0", tk.END).strip()

        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        if not ciphertext:
            messagebox.showwarning("Warning", "Please enter encrypted text to decrypt")
            return

        try:
            encrypted = base64.b64decode(ciphertext)
            decrypted, detected_padding = self.aes.decrypt(encrypted, password)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", decrypted.decode('utf-8'))

            messagebox.showinfo("Success", f"Text decrypted successfully!\nDetected padding: {detected_padding}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

    def clear_text(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.text_password.delete(0, tk.END)

    def copy_output(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            messagebox.showinfo("Copied", "Output copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No output to copy")

    # --- File operations ---
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All Files", "*.*"), ("Encrypted Files", "*.enc")]
        )
        if file_path:
            self.file_path_var.set(file_path)

    def encrypt_file(self):
        file_path = self.file_path_var.get()
        password = self.file_password.get()
        padding_method = self.file_padding_var.get()

        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Warning", "Please select a valid file")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return

        try:
            self.status_var.set("Reading file...")
            self.progress['value'] = 20
            self.root.update()

            with open(file_path, 'rb') as f:
                data = f.read()

            self.status_var.set(f"Encrypting with {padding_method}...")
            self.progress['value'] = 50
            self.root.update()

            encrypted = self.aes.encrypt(data, password, padding_method)

            output_path = file_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(encrypted)

            self.progress['value'] = 100
            self.status_var.set(f"Saved: {os.path.basename(output_path)}")

            messagebox.showinfo("Success", f"File encrypted successfully!\nPadding: {padding_method}\n\nSaved as:\n{output_path}")
            self.progress['value'] = 0

        except Exception as e:
            self.progress['value'] = 0
            self.status_var.set("Error occurred")
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

    def decrypt_file(self):
        file_path = self.file_path_var.get()
        password = self.file_password.get()

        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Warning", "Please select a valid file")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return

        try:
            self.status_var.set("Reading file...")
            self.progress['value'] = 20
            self.root.update()

            with open(file_path, 'rb') as f:
                data = f.read()

            self.status_var.set("Decrypting...")
            self.progress['value'] = 50
            self.root.update()

            decrypted, detected_padding = self.aes.decrypt(data, password)

            if file_path.endswith('.enc'):
                output_path = file_path[:-4]
            else:
                output_path = file_path + ".decrypted"

            counter = 1
            original_path = output_path
            while os.path.exists(output_path):
                name, ext = os.path.splitext(original_path)
                output_path = f"{name}_{counter}{ext}"
                counter += 1

            with open(output_path, 'wb') as f:
                f.write(decrypted)

            self.progress['value'] = 100
            self.status_var.set(f"Saved: {os.path.basename(output_path)}")

            messagebox.showinfo("Success", f"File decrypted successfully!\nDetected padding: {detected_padding}\n\nSaved as:\n{output_path}")
            self.progress['value'] = 0

        except Exception as e:
            self.progress['value'] = 0
            self.status_var.set("Error occurred")
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")


def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
