from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import keyring
import pyperclip
import tkinter as tk
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from tkinter import filedialog, messagebox, simpledialog, ttk
from ttkthemes import ThemedTk
from zxcvbn import zxcvbn

APP_NAME = "Steam Account Manager"
KEYRING_SERVICE = "MrXploisLite.SteamManager"
KEYRING_USERNAME = "vault-key"
VAULT_VERSION = 2
BACKUP_VERSION = 1
CLIPBOARD_CLEAR_MS = 30_000


class VaultError(Exception):
    """Raised when secure local storage cannot be used safely."""


def get_data_dir() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    path = root / "SteamAccountManager"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _chmod_private(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def find_steam_executable() -> str | None:
    """Find Steam without assuming one installation path."""
    candidates: list[Path] = []
    if sys.platform == "win32":
        candidates.extend(
            [
                Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Steam/Steam.exe",
                Path(os.environ.get("PROGRAMFILES", "")) / "Steam/Steam.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Steam/Steam.exe",
            ]
        )
    elif sys.platform == "darwin":
        candidates.append(Path("/Applications/Steam.app/Contents/MacOS/steam_osx"))
    else:
        candidates.extend([Path("/usr/bin/steam"), Path("/usr/local/bin/steam")])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which("steam")


def build_steam_command(executable: str, username: str, password: str) -> list[str]:
    """Build an argument-list command; never invoke a shell."""
    return [executable, "-login", username, password]


class Vault:
    """Encrypted local vault with OS keyring storage and safe fallback."""

    def __init__(self, path: Path | None = None, key_path: Path | None = None) -> None:
        data_dir = get_data_dir()
        self.path = path or data_dir / "accounts.vault"
        self.key_path = key_path or data_dir / "vault.key"
        self.fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        try:
            encoded = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if encoded:
                key = encoded.encode("ascii")
                Fernet(key)
                return key
            key = Fernet.generate_key()
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key.decode("ascii"))
            return key
        except Exception:
            # Some Linux/headless installations have no usable keyring.
            # The fallback is intentionally a local, permission-restricted key.
            try:
                if self.key_path.exists():
                    key = self.key_path.read_bytes().strip()
                    Fernet(key)
                    return key
                key = Fernet.generate_key()
                self.key_path.parent.mkdir(parents=True, exist_ok=True)
                fd, temp_name = tempfile.mkstemp(prefix="vault-key-", dir=self.key_path.parent)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(key + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temp_name, self.key_path)
                finally:
                    try:
                        os.unlink(temp_name)
                    except FileNotFoundError:
                        pass
                _chmod_private(self.key_path)
                return key
            except Exception as exc:
                raise VaultError("Unable to initialize secure key storage") from exc

    @staticmethod
    def empty_payload() -> dict[str, Any]:
        return {
            "version": VAULT_VERSION,
            "accounts": {},
            "settings": {"auto_launch": False, "last_account": None},
        }

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self.empty_payload()
        try:
            raw = self.fernet.decrypt(self.path.read_bytes())
            payload = json.loads(raw.decode("utf-8"))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise VaultError("The vault is invalid or belongs to another encryption key") from exc
        return self.validate_payload(payload)

    @staticmethod
    def validate_payload(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or payload.get("version") != VAULT_VERSION:
            raise VaultError("Unsupported or invalid vault version")
        accounts = payload.get("accounts")
        settings = payload.get("settings")
        if not isinstance(accounts, dict) or not isinstance(settings, dict):
            raise VaultError("The vault structure is invalid")
        normalized: dict[str, dict[str, str]] = {}
        for name, info in accounts.items():
            if not isinstance(name, str) or not isinstance(info, dict):
                continue
            username = info.get("username")
            password = info.get("password")
            if isinstance(username, str) and isinstance(password, str) and name.strip() and username.strip():
                normalized[name] = {"username": username, "password": password}
        last = settings.get("last_account")
        return {
            "version": VAULT_VERSION,
            "accounts": normalized,
            "settings": {
                "auto_launch": bool(settings.get("auto_launch", False)),
                "last_account": last if isinstance(last, str) and last in normalized else None,
            },
        }

    def save(self, payload: dict[str, Any]) -> None:
        payload = self.validate_payload(payload)
        encrypted = self.fernet.encrypt(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="accounts-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            _chmod_private(self.path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def export_portable(self, destination: Path, password: str) -> None:
        """Create a password-protected backup usable on another machine."""
        if len(password) < 12:
            raise VaultError("Backup password must be at least 12 characters")
        payload = self.load()
        salt = secrets.token_bytes(16)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
        backup_fernet = Fernet(base64.urlsafe_b64encode(key))
        envelope = {
            "version": BACKUP_VERSION,
            "kdf": "scrypt",
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": backup_fernet.encrypt(json.dumps(payload, separators=(",", ":")).encode()).decode("ascii"),
        }
        _atomic_write(destination, json.dumps(envelope, separators=(",", ":")).encode("utf-8"))

    @staticmethod
    def import_portable(source: Path, password: str) -> dict[str, Any]:
        try:
            envelope = json.loads(source.read_text(encoding="utf-8"))
            if envelope.get("version") != BACKUP_VERSION or envelope.get("kdf") != "scrypt":
                raise VaultError("Unsupported backup format")
            salt = base64.b64decode(envelope["salt"], validate=True)
            key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
            payload = json.loads(Fernet(base64.urlsafe_b64encode(key)).decrypt(envelope["ciphertext"].encode()).decode())
            return Vault.validate_payload(payload)
        except (InvalidToken, ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise VaultError("Backup password is incorrect or the backup is corrupted") from exc


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        _chmod_private(path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


class SteamAccountManager:
    def __init__(self) -> None:
        self.root = ThemedTk(theme="equilux")
        self.root.title(APP_NAME)
        self.root.geometry("980x650")
        self.root.minsize(760, 500)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.vault = Vault()
        payload = self.vault.load()
        self.accounts = payload["accounts"]
        self.settings = payload["settings"]
        self.steam_path = find_steam_executable()
        self.clipboard_clear_job: str | None = None
        self.create_ui()
        self.refresh_accounts()

    def persist(self) -> None:
        self.vault.save({"version": VAULT_VERSION, "accounts": self.accounts, "settings": self.settings})

    def create_ui(self) -> None:
        root_frame = ttk.Frame(self.root, padding=12)
        root_frame.pack(fill="both", expand=True)
        toolbar = ttk.Frame(root_frame)
        toolbar.pack(fill="x", pady=(0, 10))
        buttons = [
            ("Add Account", self.add_account),
            ("Remove", self.remove_account),
            ("Launch Steam", self.launch_steam),
            ("Copy Credentials", self.copy_credentials),
            ("Generate Password", self.generate_and_copy_password),
            ("Backup", self.export_accounts),
            ("Restore", self.import_accounts),
        ]
        for text, command in buttons:
            ttk.Button(toolbar, text=text, command=command).pack(side="left", padx=(0, 6))

        options = ttk.Frame(root_frame)
        options.pack(fill="x", pady=(0, 10))
        self.auto_launch_var = tk.BooleanVar(value=bool(self.settings.get("auto_launch", False)))
        ttk.Checkbutton(
            options,
            text="Launch last account when closing",
            variable=self.auto_launch_var,
            command=self.toggle_auto_launch,
        ).pack(side="left")
        self.status_var = tk.StringVar()
        ttk.Label(options, textvariable=self.status_var).pack(side="right")

        tree_frame = ttk.Frame(root_frame)
        tree_frame.pack(fill="both", expand=True)
        columns = ("Account", "Username", "Strength")
        self.accounts_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for column, title, width in [("Account", "Account", 260), ("Username", "Username", 320), ("Strength", "Password Strength", 180)]:
            self.accounts_tree.heading(column, text=title)
            self.accounts_tree.column(column, width=width, anchor="w")
        self.accounts_tree.pack(side="left", fill="both", expand=True)
        self.accounts_tree.bind("<Double-1>", lambda _event: self.copy_credentials())
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.accounts_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)

    def refresh_accounts(self) -> None:
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)
        labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
        for name in sorted(self.accounts, key=str.casefold):
            info = self.accounts[name]
            score = max(0, min(4, int(zxcvbn(info["password"]).get("score", 0))))
            self.accounts_tree.insert("", "end", iid=name, values=(name, info["username"], labels[score]))
        self.status_var.set(f"{len(self.accounts)} account(s) • {'Steam found' if self.steam_path else 'Steam not found'}")

    def selected_account_name(self) -> str | None:
        selected = self.accounts_tree.selection()
        return selected[0] if selected else None

    def add_account(self) -> None:
        name = simpledialog.askstring("Add Account", "Account name:", parent=self.root)
        if not name or not name.strip():
            return
        name = name.strip()
        if name in self.accounts:
            messagebox.showerror("Already exists", "That account name already exists.", parent=self.root)
            return
        username = simpledialog.askstring("Add Account", "Steam username:", parent=self.root)
        if not username or not username.strip():
            return
        if messagebox.askyesno("Password", "Generate a strong password automatically?", parent=self.root):
            password = secrets.token_urlsafe(24)
        else:
            password = simpledialog.askstring("Add Account", "Steam password:", show="*", parent=self.root)
        if not password:
            return
        self.accounts[name] = {"username": username.strip(), "password": password}
        self.settings["last_account"] = name
        self.persist()
        self.refresh_accounts()

    def remove_account(self) -> None:
        name = self.selected_account_name()
        if not name:
            messagebox.showinfo("Remove", "Select an account first.", parent=self.root)
            return
        if not messagebox.askyesno("Confirm removal", f"Remove '{name}'?", parent=self.root):
            return
        del self.accounts[name]
        if self.settings.get("last_account") == name:
            self.settings["last_account"] = None
        self.persist()
        self.refresh_accounts()

    def launch_steam(self) -> None:
        name = self.selected_account_name()
        if not name:
            messagebox.showinfo("Launch Steam", "Select an account first.", parent=self.root)
            return
        if not self.steam_path:
            messagebox.showerror("Steam not found", "Steam could not be found automatically.", parent=self.root)
            return
        info = self.accounts[name]
        try:
            subprocess.Popen(build_steam_command(self.steam_path, info["username"], info["password"]), shell=False)
        except OSError as exc:
            messagebox.showerror("Launch failed", str(exc), parent=self.root)
            return
        self.settings["last_account"] = name
        self.persist()
        self.status_var.set(f"Launching Steam for '{name}'")

    def copy_credentials(self) -> None:
        name = self.selected_account_name()
        if not name:
            messagebox.showinfo("Copy credentials", "Select an account first.", parent=self.root)
            return
        info = self.accounts[name]
        try:
            pyperclip.copy(f"Username: {info['username']}\nPassword: {info['password']}")
        except Exception as exc:
            messagebox.showerror("Clipboard", f"Could not access clipboard: {exc}", parent=self.root)
            return
        self.schedule_clipboard_clear()
        self.status_var.set("Credentials copied; clipboard clears in 30 seconds")

    def schedule_clipboard_clear(self) -> None:
        if self.clipboard_clear_job:
            self.root.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.root.after(CLIPBOARD_CLEAR_MS, self.clear_clipboard)

    def clear_clipboard(self) -> None:
        try:
            pyperclip.copy("")
        except Exception:
            pass
        self.clipboard_clear_job = None
        self.refresh_accounts()

    def generate_and_copy_password(self) -> None:
        password = secrets.token_urlsafe(24)
        try:
            pyperclip.copy(password)
        except Exception as exc:
            messagebox.showerror("Clipboard", f"Could not access clipboard: {exc}", parent=self.root)
            return
        self.schedule_clipboard_clear()
        messagebox.showinfo("Generated password", "A strong password was copied and will be cleared in 30 seconds.", parent=self.root)

    def export_accounts(self) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self.root, title="Create encrypted backup", defaultextension=".steamvault",
            filetypes=[("Steam encrypted backup", "*.steamvault"), ("All files", "*.*")]
        )
        if not destination:
            return
        password = simpledialog.askstring("Backup password", "Create a backup password (12+ characters):", show="*", parent=self.root)
        if password is None:
            return
        try:
            self.vault.export_portable(Path(destination), password)
        except (OSError, VaultError) as exc:
            messagebox.showerror("Backup failed", str(exc), parent=self.root)
            return
        messagebox.showinfo("Backup complete", "Encrypted backup created. Keep the backup password safe.", parent=self.root)

    def import_accounts(self) -> None:
        source = filedialog.askopenfilename(
            parent=self.root, title="Restore encrypted backup",
            filetypes=[("Steam encrypted backup", "*.steamvault"), ("All files", "*.*")]
        )
        if not source:
            return
        password = simpledialog.askstring("Backup password", "Enter backup password:", show="*", parent=self.root)
        if password is None:
            return
        try:
            payload = Vault.import_portable(Path(source), password)
        except (OSError, VaultError) as exc:
            messagebox.showerror("Restore failed", str(exc), parent=self.root)
            return
        if not messagebox.askyesno("Replace accounts", "Restore will replace the current account vault. Continue?", parent=self.root):
            return
        self.accounts = payload["accounts"]
        self.settings = payload["settings"]
        self.persist()
        self.auto_launch_var.set(bool(self.settings.get("auto_launch", False)))
        self.refresh_accounts()

    def toggle_auto_launch(self) -> None:
        self.settings["auto_launch"] = bool(self.auto_launch_var.get())
        self.persist()

    def on_close(self) -> None:
        if self.clipboard_clear_job:
            self.clear_clipboard()
        if self.auto_launch_var.get() and self.settings.get("last_account") in self.accounts and self.steam_path:
            name = self.settings["last_account"]
            info = self.accounts[name]
            try:
                subprocess.Popen(build_steam_command(self.steam_path, info["username"], info["password"]), shell=False)
            except OSError:
                pass
        self.root.destroy()


def main() -> None:
    try:
        manager = SteamAccountManager()
    except VaultError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(APP_NAME, str(exc), parent=root)
        root.destroy()
        raise SystemExit(1) from exc
    manager.root.mainloop()


if __name__ == "__main__":
    main()
