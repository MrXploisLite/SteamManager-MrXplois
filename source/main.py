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
from cryptography.fernet import Fernet, InvalidToken
from tkinter import filedialog, messagebox, simpledialog, ttk
import tkinter as tk
from ttkthemes import ThemedTk
from zxcvbn import zxcvbn

APP_NAME = "Steam Account Manager"
KEYRING_SERVICE = "MrXploisLite.SteamManager"
KEYRING_USERNAME = "vault-key"
DATA_VERSION = 1


def get_data_dir() -> Path:
    """Return a per-user writable data directory."""
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    path = root / "SteamAccountManager"
    path.mkdir(parents=True, exist_ok=True)
    return path


DATA_DIR = get_data_dir()
ACCOUNTS_FILE_PATH = DATA_DIR / "accounts.vault"
LOCAL_KEY_PATH = DATA_DIR / "vault.key"


def find_steam_executable() -> str | None:
    """Find a Steam executable without hard-coding one machine's path."""
    candidates = []
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
        if str(candidate) and candidate.is_file():
            return str(candidate)
    return shutil.which("steam")


class VaultError(Exception):
    """Raised when the encrypted account vault cannot be used safely."""


class Vault:
    """Encrypted account storage backed by the OS keyring when available."""

    def __init__(self, path: Path = ACCOUNTS_FILE_PATH) -> None:
        self.path = path
        self.fernet = Fernet(self._get_or_create_key())

    def _get_or_create_key(self) -> bytes:
        try:
            encoded = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if encoded:
                return encoded.encode("ascii")

            key = Fernet.generate_key()
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key.decode("ascii"))
            return key
        except Exception as exc:
            # Fallback keeps the app usable on systems without a configured
            # keyring while restricting the key file to the current user.
            try:
                if LOCAL_KEY_PATH.exists():
                    key = LOCAL_KEY_PATH.read_bytes().strip()
                    Fernet(key)  # Validate before using it.
                    return key

                key = Fernet.generate_key()
                LOCAL_KEY_PATH.write_bytes(key + b"\n")
                if os.name != "nt":
                    LOCAL_KEY_PATH.chmod(0o600)
                return key
            except Exception as fallback_exc:
                raise VaultError("Unable to initialize secure key storage") from fallback_exc

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": DATA_VERSION, "accounts": {}, "settings": {"auto_launch": False, "last_account": None}}

        try:
            token = self.path.read_bytes()
            payload = json.loads(self.fernet.decrypt(token).decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError("The account vault is invalid or was created with another encryption key") from exc

        if payload.get("version") != DATA_VERSION:
            raise VaultError(f"Unsupported vault version: {payload.get('version')!r}")

        accounts = payload.get("accounts")
        settings = payload.get("settings")
        if not isinstance(accounts, dict) or not isinstance(settings, dict):
            raise VaultError("The account vault has an invalid structure")

        normalized: dict[str, dict[str, str]] = {}
        for name, info in accounts.items():
            if not isinstance(name, str) or not isinstance(info, dict):
                continue
            username = info.get("username")
            password = info.get("password")
            if isinstance(username, str) and isinstance(password, str):
                normalized[name] = {"username": username, "password": password}

        return {
            "version": DATA_VERSION,
            "accounts": normalized,
            "settings": {
                "auto_launch": bool(settings.get("auto_launch", False)),
                "last_account": settings.get("last_account") if isinstance(settings.get("last_account"), str) else None,
            },
        }

    def save(self, payload: dict[str, Any]) -> None:
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = self.fernet.encrypt(plaintext)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        fd, temp_name = tempfile.mkstemp(prefix="accounts-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            if os.name != "nt":
                self.path.chmod(0o600)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def export_encrypted(self, destination: Path) -> None:
        """Export the encrypted vault bytes, never plaintext credentials."""
        if not self.path.exists():
            raise VaultError("There is no account vault to export")
        destination.write_bytes(self.path.read_bytes())
        if os.name != "nt":
            destination.chmod(0o600)


class SteamAccountManager:
    def __init__(self) -> None:
        self.root = ThemedTk(theme="equilux")
        self.root.title(APP_NAME)
        self.root.geometry("900x620")
        self.root.minsize(720, 480)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.vault = Vault()
        payload = self.vault.load()
        self.accounts: dict[str, dict[str, str]] = payload["accounts"]
        self.settings = payload["settings"]
        self.steam_path = find_steam_executable()
        self.clipboard_clear_job: str | None = None

        self.create_accounts_frame()
        self.update_accounts_tree()

    def persist(self) -> None:
        self.vault.save(
            {
                "version": DATA_VERSION,
                "accounts": self.accounts,
                "settings": self.settings,
            }
        )

    def create_accounts_frame(self) -> None:
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill="both", expand=True)

        toolbar = ttk.Frame(container)
        toolbar.pack(fill="x", pady=(0, 10))

        buttons = [
            ("Add Account", self.add_account),
            ("Remove", self.remove_account),
            ("Launch Steam", self.launch_steam),
            ("Copy Credentials", self.copy_credentials),
            ("Generate Password", self.generate_and_copy_password),
            ("Export Vault", self.export_accounts),
        ]
        for text, command in buttons:
            ttk.Button(toolbar, text=text, command=command).pack(side="left", padx=(0, 6))

        options = ttk.Frame(container)
        options.pack(fill="x", pady=(0, 10))
        self.auto_launch_var = tk.BooleanVar(value=bool(self.settings.get("auto_launch", False)))
        ttk.Checkbutton(
            options,
            text="Launch last selected account when closing",
            variable=self.auto_launch_var,
            command=self.toggle_auto_launch,
        ).pack(side="left")

        self.status_var = tk.StringVar(value=self._status_text())
        ttk.Label(options, textvariable=self.status_var).pack(side="right")

        tree_frame = ttk.Frame(container)
        tree_frame.pack(fill="both", expand=True)

        columns = ("Account", "Username", "Strength")
        self.accounts_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        self.accounts_tree.heading("Account", text="Account")
        self.accounts_tree.heading("Username", text="Username")
        self.accounts_tree.heading("Strength", text="Password Strength")
        self.accounts_tree.column("Account", width=220, anchor="w")
        self.accounts_tree.column("Username", width=280, anchor="w")
        self.accounts_tree.column("Strength", width=160, anchor="center")
        self.accounts_tree.pack(side="left", fill="both", expand=True)
        self.accounts_tree.bind("<Double-1>", lambda _event: self.copy_credentials())

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.accounts_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)

    def _status_text(self) -> str:
        return f"{len(self.accounts)} account(s) • {'Steam found' if self.steam_path else 'Steam not found'}"

    def update_accounts_tree(self) -> None:
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)

        for account_name in sorted(self.accounts, key=str.casefold):
            info = self.accounts[account_name]
            score = zxcvbn(info["password"]).get("score", 0)
            labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
            self.accounts_tree.insert("", "end", iid=account_name, values=(account_name, info["username"], labels[min(score, 4)]))

        self.status_var.set(self._status_text())

    def selected_account_name(self) -> str | None:
        selected = self.accounts_tree.selection()
        return selected[0] if selected else None

    def add_account(self) -> None:
        account_name = simpledialog.askstring("Add Account", "Account name:", parent=self.root)
        if not account_name:
            return
        account_name = account_name.strip()
        if not account_name:
            return
        if account_name in self.accounts:
            messagebox.showerror("Already exists", "That account name already exists.", parent=self.root)
            return

        username = simpledialog.askstring("Add Account", "Steam username:", parent=self.root)
        if not username:
            return

        if messagebox.askyesno("Password", "Generate a strong password automatically?", parent=self.root):
            password = secrets.token_urlsafe(20)
        else:
            password = simpledialog.askstring("Add Account", "Steam password:", show="*", parent=self.root)
        if not password:
            return

        self.accounts[account_name] = {"username": username.strip(), "password": password}
        self.settings["last_account"] = account_name
        self.persist()
        self.update_accounts_tree()

    def remove_account(self) -> None:
        account_name = self.selected_account_name()
        if not account_name:
            messagebox.showinfo("Remove", "Select an account first.", parent=self.root)
            return

        if not messagebox.askyesno("Confirm removal", f"Remove '{account_name}'?", parent=self.root):
            return
        del self.accounts[account_name]
        if self.settings.get("last_account") == account_name:
            self.settings["last_account"] = None
        self.persist()
        self.update_accounts_tree()

    def launch_steam(self) -> None:
        account_name = self.selected_account_name()
        if not account_name:
            messagebox.showinfo("Launch Steam", "Select an account first.", parent=self.root)
            return
        if not self.steam_path:
            messagebox.showerror(
                "Steam not found",
                "Steam could not be found automatically. Install Steam or add it to PATH.",
                parent=self.root,
            )
            return

        info = self.accounts[account_name]
        # shell=False prevents the username/password from becoming shell syntax.
        # Steam itself accepts credentials as command-line arguments, so users
        # should understand that the OS may expose process arguments temporarily.
        try:
            subprocess.Popen([self.steam_path, "-login", info["username"], info["password"]], shell=False)
        except OSError as exc:
            messagebox.showerror("Launch failed", str(exc), parent=self.root)
            return

        self.settings["last_account"] = account_name
        self.persist()
        messagebox.showinfo("Steam", f"Launching Steam for '{account_name}'.", parent=self.root)

    def copy_credentials(self) -> None:
        account_name = self.selected_account_name()
        if not account_name:
            messagebox.showinfo("Copy credentials", "Select an account first.", parent=self.root)
            return

        info = self.accounts[account_name]
        pyperclip.copy(f"Username: {info['username']}\nPassword: {info['password']}")
        if self.clipboard_clear_job:
            self.root.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.root.after(30_000, self.clear_clipboard)
        self.status_var.set("Credentials copied; clipboard will be cleared in 30 seconds")

    def clear_clipboard(self) -> None:
        try:
            pyperclip.copy("")
        except Exception:
            pass
        self.clipboard_clear_job = None
        self.status_var.set(self._status_text())

    def generate_and_copy_password(self) -> None:
        password = secrets.token_urlsafe(20)
        pyperclip.copy(password)
        if self.clipboard_clear_job:
            self.root.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.root.after(30_000, self.clear_clipboard)
        messagebox.showinfo("Generated password", "A strong password was copied to the clipboard and will be cleared in 30 seconds.", parent=self.root)

    def export_accounts(self) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export encrypted vault",
            defaultextension=".vault",
            filetypes=[("Encrypted vault", "*.vault"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            self.vault.export_encrypted(Path(destination))
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)
            return
        messagebox.showinfo("Export complete", "The encrypted vault was exported. Keep it private.", parent=self.root)

    def toggle_auto_launch(self) -> None:
        self.settings["auto_launch"] = bool(self.auto_launch_var.get())
        self.persist()

    def on_close(self) -> None:
        if self.clipboard_clear_job:
            self.clear_clipboard()

        if self.auto_launch_var.get() and self.settings.get("last_account") in self.accounts:
            account_name = self.settings["last_account"]
            if self.steam_path:
                info = self.accounts[account_name]
                try:
                    subprocess.Popen([self.steam_path, "-login", info["username"], info["password"]], shell=False)
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
        raise SystemExit(1)
    manager.root.mainloop()


if __name__ == "__main__":
    main()
