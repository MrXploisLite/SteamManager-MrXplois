import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, filedialog
import json
import pyperclip
import subprocess
import atexit
import os
from ttkthemes import ThemedTk
from zxcvbn import zxcvbn
from cryptography.fernet import Fernet, InvalidToken
import getpass
import secrets
import logging
from datetime import datetime

# Constants
CONFIG_FILE_PATH = "config.json"
ACCOUNTS_FILE_PATH = "accounts.json"
STEAM_EXECUTABLE_PATH = "C:\\Program Files (x86)\\Steam\\Steam.exe"

class SteamAccountManager:
    def __init__(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title("Steam Account Manager")

        self.accounts = {}
        self.license_key = None
        self.fernet = None

        self.frames_container = ttk.Frame(self.root)
        self.frames_container.pack(fill='both', expand=True)

        self.license_frame = ttk.Frame(self.frames_container)
        self.create_license_frame()

        self.accounts_frame = ttk.Frame(self.frames_container)
        self.create_accounts_frame()

        self.show_frame(self.license_frame)

        atexit.register(self.launch_steam_with_last_account)

    def load_real_license_key(self):
        try:
            with open(CONFIG_FILE_PATH, "r") as config_file:
                config_data = json.load(config_file)
                return config_data.get("real_license_key", "")
        except FileNotFoundError:
            return ""

    def decrypt_accounts_data(self, encrypted_data):
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
        except (json.JSONDecodeError, InvalidToken):
            return {}

    def import_accounts(self):
        try:
            with open(ACCOUNTS_FILE_PATH, "rb") as file:
                encrypted_data = file.read()
                self.accounts = self.decrypt_accounts_data(encrypted_data)
                self.update_accounts_tree(self.accounts_tree)
        except FileNotFoundError:
            pass

    def load_accounts(self):
        try:
            with open(ACCOUNTS_FILE_PATH, "rb") as file:
                encrypted_data = file.read()
                return self.decrypt_accounts_data(encrypted_data)
        except FileNotFoundError:
            return {}

    def save_accounts(self):
        encrypted_data = self.fernet.encrypt(json.dumps(self.accounts).encode())
        with open(ACCOUNTS_FILE_PATH, "wb") as file:
            file.write(encrypted_data)

    def create_license_frame(self):
        ttk.Label(self.license_frame, text="License Key:").grid(row=0, column=0, padx=10, pady=10)
        license_entry = ttk.Entry(self.license_frame, show='*')
        license_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(self.license_frame, text="Unlock", command=lambda: self.unlock(license_entry.get())).grid(row=1, column=0, columnspan=2, pady=10)

    def create_accounts_frame(self):
        buttons = [
            ("Add Account", self.add_account),
            ("Remove Account", self.remove_account),
            ("Launch Steam", self.launch_steam),
            ("Export Accounts", self.export_accounts),
            ("Change Password", self.change_password),
            ("Enable 2FA", self.enable_2fa)
        ]

        for i, (text, command) in enumerate(buttons):
            ttk.Button(self.accounts_frame, text=text, command=command).grid(row=0, column=i, padx=10, pady=10)

        columns = ["Username", "Last Login", "Strength", "2FA Enabled"]
        self.accounts_tree = ttk.Treeview(self.accounts_frame, columns=columns, show="headings")

        for col in columns:
            self.accounts_tree.heading(col, text=col)

        self.accounts_tree.bind("<Double-1>", self.on_tree_double_click)
        self.accounts_tree.grid(row=1, column=0, columnspan=len(columns), padx=10, pady=10)

        self.update_accounts_tree(self.accounts_tree)

    def show_frame(self, frame):
        for child in self.frames_container.winfo_children():
            child.pack_forget()
        frame.pack(fill='both', expand=True)

    def update_accounts_tree(self, tree):
        tree.delete(*tree.get_children())

        for account_name, account_info in self.accounts.items():
            password_strength = zxcvbn(account_info["password"]).get("score", 0)
            last_login = account_info.get("last_login", "N/A")
            is_2fa_enabled = account_info.get("2fa_enabled", False)
            tree.insert("", "end", values=(account_name, last_login, password_strength, is_2fa_enabled))

def unlock(self, entered_key):
    if entered_key == self.real_license_key:
        self.license_key = entered_key
        self.fernet = Fernet(Fernet.generate_key())
        self.import_accounts()
        self.create_accounts_frame()
        self.show_frame(self.accounts_frame)
    else:
        messagebox.showerror("Invalid License Key", "The entered license key is invalid.")


    def add_account(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        account_name = simpledialog.askstring("Add Account", "Enter account name")
        if account_name:
            username = simpledialog.askstring("Add Account", f"Enter username for {account_name}")
            generate_password = messagebox.askyesno("Generate Password", "Do you want to generate a strong password?")
            if generate_password:
                password = self.generate_strong_password()
            else:
                password = getpass.getpass(f"Enter password for {account_name}")

            if username and password:
                self.accounts[account_name] = {"username": username, "password": password, "last_login": "N/A", "2fa_enabled": False}
                self.save_accounts()
                self.update_accounts_tree(self.accounts_tree)

    def remove_account(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]
            confirmation = messagebox.askyesno("Confirmation", f"Are you sure you want to remove the account '{account_name}'?")
            if confirmation:
                del self.accounts[account_name]
                self.save_accounts()
                self.update_accounts_tree(self.accounts_tree)

    def change_password(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]
            old_password = getpass.getpass(f"Enter the current password for {account_name}")

            if old_password == self.accounts[account_name]["password"]:
                new_password = self.generate_strong_password()
                self.accounts[account_name]["password"] = new_password
                self.save_accounts()
                self.update_accounts_tree(self.accounts_tree)
                messagebox.showinfo("Password Changed", f"The password for {account_name} has been successfully changed.")
            else:
                messagebox.showerror("Incorrect Password", "The entered password is incorrect.")
        else:
            messagebox.showinfo("Info", "Select an account to change its password.")

    def enable_2fa(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]
            self.accounts[account_name]["2fa_enabled"] = True
            self.save_accounts()
            self.update_accounts_tree(self.accounts_tree)
            messagebox.showinfo("2FA Enabled", f"Two-Factor Authentication has been enabled for {account_name}.")
        else:
            messagebox.showinfo("Info", "Select an account to enable Two-Factor Authentication.")

    def launch_steam(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]

            # Check if Steam executable path is valid
            if not os.path.isfile(STEAM_EXECUTABLE_PATH):
                messagebox.showerror("Error", "Invalid Steam executable path. Please update the path in the code.")
                return

            username = self.accounts[account_name]["username"]
            password = self.accounts[account_name]["password"]

            # Update last login time
            self.accounts[account_name]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.save_accounts()
            self.update_accounts_tree(self.accounts_tree)

            command = f'"{STEAM_EXECUTABLE_PATH}" -login {username} {password}'
            subprocess.Popen(command, shell=True)

            messagebox.showinfo("Info", f"Launching Steam for account: {account_name}")
        else:
            messagebox.showinfo("Info", "Select an account to launch.")

    def on_tree_double_click(self, event):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]
            username = self.accounts[account_name]["username"]
            password = self.accounts[account_name]["password"]

            pyperclip.copy(f"Username: {username}\nPassword: {password}")
            messagebox.showinfo("Copy to Clipboard", "Username and Password copied to clipboard.")

    def generate_strong_password(self):
        password = secrets.token_urlsafe(16)
        messagebox.showinfo("Generated Password", f"Generated Password: {password}")
        return password

    def export_accounts(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "wb") as file:
                encrypted_data = self.fernet.encrypt(json.dumps(self.accounts).encode())
                file.write(encrypted_data)
            messagebox.showinfo("Export Successful", "Accounts exported successfully.")

    def launch_steam_with_last_account(self):
        if not self.license_key or not self.accounts:
            return

        last_selected_account = self.accounts_tree.item(self.accounts_tree.focus(), "values")[0]
        if last_selected_account in self.accounts:
            account_info = self.accounts[last_selected_account]
            username = account_info["username"]
            password = account_info["password"]

            command = f'"{STEAM_EXECUTABLE_PATH}" -login {username} {password}'
            subprocess.Popen(command, shell=True)

if __name__ == "__main__":
    logging.basicConfig(filename="steam_account_manager.log", level=logging.INFO)
    try:
        manager = SteamAccountManager()
        manager.root.mainloop()
    except Exception as e:
        logging.exception("An error occurred:")
        messagebox.showerror("Error", f"An error occurred: {str(e)}")