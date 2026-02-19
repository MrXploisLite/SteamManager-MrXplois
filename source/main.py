import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, filedialog
import json
from cryptography.fernet import Fernet, InvalidToken
import pyperclip
import secrets
import subprocess
import atexit  # Added import for atexit
import os
from ttkthemes import ThemedTk
from zxcvbn import zxcvbn

# Constants
ACCOUNTS_FILE_PATH = "accounts.json"
STEAM_EXECUTABLE_PATH = "C:\\\\Program Files (x86)\\\\Steam\\\\Steam.exe"

class SteamAccountManager:
    def __init__(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title("Steam Account Manager")
        self.root.geometry("800x600")

        self.accounts = {}
        self.fernet = None
        self.last_selected_account = None  # Track last selected account

        # Initialize the accounts frame directly
        self.accounts_frame = ttk.Frame(self.root)
        self.create_accounts_frame()
        self.accounts_frame.pack(fill='both', expand=True)

        # Register the function for auto-login when the script exits
        atexit.register(self.launch_steam_with_last_account)

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
            pass  # If import fails, proceed with an empty accounts dictionary

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

    def create_accounts_frame(self):
        ttk.Button(self.accounts_frame, text="Add Account", command=self.add_account).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(self.accounts_frame, text="Remove Account", command=self.remove_account).grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(self.accounts_frame, text="Launch Steam", command=self.launch_steam).grid(row=0, column=2, padx=10, pady=10)
        ttk.Button(self.accounts_frame, text="Export Accounts", command=self.export_accounts).grid(row=0, column=3, padx=10, pady=10)

        self.accounts_tree = ttk.Treeview(self.accounts_frame, columns=("Username", "Password", "Strength"), show="headings")
        self.accounts_tree.heading("Username", text="Username")
        self.accounts_tree.heading("Password", text="Password")
        self.accounts_tree.heading("Strength", text="Strength")

        self.accounts_tree.bind("<Double-1>", self.on_tree_double_click)

        self.accounts_tree.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

        self.update_accounts_tree(self.accounts_tree)

    def update_accounts_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)

        for account_name, account_info in self.accounts.items():
            password_strength = zxcvbn(account_info["password"]).get("score", 0)
            tree.insert("", "end", values=(account_name, "*" * len(account_info["password"]), password_strength))

    def add_account(self):
        account_name = simpledialog.askstring("Add Account", "Enter account name")
        if account_name:
            username = simpledialog.askstring("Add Account", f"Enter username for {account_name}")
            generate_password = messagebox.askyesno("Generate Password", "Do you want to generate a strong password?")
            if generate_password:
                password = self.generate_strong_password()
            else:
                password = simpledialog.askstring("Add Account", f"Enter password for {account_name}", show='*')

            if username and password:
                self.accounts[account_name] = {"username": username, "password": password}
                self.save_accounts()
                self.update_accounts_tree(self.accounts_tree)

    def remove_account(self):
        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]
            confirmation = messagebox.askyesno("Confirmation", f"Are you sure you want to remove the account '{account_name}'?")
            if confirmation:
                del self.accounts[account_name]
                self.save_accounts()
                self.update_accounts_tree(self.accounts_tree)

    def launch_steam(self):
        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]

            # Specify the path to your Steam executable
            username = self.accounts[account_name]["username"]
            password = self.accounts[account_name]["password"]

            command = f'"{STEAM_EXECUTABLE_PATH}" -login {username} {password}'
            subprocess.Popen(command, shell=True)

            # Store the last selected account for auto-launch on exit
            self.last_selected_account = account_name

            messagebox.showinfo("Info", f"Launching Steam for account: {account_name}")
        else:
            messagebox.showinfo("Info", "Select an account to launch.")

    def on_tree_double_click(self, event):
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
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "wb") as file:
                encrypted_data = self.fernet.encrypt(json.dumps(self.accounts).encode())
                file.write(encrypted_data)
            messagebox.showinfo("Export Successful", "Accounts exported successfully.")

    def launch_steam_with_last_account(self):
        if not self.accounts:
            return

        # Use the stored last selected account instead of trying to get it from the UI
        if self.last_selected_account and self.last_selected_account in self.accounts:
            account_info = self.accounts[self.last_selected_account]
            username = account_info["username"]
            password = account_info["password"]

            command = f'"{STEAM_EXECUTABLE_PATH}" -login {username} {password}'
            subprocess.Popen(command, shell=True)

if __name__ == "__main__":
    manager = SteamAccountManager()
    manager.root.mainloop()