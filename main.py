import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, filedialog
import json
from cryptography.fernet import Fernet, InvalidToken
import pyperclip
import secrets
from ttkthemes import ThemedTk
from zxcvbn import zxcvbn

class SteamAccountManager:
    def __init__(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title("Steam Account Manager")

        self.accounts = {}
        self.real_license_key = self.load_real_license_key()
        self.valid_license_keys = {self.real_license_key}
        self.license_key = None
        self.fernet = None

        self.create_license_frame()

    def load_real_license_key(self):
        try:
            with open("config.json", "r") as config_file:
                config_data = json.load(config_file)
                return config_data.get("real_license_key", "")
        except FileNotFoundError:
            return ""

    def load_accounts(self):
        try:
            with open("accounts.json", "rb") as file:
                encrypted_data = file.read()
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                return json.loads(decrypted_data)
        except (FileNotFoundError, json.JSONDecodeError, InvalidToken):
            return {}

    def save_accounts(self):
        encrypted_data = self.fernet.encrypt(json.dumps(self.accounts).encode())
        with open("accounts.json", "wb") as file:
            file.write(encrypted_data)

    def create_license_frame(self):
        license_frame = ttk.Frame(self.root)

        ttk.Label(license_frame, text="License Key:").grid(row=0, column=0, padx=10, pady=10)
        license_entry = ttk.Entry(license_frame, show='*')
        license_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(license_frame, text="Unlock", command=lambda: self.unlock(license_entry.get())).grid(row=1, column=0, columnspan=2, pady=10)

        license_frame.grid(row=0, column=0, padx=50, pady=50)

    def create_accounts_frame(self):
        accounts_frame = ttk.Frame(self.root)

        ttk.Button(accounts_frame, text="Add Account", command=self.add_account).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(accounts_frame, text="Remove Account", command=self.remove_account).grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(accounts_frame, text="Launch Steam", command=self.launch_steam).grid(row=0, column=2, padx=10, pady=10)
        ttk.Button(accounts_frame, text="Export Accounts", command=self.export_accounts).grid(row=0, column=3, padx=10, pady=10)

        self.accounts_tree = ttk.Treeview(accounts_frame, columns=("Username", "Password", "Strength"), show="headings")
        self.accounts_tree.heading("Username", text="Username")
        self.accounts_tree.heading("Password", text="Password")
        self.accounts_tree.heading("Strength", text="Strength")

        self.accounts_tree.bind("<Double-1>", self.on_tree_double_click)

        self.accounts_tree.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

        self.update_accounts_tree(self.accounts_tree)

        accounts_frame.grid(row=1, column=0, padx=50, pady=50)

    def update_accounts_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)

        for account_name, account_info in self.accounts.items():
            password_strength = zxcvbn(account_info["password"]).get("score", 0)
            tree.insert("", "end", values=(account_name, "*" * len(account_info["password"]), password_strength))

    def unlock(self, entered_key):
        if entered_key in self.valid_license_keys:
            self.license_key = entered_key
            self.fernet = Fernet(Fernet.generate_key())
            self.accounts = self.load_accounts()
            self.create_accounts_frame()
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
                password = simpledialog.askstring("Add Account", f"Enter password for {account_name}", show='*')

            if username and password:
                self.accounts[account_name] = {"username": username, "password": password}
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

    def launch_steam(self):
        if not self.license_key:
            messagebox.showinfo("Info", "Unlock the Account Manager first.")
            return

        selected_item = self.accounts_tree.focus()
        if selected_item:
            account_name = self.accounts_tree.item(selected_item, "values")[0]
            self.login_steam(account_name)
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

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    manager = SteamAccountManager()
    manager.run()
