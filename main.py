import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import json
from cryptography.fernet import Fernet
import pyperclip
from subprocess import Popen, CREATE_NEW_CONSOLE
from ttkthemes import ThemedTk

class SteamAccountManager:
    def __init__(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title("Steam Account Manager")

        self.accounts = self.load_accounts()
        self.fernet = Fernet(Fernet.generate_key())

        self.create_gui()

    def load_accounts(self):
        try:
            with open("accounts.json", "r") as file:
                encrypted_data = json.load(file)
                decrypted_data = {self.fernet.decrypt(key.encode()).decode(): value for key, value in encrypted_data.items()}
                return decrypted_data
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_accounts(self):
        encrypted_data = {self.fernet.encrypt(key.encode()).decode(): value for key, value in self.accounts.items()}
        with open("accounts.json", "w") as file:
            json.dump(encrypted_data, file, indent=4)

    def create_gui(self):
        self.create_menu()

        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.map("TButton", foreground=[('pressed', 'black'), ('active', 'blue')])

        self.tree = ttk.Treeview(self.root, columns=("Username", "Password"), show="headings")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")

        self.tree.bind("<Double-1>", self.on_tree_double_click)

        self.tree.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.create_login_frame()

        self.create_search_bar()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        settings_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Add Account", command=self.add_account)
        settings_menu.add_command(label="Remove Account", command=self.remove_account)

        launch_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Launch", menu=launch_menu)
        launch_menu.add_command(label="Launch Steam", command=self.launch_steam)

    def create_login_frame(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for account_name, account_info in self.accounts.items():
            self.tree.insert("", "end", values=(account_name, "*" * len(account_info["password"])))

    def create_search_bar(self):
        search_frame = ttk.Frame(self.root)
        search_frame.grid(row=0, column=0, pady=10, sticky="nsew")

        search_label = ttk.Label(search_frame, text="Search:")
        search_label.grid(row=0, column=0, padx=5)

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.grid(row=0, column=1, padx=5)

        search_button = ttk.Button(search_frame, text="Search", command=self.search_accounts)
        search_button.grid(row=0, column=2, padx=5)

        mask_button = ttk.Button(search_frame, text="Toggle Mask", command=self.toggle_mask)
        mask_button.grid(row=0, column=3, padx=5)

    def search_accounts(self):
        search_term = self.search_var.get().lower()
        if search_term:
            matching_accounts = {name: info for name, info in self.accounts.items() if search_term in name.lower()}
            self.create_login_frame(matching_accounts)
        else:
            self.create_login_frame()

    def toggle_mask(self):
        for item in self.tree.selection():
            account_name = self.tree.item(item, "values")[0]
            account_info = self.accounts[account_name]
            password_length = len(account_info["password"])
            masked_password = "*" * password_length
            self.tree.item(item, values=(account_name, masked_password))

    def add_account(self):
        account_name = simpledialog.askstring("Add Account", "Enter account name")
        if account_name:
            username = simpledialog.askstring("Add Account", f"Enter username for {account_name}")
            password = simpledialog.askstring("Add Account", f"Enter password for {account_name}", show='*')

            if username and password:
                self.accounts[account_name] = {"username": username, "password": password}
                self.save_accounts()
                self.create_login_frame()

    def remove_account(self):
        selected_item = self.tree.selection()
        if selected_item:
            account_name = self.tree.item(selected_item, "values")[0]
            confirmation = messagebox.askyesno("Confirmation", f"Are you sure you want to remove the account '{account_name}'?")
            if confirmation:
                del self.accounts[account_name]
                self.save_accounts()
                self.create_login_frame()

    def on_tree_double_click(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            account_name = self.tree.item(selected_item, "values")[0]
            username = self.accounts[account_name]["username"]
            password = self.accounts[account_name]["password"]

            pyperclip.copy(f"Username: {username}\nPassword: {password}")
            messagebox.showinfo("Copy to Clipboard", "Username and Password copied to clipboard.")

    def login(self, account_name):
        account = self.accounts[account_name]
        command = f'start steam.exe -login {account["username"]} {account["password"]}'
        try:
            Popen(command, shell=True, creationflags=CREATE_NEW_CONSOLE)
        except Exception as e:
            messagebox.showerror("Error", f"Error launching Steam: {e}")

    def launch_steam(self):
        selected_item = self.tree.selection()
        if selected_item:
            account_name = self.tree.item(selected_item, "values")[0]
            self.login(account_name)
        else:
            messagebox.showinfo("Info", "Select an account to launch.")

    def on_close(self):
        self.save_accounts()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    manager = SteamAccountManager()
    manager.run()