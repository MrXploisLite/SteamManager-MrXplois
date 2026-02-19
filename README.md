# Steam Account Manager

A Python-based desktop application for managing multiple Steam accounts with secure password storage and automatic login functionality.

## Features

- **Multiple Account Management**: Add, remove, and manage multiple Steam accounts from a single interface
- **Secure Password Storage**: Passwords are encrypted using Fernet (AES 128) for security
- **Steam Integration**: Direct login to Steam with stored credentials via command line
- **Password Strength Analysis**: Real-time password strength evaluation using zxcvbn
- **Auto-Launch on Exit**: Automatically launches the last selected account when the application closes
- **Password Generation**: Built-in strong password generator
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Encrypted Data Export**: Securely export your account data

## Installation

### Requirements

- Python 3.7+
- Windows, macOS, or Linux operating system

### Setup

1. Clone or download this repository
2. Install the required dependencies:
```bash
pip install tkinter cryptography pyperclip ttkthemes zxcvbn
```

3. Run the application:
```bash
python source/main.py
```

## Usage

### Adding an Account

1. Click "Add Account"
2. Enter a name for the account
3. Enter the Steam username
4. Choose to either enter a custom password or generate a strong one automatically
5. The account will appear in the list with password strength indicator

### Launching Steam

1. Select an account from the list
2. Click "Launch Steam"
3. The application will launch Steam with the selected account logged in
4. The selected account will be remembered for auto-launch on exit

### Removing an Account

1. Select the account to remove
2. Click "Remove Account"
3. Confirm the removal

### Copying Credentials

Double-click on any account to copy both username and password to clipboard.

### Exporting Accounts

Click "Export Accounts" to save your encrypted account data to a JSON file.

## Security

- All passwords are encrypted using Fernet symmetric encryption (based on AES 128)
- Passwords are never stored in plain text
- Encrypted data is saved locally in accounts.json file
- Password strength is evaluated to encourage strong passwords

## Auto-Launch Feature

The application remembers the last selected account and automatically launches Steam with those credentials when the application exits. This is useful for quickly returning to your preferred account.

## Development

This project uses:
- Tkinter for GUI
- Cryptography library for encryption
- Pyperclip for clipboard operations
- ttkthemes for enhanced styling
- zxcvbn for password strength analysis

## Contributing

Feel free to submit issues and enhancement requests. Pull requests are welcome!

## License

This project is open source and available under the MIT License.