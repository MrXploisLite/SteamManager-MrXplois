# FIND LICENSE KEY IN FOLDER

a
# Steam Account Manager

Steam Account Manager is a Python application built using Tkinter for managing and launching multiple Steam accounts.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

## Introduction

This project provides a graphical user interface for managing Steam accounts, allowing users to add, remove, and launch Steam accounts with ease. The application utilizes Tkinter for the GUI, JSON for data storage, and Fernet for basic encryption.

## Features

- Add and remove Steam accounts
- Launch Steam with selected account credentials
- Copy account details to the clipboard
- Search functionality for quickly finding accounts

## Getting Started

To get started with the Steam Account Manager, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/MrXploisLite/Steam-Romy.git

    Install the required dependencies:

    bash

pip install -r requirements.txt

Run the application:

bash

    python steam_account_manager.py

Usage

    Adding an Account: Click on "Settings" in the menu and select "Add Account." Enter the account name, username, and password when prompted.

    Removing an Account: Select an account from the list and click on "Settings" -> "Remove Account" to delete it.

    Launching Steam: Select an account from the list and click on "Launch" -> "Launch Steam" to start Steam with the selected account.

    Copying Account Details: Double-click on an account to copy its username and password to the clipboard.

    Searching for Accounts: Use the search bar to filter accounts by name.

Dependencies

    Python 3.x
    Tkinter
    Cryptography library (Fernet)
    Pyperclip
    Ttkthemes

Install the dependencies using:

bash:

pip install tkinter cryptography pyperclip ttkthemes

Contributing

Feel free to contribute to the project by opening issues or submitting pull requests. Please follow the Contributing Guidelines.
License

This project is licensed under the MIT License - see the LICENSE file for details.

vbnet:

Make sure to keep the file structure, such as the presence of the `requirements.txt`, `CONTRIBUTING.md`, and `LICENSE` files, consistent with your actual repository. Feel free to modify the content to better suit your project if needed.
