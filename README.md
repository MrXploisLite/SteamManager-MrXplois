# Steam Account Manager

A Python desktop application for managing multiple Steam accounts with encrypted local storage, password generation, password-strength feedback, encrypted backups, and optional Steam launching.

## Features

- 🔐 Fernet-encrypted local vault.
- 🔑 Encryption key stored in the OS keyring when available, with a restricted local-key fallback.
- 💾 Atomic vault writes to reduce corruption risk.
- 👤 Account list never displays passwords.
- 📋 Clipboard auto-clears after 30 seconds.
- 🎮 Platform-aware Steam executable detection.
- 🛡️ Steam is started with an argument list and `shell=False`.
- 🚦 Auto-launch on close is optional and disabled by default.
- 📦 Portable `.steamvault` backups protected by a separate password using Scrypt + Fernet.
- ♻️ Restore support with validation before replacing the current vault.

## Requirements

- Python 3.10+
- Steam installed for the launch feature
- Desktop environment with a working Tk backend

Install:

```bash
python -m pip install -r requirements.txt
```

Run:

```bash
python source/main.py
```

## Backup and restore

Use **Backup** to create a portable encrypted `.steamvault` file. The backup password is independent of the machine's keyring and must be at least 12 characters.

Use **Restore** to decrypt and validate a backup before replacing the current vault. Keep both the backup file and its password private; losing the backup password means the backup cannot be recovered.

The ordinary local vault key is deliberately not exported. This prevents a simple vault copy from becoming a portable credential package and keeps the local key separate from the encrypted data.

## Security model and limitations

The vault encrypts credentials at rest, but the application must temporarily hold a selected password in memory to perform the requested login workflow.

Steam's `-login` command-line interface receives the username and password as process arguments. `shell=False` prevents shell interpretation/injection, but it does **not** make command-line credentials invisible to the operating system. Other local processes with sufficient visibility may be able to observe them while Steam starts.

For maximum security, use Steam's normal authentication flow and avoid storing a Steam password in a third-party manager. This application does not bypass Steam Guard, MFA, CAPTCHA, or other Steam security controls.

Never commit `accounts.vault`, `vault.key`, `.steamvault` backups, or other credential material. The repository `.gitignore` excludes these local files.

## Existing data

The original application generated its Fernet key only in memory, so an old `accounts.json` could not reliably be decrypted after restarting. The hardened version does not guess or silently migrate such data. If you have legacy data, keep it as a backup and only migrate it when you possess the original encryption key.

## Development

The project includes focused tests for vault round-trips, encrypted portable backups, invalid data, and command construction. Run:

```bash
pytest -q
```

GitHub Actions also performs Python compilation and the test suite on pushes and pull requests.

## Project structure

```text
.
├── source/
│   └── main.py
├── tests/
│   └── test_core.py
├── requirements.txt
├── README.md
├── SECURITY.md
└── .gitignore
```

## License

This project is open source and available under the MIT License.
