# Steam Account Manager

A Python desktop application for managing multiple Steam accounts with encrypted local storage, password generation, password-strength feedback, and optional Steam launching.

## What changed in the hardened version

- Encrypted vault uses **Fernet** with a per-installation key.
- Key is stored in the **OS keyring** when available, with a restricted local-key fallback.
- Account data is stored under the user's application-data directory instead of the working directory.
- Vault writes are atomic to reduce corruption risk.
- Credentials are never rendered as plaintext in the account table.
- Clipboard credentials are automatically cleared after 30 seconds.
- Steam is launched with `shell=False`, avoiding shell interpretation of credentials.
- Steam executable detection is platform-aware instead of assuming one Windows path.
- Auto-launch on application close is **opt-in** and disabled by default.
- Export produces the encrypted vault, not a plaintext JSON dump.

## Requirements

- Python 3.10+
- Steam installed for the launch feature
- A desktop environment with a working Tk backend

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run:

```bash
python source/main.py
```

## Security notes

This application stores Steam credentials locally so it can perform the requested login workflow. The vault contents are encrypted at rest, but **Steam's `-login` command-line interface receives the username and password as process arguments**. Depending on the operating system, process arguments can be observable by other local processes.

For maximum security, use Steam's normal authentication flow and avoid storing a Steam password in any third-party manager.

The encrypted vault and local key fallback are ignored by Git. Never commit `accounts.vault`, `vault.key`, or other credential material.

## Existing data

The current codebase previously generated a new Fernet key in memory and did not persist it. That design could not reliably decrypt an existing `accounts.json` after restarting the application. The hardened version intentionally does **not** pretend those old files are recoverable. Keep a backup of any legacy data before replacing it, and migrate it only if you have a valid key.

## Project structure

```text
.
├── source/
│   └── main.py
├── requirements.txt
├── README.md
├── SECURITY.md
└── .gitignore
```

## License

This project is open source and available under the MIT License.
