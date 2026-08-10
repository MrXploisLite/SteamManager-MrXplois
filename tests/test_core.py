from pathlib import Path

import pytest

from source.main import Vault, VaultError, build_steam_command


def make_vault(tmp_path: Path) -> Vault:
    return Vault(path=tmp_path / "accounts.vault", key_path=tmp_path / "vault.key")


def test_build_steam_command_never_uses_shell() -> None:
    command = build_steam_command("/steam/Steam.exe", "user;evil", "p&ss")
    assert command == ["/steam/Steam.exe", "-login", "user;evil", "p&ss"]


def test_vault_round_trip(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    payload = {
        "version": 2,
        "accounts": {"main": {"username": "alice", "password": "secret"}},
        "settings": {"auto_launch": True, "last_account": "main"},
    }
    vault.save(payload)

    loaded = make_vault(tmp_path).load()
    assert loaded == payload
    assert (tmp_path / "accounts.vault").read_bytes() != b'{"version":2}'


def test_invalid_payload_is_rejected() -> None:
    with pytest.raises(VaultError):
        Vault.validate_payload({"version": 999, "accounts": {}, "settings": {}})


def test_portable_backup_round_trip(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    payload = {
        "version": 2,
        "accounts": {"main": {"username": "alice", "password": "secret"}},
        "settings": {"auto_launch": False, "last_account": "main"},
    }
    vault.save(payload)
    backup = tmp_path / "backup.steamvault"
    vault.export_portable(backup, "correct horse battery staple")

    restored = Vault.import_portable(backup, "correct horse battery staple")
    assert restored == payload


def test_portable_backup_rejects_wrong_password(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.save({"version": 2, "accounts": {}, "settings": {"auto_launch": False, "last_account": None}})
    backup = tmp_path / "backup.steamvault"
    vault.export_portable(backup, "correct horse battery staple")

    with pytest.raises(VaultError):
        Vault.import_portable(backup, "wrong password")


def test_backup_password_minimum(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.save({"version": 2, "accounts": {}, "settings": {"auto_launch": False, "last_account": None}})
    with pytest.raises(VaultError):
        vault.export_portable(tmp_path / "backup.steamvault", "short")
