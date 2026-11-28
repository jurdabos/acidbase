"""
Gives the keyring library in WSL the Windows store, through the bridge in acidbase_boot.py, so WSL keeps no store of its
own.

`acidbase keyring wsl-setup` copies this file and acidbase_boot.py into a folder of their own and names the class in
keyringrc.cfg, so every keyring in WSL uses it: the keyring command, the system Python and every venv. Naming it there
also means no fallback: when the bridge fails, the call fails, instead of quietly reaching for another store. Outside
WSL the class reports itself unusable, so keyring never picks it there.
"""

import subprocess

from jaraco.classes import properties
from keyring.backend import KeyringBackend
from keyring.errors import KeyringError, PasswordDeleteError

import acidbase_boot


def bridge(job: dict) -> dict:
    """
    Runs one job in Windows' Python, turning a failure into a KeyringError that names its kind and never quotes it.
    """
    try:
        return acidbase_boot.windows_keyring(job)
    except FileNotFoundError:
        raise KeyringError("No Windows Python found. Run uv tool install keyring on Windows.") from None
    except subprocess.CalledProcessError as error:
        last = (error.stderr or "").strip().splitlines()[-1:]
        kind = last[0].split(":", 1)[0] if last else "no message"
        raise KeyringError(f"Windows' Python failed on the keyring ({kind})") from None
    except subprocess.TimeoutExpired:
        raise KeyringError("Windows' Python did not answer in time") from None


class WindowsBridgeKeyring(KeyringBackend):
    """
    Reads, writes and deletes entries in Windows Credential Manager from WSL.
    """

    @properties.classproperty
    def priority(cls) -> float:
        """
        Returns a high priority on WSL. Elsewhere it raises, which keyring reads as unusable.
        """
        if not acidbase_boot.on_wsl():
            raise RuntimeError("Only WSL reaches the Windows store through this bridge")
        return 9

    def get_password(self, service: str, username: str) -> str | None:
        """
        Returns the stored value, or None.
        """
        return bridge({"op": "get", "service": service, "items": {username: ""}}).get(username)

    def set_password(self, service: str, username: str, password: str) -> None:
        """
        Stores a value.
        """
        bridge({"op": "set", "service": service, "items": {username: password}})

    def delete_password(self, service: str, username: str) -> None:
        """
        Deletes a value, raising PasswordDeleteError when there is none, as keyring's own backends do.
        """
        if username not in bridge({"op": "delete", "service": service, "items": {username: ""}}):
            raise PasswordDeleteError(f"No entry for {username} under service {service}")
