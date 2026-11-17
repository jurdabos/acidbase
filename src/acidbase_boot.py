"""
Fills os.environ with the secrets a project's .env names as "# keyring: NAME" markers, when a Python starts.

The line in acidbase_keyring.pth calls load() at every interpreter start in a venv that has acidbase installed, so a
project needs no launcher and no code change. Without markers it reads one file and stops, and without a .env it stops
sooner. A value already in the environment wins, which also spares child processes a second lookup.

This runs before every program in the venv, so it never raises and never prints a value. It imports what it needs
inside each function, to keep a project without markers free of the cost.
"""

import os
import sys

MARKER_PREFIX = "# keyring:"
TRIED = "ACIDBASE_KEYRING_TRIED"
BRIDGE_TIMEOUT_SECONDS = 30
# Listing where installers put Windows' Python, machine-wide ones first, as those are what the fleet's docs set up
WINDOWS_PYTHON_PATTERNS = (
    "/mnt/c/Python3*/python.exe",
    "/mnt/c/Program Files/Python3*/python.exe",
    "/mnt/c/Users/*/AppData/Local/Programs/Python/Python3*/python.exe",
    "/mnt/c/Users/*/AppData/Local/Python/pythoncore-3*/python.exe",
)
# Running in Windows' Python, with the job on stdin, so a secret never appears in any process's arguments
BRIDGE = """
import json, sys
import keyring
job = json.load(sys.stdin)
found = {}
for name, value in job['items'].items():
    if job['op'] == 'get':
        held = keyring.get_password(job['service'], name)
        if held is not None:
            found[name] = held
    elif job['op'] == 'set':
        keyring.set_password(job['service'], name, value)
print(json.dumps(found))
"""


def marker_names(text: str) -> list[str]:
    """
    Returns the names a .env text marks as held in the keyring.
    """
    import re

    return re.findall(r"(?m)^# keyring: ([A-Za-z_]\w*)\s*$", text)


def project_root() -> str | None:
    """
    Returns the folder that holds the active venv, which does not depend on the working directory, or None outside one.
    """
    return None if sys.prefix == sys.base_prefix else os.path.dirname(sys.prefix)


def on_wsl() -> bool:
    """
    Tells whether this is WSL, by the kernel name, which also holds in cron and systemd, where WSL_DISTRO_NAME is unset.
    """
    return hasattr(os, "uname") and "microsoft" in os.uname().release.lower()


def find_windows_python() -> str | None:
    """
    Returns Windows' Python, or None. A login shell finds it on PATH, but systemd and cron build a PATH without the
    Windows folders, so this falls back on the usual install locations, newest version first.
    """
    import glob
    import re
    import shutil

    found = shutil.which("python.exe")
    if found:
        return found
    for pattern in WINDOWS_PYTHON_PATTERNS:
        matches = glob.glob(pattern)
        if matches:
            return max(matches, key=lambda path: int(re.sub(r"\D", "", path.rsplit("/", 2)[-2]) or 0))
    return None


def windows_keyring(job: dict) -> dict:
    """
    Runs a batch of keyring calls in Windows' Python, so WSL shares the Windows store and nothing asks for a password.
    The -P flag keeps the working directory off its sys.path, so a project's own files cannot pose as keyring.
    Args:
        job: The op ("get" or "set"), the service, and the items as a name-to-value dictionary
    Returns:
        The values found, by name
    """
    import json
    import subprocess

    python = find_windows_python()
    if python is None:
        raise FileNotFoundError("python.exe")
    done = subprocess.run(
        [python, "-P", "-c", BRIDGE],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        timeout=BRIDGE_TIMEOUT_SECONDS,
        check=True,
    )
    return json.loads(done.stdout)


def fetch(service: str, names: list[str]) -> dict[str, str]:
    """
    Returns the values the keyring holds for the names, leaving out the ones it does not.
    """
    if on_wsl():
        return windows_keyring({"op": "get", "service": service, "items": dict.fromkeys(names, "")})
    import keyring

    found = {name: keyring.get_password(service, name) for name in names}
    return {name: value for name, value in found.items() if value is not None}


def warn(message: str) -> None:
    """
    Prints one line to stderr. Callers pass names and error types, never values.
    """
    print(f"acidbase: {message}", file=sys.stderr)


def load() -> None:
    """
    Puts the marked secrets of the active project into os.environ. A failure costs one line on stderr, and the program
    still starts, because it may not need the secret, and because stopping here would stop every Python in the venv.
    """
    names: list[str] = []
    try:
        root = project_root()
        if root is None or os.environ.get(TRIED) == root:
            return
        try:
            with open(os.path.join(root, ".env"), encoding="utf-8-sig", errors="replace") as handle:
                text = handle.read()
        except OSError:
            return
        if MARKER_PREFIX not in text:
            return
        names = [name for name in marker_names(text) if name not in os.environ]
        if not names:
            return
        # Telling child processes that this was tried, so a missing secret costs one lookup and one warning
        os.environ[TRIED] = root
        service = os.path.basename(root).lower()
        found = fetch(service, names)
        os.environ.update(found)
        missing = [name for name in names if name not in found]
        if missing:
            warn(f"the keyring has no value for {', '.join(missing)} under service {service}")
    except Exception as error:  # to name the failure without its message, and to let the program start
        warn(f"could not read the keyring ({type(error).__name__}), so these stay unset: {', '.join(names)}")
