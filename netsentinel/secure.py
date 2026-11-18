"""Owner-only permissions for files that can hold secrets (webhook URLs, alert history, packet captures).

POSIX: mode 0700 for folders, 0600 for files. Windows: an explicit ACL that grants full control to the
current user, SYSTEM and Administrators only, with inherited entries removed. Files inside the data folder
(~/.netsentinel) are protected through the folder's ACL, which new files inherit, so icacls runs once per
process. Files placed elsewhere (--db, --json-log, --save-pcap) are restricted individually.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional, Union

from .config import DATA_DIR

_SYSTEM_SID = 'S-1-5-18'
_ADMINS_SID = 'S-1-5-32-544'
_done: set = set()
_lock = threading.Lock()
_user_sid: Optional[str] = None


def _run(args: list) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)          # no console flash from the GUI
    return subprocess.run(args, capture_output=True, text=True, timeout=15, creationflags=flags)


def current_user_sid() -> Optional[str]:
    """The SID of the user running this process (Windows), from whoami, which is language-independent."""
    global _user_sid
    if _user_sid is None:
        try:
            out = _run(['whoami', '/user', '/fo', 'csv', '/nh']).stdout.strip()
            sid = out.rsplit(',', 1)[-1].strip().strip('"')
            _user_sid = sid if sid.startswith('S-1-') else ''
        except (OSError, subprocess.SubprocessError):
            _user_sid = ''
    return _user_sid or None


def windows_acl_args(path: Union[str, os.PathLike], directory: bool, user_sid: str) -> list:
    perm = '(OI)(CI)F' if directory else 'F'
    return ['icacls', str(path), '/inheritance:r', '/grant:r', f'*{user_sid}:{perm}', f'*{_SYSTEM_SID}:{perm}',
            f'*{_ADMINS_SID}:{perm}', '/q']


def _inside_data_dir(path: Path) -> bool:
    try:
        path.resolve().relative_to(DATA_DIR.resolve())
        return True
    except (ValueError, OSError):
        return False


def restrict_to_owner(path: Union[str, os.PathLike]) -> bool:
    """Make `path` readable by its owner only. Never raises; returns False if it could not be done."""
    path = Path(path)
    if not path.exists():
        return False
    if sys.platform != 'win32':
        try:
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
            return True
        except OSError:
            return False
    target = DATA_DIR if _inside_data_dir(path) else path
    key = str(target.resolve()).lower()
    with _lock:
        if key in _done:
            return True
        sid = current_user_sid()
        if sid is None or not target.exists():
            return False
        try:
            ok = _run(windows_acl_args(target, target.is_dir(), sid)).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            _done.add(key)
        return ok
