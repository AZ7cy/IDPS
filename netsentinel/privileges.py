"""Administrator/root checks, restarting with administrator rights, and plain-language capture errors (Qt-free).

Live capture and the inline IPS need elevated rights:
- Windows: Administrator. Npcap can be installed so that ordinary users may capture too, so live capture
  sometimes works without it; WinDivert (the inline IPS) always needs it.
- Linux: root, or the cap_net_raw (capture) and cap_net_admin (NFQUEUE) capabilities on the Python binary.
"""
from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

CAP_NET_ADMIN, CAP_NET_RAW = 12, 13
PROJECT_DIR = Path(__file__).resolve().parent.parent     # folder that contains the netsentinel package


def _linux_capabilities() -> int:
    """Effective capability bits of this process (0 if unknown)."""
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('CapEff:'):
                return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def is_admin() -> bool:
    """True when running as Administrator (Windows) or with root / the needed capabilities (Linux)."""
    if sys.platform == 'win32':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        return False
    caps = _linux_capabilities()
    return bool(caps & (1 << CAP_NET_RAW)) and bool(caps & (1 << CAP_NET_ADMIN))


def privilege_note() -> str:
    """One sentence for the Dashboard, or '' when the rights are there."""
    if is_admin():
        return ''
    if sys.platform == 'win32':
        return ('Not running as Administrator. The inline IPS needs it, and live capture may too (depending on '
                'how Npcap was installed). Simulated traffic, PCAP replay and Wi-Fi work without it.')
    return ('Not running as root. Live capture and the inline IPS need root: start IDPS with "sudo ./run.sh". '
            'Simulated traffic, PCAP replay and Wi-Fi work without it.')


def can_restart_as_admin() -> bool:
    return sys.platform == 'win32' and not is_admin()


def relaunch_command(argv: Optional[list] = None) -> tuple[str, str, str]:
    """(program, parameters, working folder) that start IDPS again with the same options.

    Uses `python -m netsentinel`, which works however IDPS was started (idps.py, run.bat, the netsentinel
    command or python -m netsentinel)."""
    args = list(sys.argv[1:] if argv is None else argv)
    return sys.executable, subprocess.list2cmdline(['-m', 'netsentinel', *args]), str(PROJECT_DIR)


def restart_as_admin(argv: Optional[list] = None) -> str:
    """Ask Windows to start IDPS again as Administrator (the usual permission prompt).

    Returns '' when the new instance was started, so the caller should close this one, or why it was not."""
    if sys.platform != 'win32':
        return 'Restarting as Administrator only works on Windows. On Linux, use "sudo ./run.sh".'
    try:
        import ctypes
        program, params, folder = relaunch_command(argv)
        code = int(ctypes.windll.shell32.ShellExecuteW(None, 'runas', program, params, folder, 1))
    except Exception as exc:
        return f'Could not restart as Administrator: {exc}'
    if code > 32:                       # ShellExecute returns a value above 32 on success
        return ''
    if code == 5:                       # SE_ERR_ACCESSDENIED: the permission prompt was declined
        return 'The permission prompt was declined, so IDPS keeps running without Administrator rights.'
    return f'Could not restart as Administrator (Windows error {code}).'


_PERMISSION_WORDS = ('permission', 'access is denied', 'access denied', 'not permitted', 'requires root',
                     'administrator', 'privilege')
_NO_DRIVER_WORDS = ('npcap', 'winpcap', 'libpcap', 'not available at layer 2', 'no libpcap')


def capture_error_message(exc: BaseException, gui: bool = True) -> Optional[str]:
    """A plain explanation when live capture failed for missing rights or a missing capture driver, else None."""
    text = str(exc).lower()
    code = getattr(exc, 'errno', None)
    winerror = getattr(exc, 'winerror', None)
    denied = (isinstance(exc, PermissionError) or code in (errno.EPERM, errno.EACCES) or winerror == 5
              or any(w in text for w in _PERMISSION_WORDS))
    if denied:
        if sys.platform == 'win32':
            how = ('click "Restart as Administrator" on the Dashboard' if gui
                   else 'start it from an Administrator terminal')
            return f'Live capture needs Administrator rights: {how}.'
        return ('Live capture needs root: start IDPS with "sudo ./run.sh", or give Python the '
                'cap_net_raw,cap_net_admin capabilities.')
    if any(w in text for w in _NO_DRIVER_WORDS):
        if sys.platform == 'win32':
            return 'Live capture needs Npcap: install it from https://npcap.com and start IDPS again.'
        return 'Live capture needs libpcap: install it (for example "sudo apt install libpcap0.8") and try again.'
    return None
