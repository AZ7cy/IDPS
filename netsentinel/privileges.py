"""Administrator/root checks, restarting with administrator rights, and plain-language capture errors (Qt-free).

Live capture and the inline IPS need elevated rights:
- Windows: Administrator. Npcap can be installed so that ordinary users may capture too, so live capture
  sometimes works without it; WinDivert (the inline IPS) always needs it.
- Linux: root, or capabilities on the Python binary: cap_net_raw for capture, plus cap_net_admin for NFQUEUE.
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
LAUNCHER = PROJECT_DIR / 'idps.py'


def _linux_capabilities() -> int:
    """Effective capability bits of this process (0 if unknown)."""
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('CapEff:'):
                return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _windows_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _linux_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def is_admin() -> bool:
    """Rights for everything (capture and the inline IPS): Administrator on Windows; root, or both
    cap_net_raw and cap_net_admin, on Linux."""
    if sys.platform == 'win32':
        return _windows_admin()
    if _linux_root():
        return True
    caps = _linux_capabilities()
    return bool(caps & (1 << CAP_NET_RAW)) and bool(caps & (1 << CAP_NET_ADMIN))


def can_capture() -> bool:
    """Rights for live capture: on Linux cap_net_raw is enough. (On Windows it depends on how Npcap was
    installed, which cannot be checked, so this is the Administrator check.)"""
    if sys.platform == 'win32':
        return _windows_admin()
    return _linux_root() or bool(_linux_capabilities() & (1 << CAP_NET_RAW))


def privilege_note() -> str:
    """One sentence for the Dashboard, or '' when the rights are there."""
    if is_admin():
        return ''
    if sys.platform == 'win32':
        return ('Not running as Administrator. The inline IPS needs it, and live capture may too (depending on '
                'how Npcap was installed). Simulated traffic, PCAP replay and Wi-Fi work without it.')
    if can_capture():
        return ('Live capture works, but the inline IPS needs root (or the cap_net_admin capability): start IDPS '
                'with "sudo ./run.sh" to use it.')
    return ('Not running as root. Live capture and the inline IPS need root: start IDPS with "sudo ./run.sh". '
            'Simulated traffic, PCAP replay and Wi-Fi work without it.')


def can_restart_as_admin() -> bool:
    return sys.platform == 'win32' and not is_admin()


def _windowless(python: str) -> str:
    """pythonw.exe next to python.exe, so the elevated GUI does not open a console window of its own."""
    p = Path(python)
    w = p.with_name(p.stem + 'w' + p.suffix)
    return str(w) if p.stem.lower() == 'python' and w.is_file() else python


def relaunch_command(argv: Optional[list] = None, console: bool = False) -> tuple[str, str, str]:
    """(program, parameters, working folder) that start IDPS again with the same options.

    The working folder stays the current one, so relative paths such as `--db lab.db` mean the same file.
    In a source checkout the launcher is run by its full path (it puts the package on sys.path itself);
    an installed package is run with `-m netsentinel`."""
    args = list(sys.argv[1:] if argv is None else argv)
    head = [str(LAUNCHER)] if LAUNCHER.is_file() else ['-m', 'netsentinel']
    program = sys.executable if console else _windowless(sys.executable)
    return program, subprocess.list2cmdline([*head, *args]), os.getcwd()


def restart_as_admin(argv: Optional[list] = None, owner: int = 0) -> str:
    """Ask Windows to start IDPS again as Administrator (the usual permission prompt).

    `owner` is the window handle the prompt belongs to. Returns '' when the new instance was started, so
    the caller should close this one, or why it was not."""
    if sys.platform != 'win32':
        return 'Restarting as Administrator only works on Windows. On Linux, use "sudo ./run.sh".'
    try:
        import ctypes
        program, params, folder = relaunch_command(argv)
        code = int(ctypes.windll.shell32.ShellExecuteW(owner or None, 'runas', program, params, folder, 1))
    except Exception as exc:
        return f'Could not restart as Administrator: {exc}'
    if code > 32:                       # ShellExecute returns a value above 32 on success
        return ''
    if code == 5:                       # SE_ERR_ACCESSDENIED: the permission prompt was declined
        return 'The permission prompt was declined, so IDPS keeps running without Administrator rights.'
    return f'Could not restart as Administrator (Windows error {code}).'


# Phrases from the operating system and capture libraries. Kept specific: capture errors often quote the
# interface name or filter the user typed (for example "Npcap Loopback Adapter"), which must not match.
_PERMISSION_PHRASES = ('permission denied', 'access is denied', 'access denied', 'operation not permitted',
                       'requires root', 'you don\'t have permission', 'failed to create queue')
_NO_DRIVER_PHRASES = ('winpcap is not installed', 'npcap is not installed', 'not available at layer 2',
                      'no libpcap', 'libpcap is not available', 'wpcap.dll', 'cannot load npcap')


def capture_error_message(exc: BaseException, gui: bool = True) -> Optional[str]:
    """A plain explanation when live capture failed for missing rights or a missing capture driver, else None."""
    text = str(exc).lower()
    code = getattr(exc, 'errno', None)
    winerror = getattr(exc, 'winerror', None)
    denied = (isinstance(exc, PermissionError) or code in (errno.EPERM, errno.EACCES) or winerror == 5
              or any(p in text for p in _PERMISSION_PHRASES))
    if denied:
        if sys.platform == 'win32':
            if _windows_admin():
                return (f'Live capture was refused even with Administrator rights ({exc}). Check that Npcap is '
                        'installed and that security software is not blocking it.')
            how = ('click "Restart as Administrator" on the Dashboard' if gui
                   else 'start it from an Administrator terminal')
            return f'Live capture needs Administrator rights: {how}.'
        if _linux_root():
            return (f'Live capture was refused even as root ({exc}). In a container, add the NET_RAW and '
                    'NET_ADMIN capabilities.')
        return ('Live capture needs root: start IDPS with "sudo ./run.sh", or give Python the '
                'cap_net_raw,cap_net_admin capabilities.')
    if any(p in text for p in _NO_DRIVER_PHRASES):
        if sys.platform == 'win32':
            return 'Live capture needs Npcap: install it from https://npcap.com and start IDPS again.'
        return 'Live capture needs libpcap: install it with "sudo apt install tcpdump" and try again.'
    return None
