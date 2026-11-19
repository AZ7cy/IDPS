"""Administrator/root detection, restarting as Administrator, and plain-language capture errors."""
import errno
import subprocess
import sys

import pytest

import netsentinel.privileges as priv


def test_note_only_when_rights_are_missing(monkeypatch):
    monkeypatch.setattr(priv, 'is_admin', lambda: True)
    assert priv.privilege_note() == '' and not priv.can_restart_as_admin()
    monkeypatch.setattr(priv, 'is_admin', lambda: False)
    note = priv.privilege_note()
    assert ('Administrator' if sys.platform == 'win32' else 'root') in note
    assert 'PCAP replay' in note                                     # says what still works
    assert priv.can_restart_as_admin() == (sys.platform == 'win32')


def test_is_admin_returns_a_bool():
    assert isinstance(priv.is_admin(), bool)


def test_linux_capabilities_count_as_admin(monkeypatch):
    monkeypatch.setattr(priv, 'sys', type('S', (), {'platform': 'linux'}))
    monkeypatch.setattr(priv.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(priv, '_linux_capabilities', lambda: 1 << priv.CAP_NET_RAW)
    assert not priv.is_admin()                                       # capture only, no NFQUEUE
    monkeypatch.setattr(priv, '_linux_capabilities',
                        lambda: (1 << priv.CAP_NET_RAW) | (1 << priv.CAP_NET_ADMIN))
    assert priv.is_admin()
    monkeypatch.setattr(priv.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(priv, '_linux_capabilities', lambda: 0)
    assert priv.is_admin()                                           # root


def test_relaunch_keeps_the_options_and_runs_the_package():
    program, params, folder = priv.relaunch_command(['--db', r'C:\lab files\x.db'])
    assert program == sys.executable and folder == str(priv.PROJECT_DIR)
    assert params == subprocess.list2cmdline(['-m', 'netsentinel', '--db', r'C:\lab files\x.db'])
    assert (priv.PROJECT_DIR / 'netsentinel' / '__main__.py').is_file()


@pytest.mark.skipif(sys.platform != 'win32', reason='ShellExecute is Windows-only')
@pytest.mark.parametrize('code, ok, words', [(42, True, ''), (5, False, 'declined'), (2, False, 'error 2')])
def test_restart_as_admin_reports_the_outcome(monkeypatch, code, ok, words):
    import ctypes
    calls = []

    class Shell:
        @staticmethod
        def ShellExecuteW(*args):
            calls.append(args)
            return code
    monkeypatch.setattr(ctypes, 'windll', type('W', (), {'shell32': Shell}))
    problem = priv.restart_as_admin(['--db', 'x.db'])
    assert (problem == '') is ok and words in problem
    assert calls[0][1] == 'runas' and calls[0][2] == sys.executable and '-m netsentinel --db x.db' in calls[0][3]


@pytest.mark.parametrize('exc', [
    PermissionError('denied'), OSError(errno.EPERM, 'Operation not permitted'),
    RuntimeError('Error opening adapter: Access is denied.'),
])
def test_permission_errors_get_a_plain_message(exc):
    gui, cli = priv.capture_error_message(exc), priv.capture_error_message(exc, gui=False)
    if sys.platform == 'win32':
        assert 'Restart as Administrator' in gui and 'Administrator terminal' in cli
    else:
        assert 'sudo ./run.sh' in gui and 'sudo ./run.sh' in cli


def test_missing_driver_and_other_errors():
    msg = priv.capture_error_message(RuntimeError('Sniffing and sending packets is not available at layer 2: '
                                                  'winpcap is not installed'))
    assert ('npcap.com' if sys.platform == 'win32' else 'libpcap') in msg
    assert priv.capture_error_message(ValueError('bad BPF filter')) is None


def test_capture_thread_errors_are_explained():
    pytest.importorskip('PyQt6')
    from netsentinel.workers import capture_stopped_message
    assert 'unexpectedly' in capture_stopped_message(None)
    assert capture_stopped_message(ValueError('syntax error in filter')) == \
        'Live capture stopped: syntax error in filter'
    assert 'Live capture needs' in capture_stopped_message(PermissionError('denied'))
