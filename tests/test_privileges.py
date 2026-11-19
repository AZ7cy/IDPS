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
    monkeypatch.setattr(priv, '_linux_root', lambda: False)
    monkeypatch.setattr(priv, '_linux_capabilities', lambda: 1 << priv.CAP_NET_RAW)
    assert not priv.is_admin()                                       # capture only, no NFQUEUE
    monkeypatch.setattr(priv, '_linux_capabilities',
                        lambda: (1 << priv.CAP_NET_RAW) | (1 << priv.CAP_NET_ADMIN))
    assert priv.is_admin()
    monkeypatch.setattr(priv, '_linux_root', lambda: True)
    monkeypatch.setattr(priv, '_linux_capabilities', lambda: 0)
    assert priv.is_admin()                                           # root


def test_relaunch_keeps_the_options_and_the_working_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                                      # so a relative --db means the same file
    program, params, folder = priv.relaunch_command(['--db', r'lab files\x.db'], console=True)
    assert program == sys.executable and folder == str(tmp_path)
    assert params == subprocess.list2cmdline([str(priv.LAUNCHER), '--db', r'lab files\x.db'])
    monkeypatch.setattr(priv, 'LAUNCHER', tmp_path / 'missing.py')    # installed package: no launcher file
    assert priv.relaunch_command([], console=True)[1] == '-m netsentinel'


def test_relaunch_uses_the_windowless_python(tmp_path, monkeypatch):
    (tmp_path / 'python.exe').write_bytes(b'')
    monkeypatch.setattr(priv.sys, 'executable', str(tmp_path / 'python.exe'))
    assert priv.relaunch_command([], console=True)[0] == str(tmp_path / 'python.exe')
    assert priv.relaunch_command([])[0] == str(tmp_path / 'python.exe')       # no pythonw.exe: keep python
    (tmp_path / 'pythonw.exe').write_bytes(b'')
    assert priv.relaunch_command([])[0] == str(tmp_path / 'pythonw.exe')


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
    problem = priv.restart_as_admin(['--db', 'x.db'], owner=1234)
    assert (problem == '') is ok and words in problem
    owner, verb, program, params, _folder, _show = calls[0]
    assert owner == 1234 and verb == 'runas' and program == priv.relaunch_command([])[0]
    assert params.endswith('--db x.db')


@pytest.mark.parametrize('exc', [
    PermissionError('denied'), OSError(errno.EPERM, 'Operation not permitted'),
    RuntimeError('Error opening adapter: Access is denied.'),
])
def test_permission_errors_get_a_plain_message(exc, monkeypatch):
    monkeypatch.setattr(priv, '_windows_admin', lambda: False)
    monkeypatch.setattr(priv, '_linux_root', lambda: False)
    gui, cli = priv.capture_error_message(exc), priv.capture_error_message(exc, gui=False)
    assert gui is not None and cli is not None
    if sys.platform == 'win32':
        assert 'Restart as Administrator' in gui and 'Administrator terminal' in cli
    else:
        assert 'sudo ./run.sh' in gui and 'sudo ./run.sh' in cli


def test_already_elevated_users_are_not_told_to_elevate(monkeypatch):
    monkeypatch.setattr(priv, '_windows_admin', lambda: True)
    monkeypatch.setattr(priv, '_linux_root', lambda: True)
    msg = priv.capture_error_message(PermissionError('Operation not permitted'))
    assert msg is not None and 'even' in msg and 'Restart as Administrator' not in msg and 'sudo' not in msg


@pytest.mark.parametrize('text', [
    "Interface 'Npcap Loopback Adapter' not found !",          # an interface name, not a missing driver
    'syntax error in filter expression: host administrator',  # a word in the user's own filter
    'Interface privilege-net is down',
])
def test_user_text_does_not_trigger_the_hints(text):
    assert priv.capture_error_message(RuntimeError(text)) is None


def test_missing_driver_and_other_errors():
    msg = priv.capture_error_message(RuntimeError('Sniffing and sending packets is not available at layer 2: '
                                                  'winpcap is not installed'))
    assert msg is not None
    assert ('npcap.com' if sys.platform == 'win32' else 'libpcap') in msg
    assert priv.capture_error_message(ValueError('bad BPF filter')) is None


def test_capture_thread_errors_are_explained():
    pytest.importorskip('PyQt6')
    from netsentinel.workers import capture_stopped_message
    assert 'unexpectedly' in capture_stopped_message(None)
    assert capture_stopped_message(ValueError('syntax error in filter')) == \
        'Live capture stopped: syntax error in filter'
    assert 'Live capture' in capture_stopped_message(PermissionError('denied'))


def test_linux_capture_only_capability(monkeypatch):
    monkeypatch.setattr(priv, 'sys', type('S', (), {'platform': 'linux'}))
    monkeypatch.setattr(priv, '_linux_root', lambda: False)
    monkeypatch.setattr(priv, '_linux_capabilities', lambda: 1 << priv.CAP_NET_RAW)
    assert priv.can_capture() and not priv.is_admin()
    assert 'Live capture works' in priv.privilege_note()
