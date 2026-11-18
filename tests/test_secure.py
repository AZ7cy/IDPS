"""Owner-only permissions on Windows (ACL) and POSIX (mode bits)."""
import os
import stat
import subprocess
import sys

import pytest

import netsentinel.secure as secure


def test_windows_acl_arguments_remove_inheritance_and_use_sids():
    args = secure.windows_acl_args('C:/x/settings.json', False, 'S-1-5-21-1-2-3-1001')
    assert args[:3] == ['icacls', 'C:/x/settings.json', '/inheritance:r']
    assert '*S-1-5-21-1-2-3-1001:F' in args and '*S-1-5-18:F' in args and '*S-1-5-32-544:F' in args
    assert '*S-1-5-21-1-2-3-1001:(OI)(CI)F' in secure.windows_acl_args('C:/x', True, 'S-1-5-21-1-2-3-1001')


def test_files_in_the_data_folder_protect_the_folder_once(tmp_path, monkeypatch):
    monkeypatch.setattr(secure, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(secure, 'sys', type('S', (), {'platform': 'win32'}))
    monkeypatch.setattr(secure, '_done', set())
    monkeypatch.setattr(secure, 'current_user_sid', lambda: 'S-1-5-21-9')
    calls = []
    monkeypatch.setattr(secure, '_run', lambda a: calls.append(a) or subprocess.CompletedProcess(a, 0))
    (tmp_path / 'settings.json').write_text('{}')
    (tmp_path / 'rules').mkdir()
    (tmp_path / 'rules' / 'local.rules').write_text('')
    assert secure.restrict_to_owner(tmp_path / 'settings.json')
    assert secure.restrict_to_owner(tmp_path / 'rules' / 'local.rules')
    assert len(calls) == 1 and calls[0][1] == str(tmp_path)        # one icacls call, on the folder
    outside = tmp_path.parent / f'{tmp_path.name}-export.jsonl'
    outside.write_text('')
    try:
        assert secure.restrict_to_owner(outside) and calls[-1][1] == str(outside)
    finally:
        outside.unlink()
    assert not secure.restrict_to_owner(tmp_path / 'missing.db')


def _sddl_dacl(path) -> tuple[str, set[str]]:
    """(DACL flags, trustee SIDs of allow entries) from `icacls /save`, which writes SDDL: SIDs, not
    account names, so the check does not depend on the Windows language."""
    import re
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        saved = os.path.join(tmp, 'acl.txt')
        subprocess.run(['icacls', str(path), '/save', saved, '/q'], check=True, capture_output=True)
        raw = open(saved, 'rb').read()
    sddl = raw.decode('utf-16-le', 'replace') if raw[:1] != b'D' else raw.decode('ascii', 'replace')
    dacl = sddl[sddl.index('D:') + 2:]
    flags = dacl.split('(', 1)[0]
    trustees = {m.group(2) for m in re.finditer(r'\((A|D);[^;]*;[^;]*;[^;]*;[^;]*;([^;)]+)', dacl)
                if m.group(1) == 'A'}
    denies = re.findall(r'\(D;', dacl)
    assert not denies, sddl
    return flags, trustees


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows ACLs')
def test_real_acl_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setattr(secure, 'DATA_DIR', tmp_path / 'data')
    monkeypatch.setattr(secure, '_done', set())
    target = tmp_path / 'secret.json'
    target.write_text('{}')
    assert secure.restrict_to_owner(target)
    flags, trustees = _sddl_dacl(target)
    assert 'P' in flags, flags                                  # protected: nothing inherited from the folder
    # Only this account, SYSTEM, Administrators and OWNER RIGHTS (the file's owner, added on some systems).
    allowed = {secure.current_user_sid(), 'SY', 'S-1-5-18', 'BA', 'S-1-5-32-544', 'OW', 'S-1-3-4'}
    assert trustees and trustees <= allowed, trustees


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX mode bits')
def test_posix_mode_is_owner_only(tmp_path):
    target = tmp_path / 'secret.json'
    target.write_text('{}')
    assert secure.restrict_to_owner(target)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
