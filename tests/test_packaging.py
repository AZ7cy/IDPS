"""Packaging checks: one source of dependency ranges, a lock that agrees with it, and a headless entry point
that works without the GUI toolkit."""
import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict:
    tomllib = pytest.importorskip('tomllib')          # Python 3.11+
    return tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))


def _lock() -> dict:
    pins = {}
    for line in (ROOT / 'requirements-lock.txt').read_text(encoding='utf-8').splitlines():
        m = re.match(r'^([A-Za-z0-9_.-]+)==([^\s;\\]+)', line)
        if m:
            pins[re.sub(r'[-_.]+', '-', m.group(1)).lower()] = m.group(2)
    return pins


def test_lock_pins_satisfy_the_pyproject_ranges():
    requirements = pytest.importorskip('packaging.requirements')
    project = _pyproject()['project']
    declared = list(project['dependencies'])
    for extra in ('gui', 'ips'):
        declared += project['optional-dependencies'][extra]
    pins = _lock()
    for text in declared:
        req = requirements.Requirement(text)
        name = re.sub(r'[-_.]+', '-', req.name).lower()
        assert name in pins, f'{req.name} is declared in pyproject.toml but not pinned in requirements-lock.txt'
        assert req.specifier.contains(pins[name], prereleases=True), \
            f'requirements-lock.txt pins {req.name}=={pins[name]}, outside pyproject.toml range {req.specifier}'


def test_lock_is_hash_checked():
    text = (ROOT / 'requirements-lock.txt').read_text(encoding='utf-8')
    blocks = re.split(r'\n(?=[A-Za-z0-9])', text.split('\n', 4)[-1])
    pinned = [b for b in blocks if '==' in b.split('\n', 1)[0]]
    assert pinned and all('--hash=sha256:' in b for b in pinned)


def test_requirements_files_do_not_repeat_version_ranges():
    for name in ('requirements.txt', 'requirements-dev.txt'):
        lines = [ln.split('#', 1)[0].strip() for ln in (ROOT / name).read_text(encoding='utf-8').splitlines()]
        lines = [ln for ln in lines if ln]
        assert lines and all(ln.startswith('-e .[') for ln in lines), (name, lines)


def test_version_is_a_plain_literal():
    """setuptools' dynamic version reads netsentinel.__version__ statically; that needs a literal."""
    tree = ast.parse((ROOT / 'netsentinel' / '__init__.py').read_text(encoding='utf-8'))
    values = [n.value for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == '__version__' for t in n.targets)]
    assert len(values) == 1 and isinstance(values[0], ast.Constant) and isinstance(values[0].value, str)


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, timeout=120)


def test_importing_the_entry_point_does_not_load_qt():
    result = _run('import sys, netsentinel.app; print("PyQt6" in sys.modules)')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'False'


def test_module_help_runs_without_qt():
    result = subprocess.run([sys.executable, '-m', 'netsentinel', '--help'], cwd=ROOT, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert '--headless' in result.stdout
