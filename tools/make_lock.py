"""Regenerate requirements-lock.txt from pyproject.toml with hashes.

    python tools/make_lock.py [pip-compile options, e.g. --upgrade-package "regex==2026.11.7"]

Runs pip-compile, restores the Windows-only marker on pydivert (pip-compile drops markers) and writes the
header. Let new releases age a week or two before locking them, then run the tests.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'requirements-lock.txt'
MARKERS = {'pydivert': 'sys_platform == "win32"'}
HEADER = f"""\
# Exact, hash-checked versions the test suite last passed with (Python {sys.version.split()[0]}, {sys.platform}).
# Install:    pip install --require-hashes -r requirements-lock.txt
#   and then: pip install --no-deps -e .
# Regenerate: python tools/make_lock.py   (pyproject.toml is the only place version ranges are declared)
"""


def main(argv: list[str]) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / 'lock.txt'
        cmd = [sys.executable, '-m', 'piptools', 'compile', '--quiet', '--generate-hashes', '--strip-extras',
               '--no-header', '--extra', 'gui', '--extra', 'ips', '-o', str(out), *argv, 'pyproject.toml']
        result = subprocess.run(cmd, cwd=ROOT)
        if result.returncode:
            return result.returncode
        lines = out.read_text(encoding='utf-8').splitlines()
    fixed = []
    for line in lines:
        m = re.match(r'^([A-Za-z0-9_.-]+)==(\S+) \\$', line)
        if m and m.group(1).lower() in MARKERS:
            line = f'{m.group(1)}=={m.group(2)} ; {MARKERS[m.group(1).lower()]} \\'
        fixed.append(line)
    LOCK.write_text(HEADER + '\n'.join(fixed).rstrip() + '\n', encoding='utf-8', newline='\n')
    print(f'wrote {LOCK}')
    return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    raise SystemExit(main(sys.argv[1:]))
