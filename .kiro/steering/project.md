---
inclusion: always
---
# IDPS project conventions

IDPS is a Python intrusion detection and prevention system. The code lives in the `netsentinel/` package;
`idps.py` is the launcher. Follow these rules in every change.

## Structure
- Only `gui.py`, `workers.py`, `sig_gui.py`, `wifi_gui.py`, `charts.py` and `splash.py` may import PyQt6
  at module level; `app.py` imports it only inside `run_gui()`. Everything else must stay Qt-free, so
  headless mode (`--headless`) runs on servers without Qt. `tests/test_packaging.py` checks that importing
  `netsentinel.app` does not load PyQt6.
- Dependency version ranges are declared only in `pyproject.toml`. `requirements.txt` and
  `requirements-dev.txt` only install the project (`-e .[...]`). After changing a range, regenerate
  `requirements-lock.txt` with `python tools/make_lock.py`.
- Keep `__version__` in `netsentinel/__init__.py` a plain string literal (setuptools reads it statically).

## Safety
- Never read or write the user's real data in `~/.netsentinel` from tests or probes. Tests use temporary
  databases and settings; `tests/conftest.py` redirects the rule files.
- The inline IPS must stay opt-in: dry-run on by default, and never block local, gateway or trusted addresses.
- Treat packets, rule files, feeds and downloads as untrusted input: bound sizes and times, and fail closed
  (a pcre timeout counts as a match, not a miss).
- Never put secrets, real IP addresses, MAC addresses or Wi-Fi network names in code, tests or commits.
  Use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).

## GUI
- Never block the GUI thread: database reads that can be slow, downloads, rule loading and scans run on
  worker threads and report back through Qt signals.
- In GUI tests, monkeypatch `QMessageBox.question` (and the other dialogs), or the test run hangs.

## Checks before committing
Run, from the project folder:
```powershell
.\.venv\Scripts\python.exe -m pyflakes netsentinel tests tools idps.py
.\.venv\Scripts\python.exe -m pytest -q
```
Both must pass. CI runs the same on Windows and Ubuntu with Python 3.10 and 3.14.

## Writing
User-facing text (UI, errors, README) is plain English: say what happened and what to do next, with the
exact button or command.
