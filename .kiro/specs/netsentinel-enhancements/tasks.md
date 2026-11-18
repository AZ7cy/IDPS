# Implementation Plan

- [x] 1. Qt-free building blocks
  - `settings.py`, `timeline.py`, `simulation.py`, `interfaces.py`; config constants.
  - Switch `SimWorker` to `simulation.generate_round`.
  - _Requirements: E3.1, E3.2, E5, E6.1_

- [x] 2. Store queries
  - Filtered `alerts()`, `alert(id)`, `related_packets()`.
  - _Requirements: E4.2, E9.2_

- [x] 3. Notifications
  - `notify.py`: settings validation, severity filter, rate limits, delivery thread, webhook, syslog.
  - _Requirements: E8.1–E8.5_

- [x] 4. Headless mode and CLI
  - `headless.py`, plus argparse in `app.py` with `--headless`, `--list-interfaces`, `--db` and notification flags.
  - _Requirements: E3.3, E7, E8.6_

- [x] 5. GUI
  - Interface picker, alert filters, detail panel, chart widget, Notifications tab, settings binding, tray notifications.
  - _Requirements: E3, E4, E5, E6, E8.6, E9_

- [x] 6. Documentation
  - `requirements.txt`, `README.md`.
  - _Requirements: E1_

- [x] 7. Test suite
  - `tests/` covering every area listed in E2.1; set up `.venv` and run it.
  - _Requirements: E2_
