"""IDPS launcher.

The application lives in the `netsentinel` package (also runnable as `python -m netsentinel`).
Previous single-file versions are kept in the `legacy/` folder for reference.
PyQt6 is only imported on the GUI path, so headless mode works on servers without Qt.
"""
from netsentinel.app import main

if __name__ == '__main__':
    # main() normally exits itself; this keeps the exit code if it ever returns one instead.
    raise SystemExit(main())
