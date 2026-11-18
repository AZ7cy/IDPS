@echo off
rem Start IDPS with the project's virtual environment. Extra arguments are passed through.
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo IDPS's virtual environment was not found in "%~dp0.venv".
    echo Create it once from this folder with:
    echo     python -m venv .venv
    echo     .venv\Scripts\python.exe -m pip install -r requirements.txt
    exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0idps.py" %*
