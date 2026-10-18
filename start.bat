@echo off
rem ============================================================================
rem  KazualCipher - one-click launcher (Windows).
rem  First run: creates .venv and installs dependencies (internet required).
rem  Later runs: just starts the GUI.
rem  NOTE: this file MUST stay pure ASCII - cmd.exe parses batch files in the
rem  OEM codepage, so any non-ASCII byte here breaks the whole script.
rem  Russian instructions: see README.md ("Bystoryj start" / quick start).
rem ============================================================================
setlocal
cd /d "%~dp0"

set "VENV_PY=.venv\Scripts\python.exe"

if exist "%VENV_PY%" goto run

echo.
echo  First run: creating virtual environment (.venv) ...
where py >nul 2>nul && (py -3 -m venv .venv) || (python -m venv .venv)
if not exist "%VENV_PY%" (
    echo.
    echo  ERROR: Python 3.9+ not found.
    echo  Install it from https://www.python.org/downloads/
    echo  tick "Add Python to PATH" during installation, then run start.bat again.
    pause
    exit /b 1
)

echo  Installing dependencies ^(PySide6, numpy, argon2-cffi^) ...
echo  This may take a few minutes on the first run.
"%VENV_PY%" -m pip install --upgrade pip
"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  ERROR: dependency installation failed.
    echo  Check your internet connection and run start.bat again.
    pause
    exit /b 1
)

:run
"%VENV_PY%" main.py
if errorlevel 1 (
    echo.
    echo  The program exited with an error - window kept open for diagnostics.
    pause
)
endlocal
