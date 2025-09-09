@echo off
setlocal enabledelayedexpansion

REM Change to script directory
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found. Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

echo [1/4] Creating virtual environment (venv)...
if not exist venv (
    python -m venv venv
) else (
    echo venv already exists
)

echo [2/4] Upgrading pip...
venv\Scripts\python.exe -m pip install --upgrade pip

echo [3/4] Installing dependencies...
venv\Scripts\pip.exe install --disable-pip-version-check --no-input flask flask-cors webauthn python-dotenv

echo [4/4] Starting Flask server on http://localhost:5000 ...
venv\Scripts\python.exe app.py

pause