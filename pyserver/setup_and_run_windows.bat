@echo off
setlocal enabledelayedexpansion

REM Change to script directory
cd /d %~dp0

REM Check Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
  echo [ERROR] Python not found in PATH. Install Python 3.10+ and try again.
  echo.
  pause
  exit /b 1
)

:menu
cls
echo =============================================
echo   Fingerprint 2FA Python Server - Windows
echo =============================================
echo   1 ^) Start server
echo   2 ^) Install / Update requirements
echo   3 ^) Exit
echo.
choice /c 123 /n /m "Select option (1-3): "
if errorlevel 3 goto :eof
if errorlevel 2 goto install
if errorlevel 1 goto start

:start
if not exist venv (
  echo [WARN] venv not found. Run option 2 first to install requirements.
  echo.
  pause
  goto menu
)
echo [INFO] Starting Flask server on http://localhost:5000
echo [INFO] Press Ctrl+C to stop and return to menu.
call venv\Scripts\python app.py
echo.
pause
goto menu

:install
echo [1/3] Creating virtual environment (venv) if missing...
if not exist venv (
  python -m venv venv
) else (
  echo venv already exists
)

echo [2/3] Upgrading pip...
call venv\Scripts\python -m pip install --upgrade pip

echo [3/3] Installing required packages (flask, flask-cors, webauthn)...
call venv\Scripts\pip install --disable-pip-version-check --no-input flask flask-cors webauthn
if %ERRORLEVEL% neq 0 (
  echo [ERROR] Failed to install Python dependencies.
  echo.
  pause
  goto menu
)

echo [DONE] Requirements installed/updated.
echo.
pause
goto menu
