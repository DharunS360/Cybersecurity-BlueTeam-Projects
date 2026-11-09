@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating project virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo Failed to create virtual environment. Install Python 3.11 or newer.
        pause
        exit /b 1
    )
)
echo [2/3] Installing or updating required packages...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed. Check your internet connection and Python installation.
    pause
    exit /b 1
)
echo [3/3] Starting SysmonHunter...
echo Running as the current user. The local web server will NOT request Administrator privileges.
echo Protected live channels may be denied; upload an authorized EVTX export when required.
".venv\Scripts\python.exe" app.py
pause
