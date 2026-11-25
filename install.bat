@echo off
rem gocmd installer for people who used "git clone" or downloaded the ZIP.
rem Easier option: download the .msi from GitHub Releases - it needs nothing else.
setlocal
cd /d "%~dp0"
echo === gocmd setup ===

where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo Python is not installed.
    echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
    echo or use the .msi from https://github.com/Margrina/gocmd/releases instead.
    echo.
    pause
    exit /b 1
)

echo Installing libraries...
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo Could not install the libraries. Check your internet connection and try again.
    pause
    exit /b 1
)

python gocmd.py --install
if errorlevel 1 (
    pause
    exit /b 1
)
echo.
echo All set. Open a NEW CMD window and type:  gocmd -u NAME --new
pause
