@echo off
title DFIP Investigator - Forensic Workstation
echo ========================================================
echo    DFIP INVESTIGATOR - DIGITAL FORENSICS WORKSTATION
echo ========================================================
echo Launching standalone forensic desktop window...

where msedge.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
    start "" msedge.exe --app="http://127.0.0.1:1420" --window-size=1440,920 --user-data-dir="%APPDATA%\DFIP\DesktopProfile"
    exit /b 0
)

where chrome.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
    start "" chrome.exe --app="http://127.0.0.1:1420" --window-size=1440,920 --user-data-dir="%APPDATA%\DFIP\DesktopProfile"
    exit /b 0
)

start http://127.0.0.1:1420
exit /b 0
