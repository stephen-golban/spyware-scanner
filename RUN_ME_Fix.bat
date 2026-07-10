@echo off
REM ============================================================================
REM  RUN_ME_Fix.bat  -  launches the guided remediation tool (asks before every
REM  change; everything is reversible with UNDO_Fix.bat).
REM  Administrator rights are required to make changes.
REM ============================================================================
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo   Requesting Administrator rights - please click YES.
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
    if %errorlevel% NEQ 0 (
        echo   Could not elevate automatically. Right-click this file and choose
        echo   "Run as administrator".
        echo.
        pause
    )
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix-Surveillance.ps1"
if %errorlevel% NEQ 0 (
    echo.
    echo   The tool exited with an error code ^(%errorlevel%^).
    echo.
    pause
)
endlocal
