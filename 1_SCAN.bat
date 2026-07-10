@echo off
REM ============================================================================
REM  1_SCAN.bat  -  double-click launcher for scan-engine.ps1
REM
REM  What it does:
REM    1. Asks Windows for Administrator rights (a UAC prompt will pop up).
REM    2. Runs the read-only surveillance scan in PowerShell.
REM    3. Leaves the window open so you can read the results.
REM
REM  Admin rights are recommended so the scan can see ALL user accounts,
REM  services, and scheduled tasks - not just the current user's. The scan
REM  still runs without admin, just with less coverage.
REM ============================================================================

setlocal
cd /d "%~dp0"

REM --- Are we already running as Administrator? ---
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo   Requesting Administrator rights...
    echo   Please click YES on the Windows prompt that appears.
    echo.
    REM Relaunch this same .bat elevated, then exit this non-elevated copy.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
    if %errorlevel% NEQ 0 (
        echo   Could not elevate automatically. Continuing WITHOUT admin rights.
        echo   ^(Coverage will be reduced. To get full coverage, right-click this
        echo    file and choose "Run as administrator".^)
        echo.
        goto :run
    )
    exit /b
)

:run
echo.
echo   Starting the scan. This can take a minute or two...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan-engine.ps1"

REM Fallback pause in case the PowerShell script exits before its own prompt
if %errorlevel% NEQ 0 (
    echo.
    echo   The script exited with an error code ^(%errorlevel%^).
    echo.
    pause
)

endlocal
