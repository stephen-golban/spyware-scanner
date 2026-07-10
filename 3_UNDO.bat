@echo off
REM ============================================================================
REM  3_UNDO.bat  -  reverses every change made by 2_FIX.bat, using the
REM  undo journal (restores settings, re-enables services/tasks, and moves any
REM  quarantined files back). Requires Administrator rights.
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

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-engine.ps1" -Undo
if %errorlevel% NEQ 0 (
    echo.
    echo   The tool exited with an error code ^(%errorlevel%^).
    echo.
    pause
)
endlocal
