@echo off
REM ============================================================
REM Donjon Platform v7.0 - Windows Launcher
REM Finds Python and runs bin/donjon-launcher
REM ============================================================

setlocal

REM Try venv first, then system Python
set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."

if exist "%ROOT_DIR%\venv\Scripts\python.exe" (
    "%ROOT_DIR%\venv\Scripts\python.exe" "%SCRIPT_DIR%donjon-launcher" %*
) else (
    python "%SCRIPT_DIR%donjon-launcher" %*
)

exit /b %ERRORLEVEL%
