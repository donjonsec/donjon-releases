@echo off
REM ============================================================
REM Donjon Platform v7.0 - One-Click Start
REM Double-click this file to set up and launch the platform.
REM ============================================================

call "%~dp0bin\donjon-launcher.bat" %*
exit /b %ERRORLEVEL%
