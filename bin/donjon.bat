@echo off
REM ============================================================
REM Donjon Platform v7.0 - Windows Wrapper
REM Short alias that calls donjon-launcher.bat
REM ============================================================

echo.
echo   Donjon Platform v7.0
echo   Systems Thinking Security Assessment
echo.

call "%~dp0donjon-launcher.bat" %*
exit /b %ERRORLEVEL%
