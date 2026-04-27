@echo off
title SecurityScanKit Launcher
cd /d %~dp0
echo.
echo ====================================================
echo   SecurityScanKit v2.0
echo ====================================================
echo.
python --version > nul 2>&1
if errorlevel 1 goto nopython
echo [OK] Python found
echo.
if "%1"=="stop"   goto stop
if "%1"=="status" goto status
if "%1"=="config" goto showconfig
goto start
:start
python launch.py start
pause
exit /b 0
:stop
python launch.py stop
pause
exit /b 0
:status
python launch.py status
pause
exit /b 0
:showconfig
python launch.py config
pause
exit /b 0
:nopython
echo ERROR: Python not found.
echo Install Python 3.10+ from https://www.python.org/downloads/
pause
exit /b 1
