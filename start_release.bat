@echo off
title SecurityScanKit - Release Mode

echo.
echo  =============================================
echo    SecurityScanKit v1.0  Release Mode
echo  =============================================
echo.

cd /d %~dp0

:: --- Find and use existing ssk.db ---
if exist "data\ssk.db" (
    echo  [OK] Found existing database: data\ssk.db
) else (
    echo  [INFO] No existing database found, new one will be created
)
echo.

:: --- Step 1: Frontend Build ---
echo [1/3] Building frontend... (first time: 1-2 min)
cd frontend
call npm run build
if errorlevel 1 (
    echo  [ERROR] Frontend build failed! Try: npm install
    pause
    exit /b 1
)
cd ..
echo  [OK] Frontend build done
echo.

:: --- Step 2: Start Backend (working dir = backend, DB path resolved correctly) ---
echo [2/3] Starting backend server...
set ROOT=%~dp0
start "SSK Backend" cmd /k "cd /d %ROOT%backend && uvicorn main:app --host 0.0.0.0 --port 8000 --log-config log_config.json"
echo  [OK] Backend started
echo.

:: --- Step 3: Done ---
echo [3/3] Ready!
echo.
echo  +------------------------------------------+
echo  ^|  DB path  : %ROOT%data\ssk.db
echo  ^|  This PC  : http://localhost:8000         ^|
echo  ^|  Other PC : http://[server-ip]:8000       ^|
echo  ^|  Check IP : ipconfig                      ^|
echo  +------------------------------------------+
echo.
pause
