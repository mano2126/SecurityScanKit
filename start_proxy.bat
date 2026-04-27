@echo off
title SSK Proxy (Port 80)
echo.
echo  Starting SSK Proxy on port 80...
echo  Access: http://[server-ip]  (no port needed)
echo.
cd /d %~dp0
python proxy.py
