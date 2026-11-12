@echo off
title Custody Watch - Live System Launcher
cd /d "%~dp0backend"

echo ===================================================================
echo               CUSTODY WATCH - FULL PLATFORM LAUNCHER
echo ===================================================================
echo [1/2] Starting Backend Server (Port 8000 API & Port 9001 GPS Receiver)...
if exist "..\venv\Scripts\python.exe" (
    start "Custody Watch Backend (Port 8000 & 9001)" "..\venv\Scripts\python.exe" run_server.py
) else (
    start "Custody Watch Backend (Port 8000 & 9001)" python run_server.py
)

echo Waiting for backend server to initialize...
timeout /t 4 /nobreak >nul

echo Check your Chrome tabs:
echo   - Swagger Docs: http://127.0.0.1:8000/docs
echo   - Web App Map : https://custody-band-a8f59.web.app/admin/dashboard
echo ===================================================================
if /I "%~1"=="--simulate" (
    echo Starting demo GPS stream on a separate simulator device...
    if exist "..\venv\Scripts\python.exe" (
        "..\venv\Scripts\python.exe" simulate_gps.py --loop
    ) else (
        python simulate_gps.py --loop
    )
) else (
    echo Demo GPS stream is off. Only real watch telemetry will update device locations.
    echo To run an isolated demo stream, start this script with --simulate.
)

pause
