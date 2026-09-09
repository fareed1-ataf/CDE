@echo off
title Cyber Data Engine v4.0
color 0b
echo.
echo  =====================================================
echo   CYBER DATA ENGINE v4.0  ^|  Web Interface
echo  =====================================================
echo.
echo  [*] Starting FastAPI backend...
echo  [*] Open your browser at:  http://localhost:8080
echo  [*] API Docs available at: http://localhost:8080/api/docs
echo.
echo  Press Ctrl+C to stop the server.
echo.

cd /d "%~dp0"

:: Try running with uvicorn directly
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8080 --reload

pause
