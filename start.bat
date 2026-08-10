@echo off
chcp 65001 >nul
echo === FSTEC Service (dev) ===
echo.
echo [1/2] Backend...
start "FSTEC Backend" /D "%~dp0backend" cmd /k python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload
echo [2/2] Frontend...
start "FSTEC Frontend" /D "%~dp0frontend" cmd /k npm run dev
echo.
echo Backend: http://127.0.0.1:8765
echo Frontend: http://localhost:5173
echo.
pause
