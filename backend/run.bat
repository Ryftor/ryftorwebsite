@echo off
echo Starting FastAPI backend...

:: Start FastAPI backend in a new window, listening on all interfaces (0.0.0.0)
start "FastAPI Server" cmd /k python -m uvicorn main:app --host 0.0.0.0 --port 8000

:: Wait a few seconds to let the server start
timeout /t 5 /nobreak >nul

:: Open the frontend index.html in default browser
start "" "static\index.html"

echo Backend and Frontend started.
pause
