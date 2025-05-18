@echo off
echo Starting FastAPI backend...

:: Activate virtual environment if using one
call venv\Scripts\activate

:: Start FastAPI backend in a new window
start "FastAPI Server" cmd /k python -m uvicorn main:app --host  192.168.1.96 --port 8000

:: Wait a couple seconds to let the server start
timeout /t 3

:: Open the frontend index.html in default browser
start static\index.html

echo Backend and Frontend started.
pause
