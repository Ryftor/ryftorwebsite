@echo off
echo Starting FastAPI server...
call venv\Scripts\activate
python -m uvicorn main:app --reload
pause
