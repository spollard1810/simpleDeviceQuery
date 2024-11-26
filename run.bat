@echo off
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.x from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Checking/Installing requirements...
python -m pip install -r requirements.txt

echo Starting Device Query Maker...
python main.py
pause 