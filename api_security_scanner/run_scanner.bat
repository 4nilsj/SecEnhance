@echo off
REM API Security Scanner - Windows Batch Runner
REM This script helps run the API Security Scanner on Windows

echo API Security Scanner
echo ===================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher
    pause
    exit /b 1
)

REM Check if main.py exists
if not exist "main.py" (
    echo Error: main.py not found
    echo Please run this script from the API Security Scanner directory
    pause
    exit /b 1
)

REM Run the scanner with provided arguments
python main.py %*

pause
