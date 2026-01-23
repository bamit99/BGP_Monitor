@echo off
echo BGP Monitor Installation Script for Windows
echo ===========================================

REM Check if conda is installed
where conda >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Conda is not installed or not in PATH.
    echo Please install Miniconda or Anaconda first from: https://docs.conda.io/en/latest/miniconda.html
    pause
    exit /b 1
)

echo Creating conda environment 'bgpmon' with Python 3.11...
conda create -n bgpmon python=3.11 -y
if %errorlevel% neq 0 (
    echo ERROR: Failed to create conda environment.
    pause
    exit /b 1
)

echo Activating environment and installing requirements...
call conda activate bgpmon
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate conda environment.
    pause
    exit /b 1
)

pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install requirements.
    pause
    exit /b 1
)

echo.
echo Installation completed successfully!
echo.
echo To use the BGP Monitor:
echo 1. Run: conda activate bgpmon
echo 2. Run: python main.py
echo.
echo For Neo4j setup, refer to the README.md file.
echo.
pause