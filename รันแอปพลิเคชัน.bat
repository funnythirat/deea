@echo off
chcp 65001 >nul 2>&1
title Security Workspace Desktop App
echo =========================================================
echo    Security Workspace Desktop App
echo =========================================================
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in system PATH!
    echo Please install Python from https://www.python.org
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo Starting Security Workspace Desktop App...
echo (A desktop window will open shortly. Do not close this black window while using)
echo.
python "%~dp0desktop_launcher.py"
if errorlevel 1 (
    echo.
    echo [ERROR] Application exited with an error.
    pause
)
