@echo off
chcp 65001 >nul
title วิถีป้องกันรอบด้าน - Security Workspace Desktop App
echo =========================================================
echo    วิถีป้องกันรอบด้าน - Security Workspace Desktop App
echo =========================================================
echo.
echo กำลังตรวจสอบ Python ในเครื่อง...
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] ไม่พบ Python ในระบบ กรุณาติดตั้ง Python จาก python.org
    pause
    exit /b 1
)

echo กำลังเปิดหน้าต่าง Desktop App...
python "%~dp0desktop_launcher.py"
