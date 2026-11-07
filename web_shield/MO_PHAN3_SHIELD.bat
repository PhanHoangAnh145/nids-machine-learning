@echo off
chcp 65001 >nul
pushd "%~dp0\.."
echo [*] Mo web server mau o cua so khac... (http://127.0.0.1:8000)
start "Web demo" cmd /k python -m web_shield.demo_backend
timeout /t 2 >nul
echo [*] Mo giao dien La chan (Phan 3)...
python -m web_shield
if errorlevel 1 ( echo. & echo [!] Thieu thu vien? chay: pip install customtkinter & pause )
popd
