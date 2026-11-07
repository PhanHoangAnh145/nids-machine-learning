@echo off
chcp 65001 >nul
REM Mo dashboard cho may khac cung mang. CHAY BANG QUYEN ADMINISTRATOR.
pushd "%~dp0"
set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
echo [*] NET SHIELD (IPS) - mo cho LAN. Xem mat khau + dia chi o ben duoi.
"%PY%" -m net_shield --lan
if errorlevel 1 ( echo. ^& echo [!] Loi. Kiem tra: pip install scapy scikit-learn pandas joblib ^& pause )
popd
