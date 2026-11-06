@echo off
chcp 65001 >nul
REM Nen chay bang quyen Administrator (chuot phai > Run as administrator)
pushd "%~dp0\.."
echo [*] Mo NET SHIELD (IPS) - dashboard tai http://127.0.0.1:8081
python -m net_shield
if errorlevel 1 ( echo. & echo [!] Thieu thu vien? chay: pip install scapy scikit-learn pandas joblib customtkinter & pause )
popd
