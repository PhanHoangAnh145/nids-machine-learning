@echo off
chcp 65001 >nul
REM Chay bang quyen Administrator (chuot phai > Run as administrator)
pushd "%~dp0"
echo [*] NET SHIELD (IPS) - dashboard: http://127.0.0.1:8081
python -m net_shield
if errorlevel 1 ( echo. & echo [!] Loi. Kiem tra: pip install scapy scikit-learn pandas joblib & pause )
popd
