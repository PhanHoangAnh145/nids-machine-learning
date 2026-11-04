@echo off
chcp 65001 >nul
REM Mo giao dien Phan 2 - Traffic Generator & Sender
pushd "%~dp0"
echo [*] Dang mo giao dien Phan 2 ... (can da cai: pip install scapy customtkinter)
python -m traffic_sender
if errorlevel 1 (
  echo.
  echo [!] Neu loi thieu thu vien, chay:  pip install scapy customtkinter
  pause
)
popd
