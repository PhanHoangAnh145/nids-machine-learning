@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo   NET SHIELD - TU KIEM THU DUONG CANH BAO XAM NHAP
echo   (sinh tan cong gia lap -> mo hinh phat hien -> dashboard)
echo   Dashboard: http://127.0.0.1:8081   (Ctrl+C de dung)
echo ============================================================
python -m net_shield.selftest
pause
