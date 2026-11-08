@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================================================
echo   LAB ATTACKER - giao dien web (khong can go lenh)
echo   Mo http://127.0.0.1:8099 -> dien IP -> bam nut
echo   CHI nham may/mang cua chinh ban (vd hotspot 192.168.137.1)
echo ================================================================
python attack_web.py
pause
