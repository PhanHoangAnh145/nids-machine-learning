@echo off
chcp 65001 >nul
set TARGET=192.168.137.1
echo Quet cong bang nmap -> %TARGET%
nmap -sS -T5 -p 1-2000 %TARGET%
pause
