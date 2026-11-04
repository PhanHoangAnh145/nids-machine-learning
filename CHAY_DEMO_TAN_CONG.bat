@echo off
chcp 65001 >nul
REM ======================================================================
REM  Demo NIDS SHIELD - Giam sat & phat hien tan cong (realtime)
REM  Dat file nay o thu muc goc du an, cung cap voi realtime\ va src\
REM ======================================================================
pushd "%~dp0"
echo [*] Thu muc du an: %CD%
echo.
echo [*] Buoc 1: sinh cac kich ban luu luong (ghi ra thu muc pcaps\)
python -m traffic_generator --scenario all --outdir pcaps --target 192.168.1.10 --count 250
echo.
echo [*] Buoc 2: PHAT HIEN TAN CONG - phat lai SYN flood
python -m realtime --replay pcaps\synflood.pcap
echo.
echo [*] Buoc 3: PHAT HIEN TAN CONG - quet cong (nmap -sS)
python -m realtime --replay pcaps\synscan.pcap
echo.
echo [*] Buoc 4: PHAT HIEN TAN CONG - smurf (ICMP flood)
python -m realtime --replay pcaps\smurf.pcap
echo.
echo [*] Buoc 5: luu luong BINH THUONG (kiem tra bao dong gia)
python -m realtime --replay pcaps\normal.pcap
echo.
echo [=] Xong. Nhan phim bat ky de dong.
pause >nul
popd
