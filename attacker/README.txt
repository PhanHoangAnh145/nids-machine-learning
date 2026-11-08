LAB ATTACKER - cong cu tao luu luong tan cong de kiem thu net_shield
====================================================================
CHI dung trong lab, CHI nham may/mang cua chinh ban (vd hotspot 192.168.137.1).

Dat thu muc "attacker" nay tren MAY TAN CONG (may KHAC voi may chay net_shield,
da noi cung hotspot/mang voi may do).

CACH 1 - Giao dien web (can co Python tren may tan cong):
  - Bam dup TAN_CONG_WEB.bat
  - Trinh duyet mo http://127.0.0.1:8099
  - Dien IP dich (vd 192.168.137.1), chon cong, bam:
       * SYN Flood  -> doi 1 cong (ra canh bao DoS)
       * Quet cong  -> 1..2000 (ra canh bao Probe)
  - Bam Dung de ngung.

CACH 2 - Dung nmap (KHONG can Python, chi can da cai nmap):
  - Bam dup TAN_CONG_FLOOD_NMAP.bat     (flood manh, de bi chan)
  - Bam dup TAN_CONG_QUETCONG_NMAP.bat  (quet cong)
  - Muon doi IP dich: chuot phai .bat -> Edit -> sua dong "set TARGET=..."
  - Nen chay "Run as administrator".

LUU Y net_shield:
  - Flood nen nham cong DONG/LOC (vd 80 tren may co firewall) -> ra DoS.
    Neu cong dang MO, bat tay thanh cong se bi coi la "binh thuong";
    khi do doi cong khac hoac dung che do Quet cong.
