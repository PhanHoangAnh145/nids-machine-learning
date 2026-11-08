"""
CÔNG CỤ TẤN CÔNG CÓ GIAO DIỆN WEB (chỉ dùng trong LAB, nhắm máy của CHÍNH BẠN).

Mục đích: tạo lưu lượng tấn công để KIỂM THỬ net_shield mà KHÔNG phải gõ lệnh
trong CMD/PowerShell. Mở trang web -> điền IP đích -> bấm nút -> tự tấn công.

Chạy hoàn toàn bằng thư viện chuẩn Python (socket), KHÔNG cần nmap, KHÔNG cần
quyền Admin, KHÔNG cần Npcap. Chạy được trên mọi máy Windows có sẵn Python.

    python attack_web.py        # mở http://127.0.0.1:8099

⚠ CHỈ nhắm máy / mạng mà bạn sở hữu (vd hotspot của bạn: 192.168.137.1).
  Dùng để tự kiểm thử hệ thống phòng thủ của mình, không nhắm người khác.
"""
from __future__ import annotations

import socket
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

UI_PORT = 8099          # cổng của trang web điều khiển (trên máy tấn công)
WORKERS = 120           # số luồng bắn song song cho SYN Flood (tốc độ cao)
SLOW_WORKERS = 6        # số luồng cho chế độ "Gửi chậm" (đủ vượt 20/5s, vẫn chậm)

# ---- trạng thái dùng chung -------------------------------------------------
_lock = threading.Lock()
_stop = threading.Event()
_threads: list = []
STATE = {"running": False, "mode": "", "target": "", "port": 0,
         "sent": 0, "hits": 0, "started": 0.0}


def _one_connect(target: str, port: int, timeout: float = 0.5):
    """Mở 1 kết nối TCP (gửi SYN). Cổng đóng/lọc -> vẫn đã gửi SYN = đủ để IDS thấy."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        with _lock:
            STATE["hits"] += 1          # cổng mở (bắt tay thành công)
    except Exception:                    # noqa: BLE001  (đóng/lọc/timeout -> bỏ qua)
        pass
    finally:
        try:
            s.close()
        except Exception:                # noqa: BLE001
            pass
    with _lock:
        STATE["sent"] += 1


def _flood_worker(target: str, port: int):
    """Dội kết nối liên tục tới MỘT cổng (giống SYN flood -> cảnh báo DoS)."""
    while not _stop.is_set():
        _one_connect(target, port)


def _slow_worker(target: str, port: int):
    """Bắn CHẬM nhưng ổn định: timeout ngắn để không bị kẹt ở cổng bị lọc, mỗi
    luồng nghỉ 0.3s. Chạy SLOW_WORKERS luồng -> tổng ~10-12 kết nối/giây, đủ
    vượt ngưỡng 20 trong 5 giây mà vẫn chậm để nhìn bộ đếm bò lên rồi bị chặn."""
    while not _stop.is_set():
        _one_connect(target, port, timeout=0.25)
        time.sleep(0.3)


def _scan_worker(target: str, start_port: int, step: int, max_port: int):
    """Quét dải cổng (mỗi luồng lo một phần; lặp lại -> cảnh báo Probe)."""
    while not _stop.is_set():
        p = start_port
        while p <= max_port and not _stop.is_set():
            _one_connect(target, p)
            p += step


def _slow_scan_worker(target: str, start_port: int, step: int, max_port: int):
    """Quét cổng CHẬM: giống _scan_worker nhưng timeout ngắn + nghỉ 0.3s giữa mỗi
    cổng. Chạy SLOW_WORKERS luồng -> số kết nối (mỗi cổng một kết nối) bò lên tới
    ngưỡng 20/5s rồi mới bị chặn. Ra cảnh báo Probe nếu cổng trả RST (REJ)."""
    while not _stop.is_set():
        p = start_port
        while p <= max_port and not _stop.is_set():
            _one_connect(target, p, timeout=0.25)
            time.sleep(0.3)
            p += step


def _start(mode: str, target: str, port: int):
    """Khởi động tấn công trong nhiều luồng."""
    stop_current()
    _stop.clear()
    with _lock:
        STATE.update(running=True, mode=mode, target=target, port=port,
                     sent=0, hits=0, started=time.time())
    if mode == "slow":
        # vài luồng bắn chậm -> số kết nối tăng từ từ nhưng chắc chắn vượt 20/5s
        for _ in range(SLOW_WORKERS):
            t = threading.Thread(target=_slow_worker, args=(target, port), daemon=True)
            t.start()
            _threads.append(t)
        return
    if mode == "slowscan":
        # quét cổng CHẬM -> bộ đếm Probe bò lên tới ngưỡng rồi chặn
        for i in range(SLOW_WORKERS):
            t = threading.Thread(target=_slow_scan_worker,
                                 args=(target, 1 + i, SLOW_WORKERS, 2000), daemon=True)
            t.start()
            _threads.append(t)
        return
    for i in range(WORKERS):
        if mode == "flood":
            t = threading.Thread(target=_flood_worker, args=(target, port), daemon=True)
        else:  # scan
            t = threading.Thread(target=_scan_worker,
                                 args=(target, 1 + i, WORKERS, 2000), daemon=True)
        t.start()
        _threads.append(t)


def stop_current():
    _stop.set()
    time.sleep(0.2)
    _threads.clear()
    with _lock:
        STATE["running"] = False


# ---- trang web -------------------------------------------------------------
PAGE = """<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab Attacker · kiểm thử net_shield</title>
<style>
:root{--bg:#0f1220;--card:#191d2e;--line:#2a3048;--text:#e8eaf2;--muted:#8b93a7;
--red:#e74c3c;--green:#2ecc71;--blue:#4aa3ff;--orange:#f39c12}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,Segoe UI,sans-serif;
background:var(--bg);color:var(--text)}
.wrap{max-width:720px;margin:0 auto;padding:24px}
h1{font-size:20px}.sub{color:var(--muted);font-size:13px;margin-top:-6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-top:16px}
label{font-size:13px;color:var(--muted)}
input{width:100%;margin-top:6px;padding:10px;border-radius:8px;border:1px solid var(--line);
background:#0f1322;color:var(--text);font-size:15px}
.row{display:flex;gap:12px}.row>div{flex:1}
.btns{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}
button{cursor:pointer;border:none;border-radius:10px;padding:16px;font-size:15px;font-weight:700;color:#fff}
.flood{background:var(--red)}.scan{background:var(--blue)}.slow{background:var(--orange)}.stop{background:#333a52;grid-column:1/3}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}
.tile{background:#0f1322;border:1px solid var(--line);border-radius:10px;padding:14px;text-align:center}
.tile .k{color:var(--muted);font-size:12px}.tile .v{font-size:26px;font-weight:800;margin-top:4px}
.on{color:var(--green)}.off{color:var(--muted)}
.warn{background:rgba(243,156,18,.12);border:1px solid rgba(243,156,18,.4);color:var(--orange);
border-radius:10px;padding:10px 14px;font-size:13px;margin-top:16px}
.status{margin-top:14px;font-size:14px}
</style></head><body><div class="wrap">
<h1>🎯 Lab Attacker</h1>
<p class="sub">Tạo lưu lượng tấn công để kiểm thử net_shield — chỉ nhắm máy của chính bạn.</p>

<div class="card">
  <div class="row">
    <div><label>IP đích (máy chạy net_shield)</label>
      <input id="ip" value="192.168.137.1"></div>
    <div><label>Cổng (cho chế độ Flood)</label>
      <input id="port" value="80"></div>
  </div>
  <div class="btns">
    <button class="flood" onclick="go('flood')">🌊 SYN Flood<br><small>dồn 1 cổng → DoS (chặn tức thì)</small></button>
    <button class="scan" onclick="go('scan')">🔍 Quét cổng<br><small>1–2000 → Probe (nhanh)</small></button>
    <button class="slow" onclick="go('slow')">🐢 Flood chậm<br><small>DoS chậm → đếm bò lên 20/5s rồi chặn</small></button>
    <button class="slow" onclick="go('slowscan')">🐢 Quét chậm<br><small>Probe chậm → đếm bò lên 20/5s rồi chặn</small></button>
    <button class="stop" onclick="stop()">⏹ Dừng tấn công</button>
  </div>
  <div class="tiles">
    <div class="tile"><div class="k">Trạng thái</div><div class="v" id="run">—</div></div>
    <div class="tile"><div class="k">Gói đã bắn</div><div class="v" id="sent">0</div></div>
    <div class="tile"><div class="k">Cổng mở gặp</div><div class="v" id="hits">0</div></div>
  </div>
  <div class="status" id="status">Chưa chạy.</div>
</div>

<div class="warn">⚠ Công cụ dành cho phòng lab. Chỉ nhắm máy/mạng bạn sở hữu
(vd hotspot của bạn). Không dùng để nhắm máy người khác.</div>
</div>
<script>
const $=i=>document.getElementById(i);
async function api(p,b){const o={method:"POST",headers:{"Content-Type":"application/json"}};
  if(b)o.body=JSON.stringify(b);return (await fetch(p,o)).json();}
async function go(mode){
  const ip=$("ip").value.trim(), port=parseInt($("port").value)||80;
  await api("/api/start",{mode,target:ip,port});
}
async function stop(){await api("/api/stop");}
async function tick(){
  try{const s=await (await fetch("/api/state")).json();
    $("run").textContent=s.running?"ĐANG CHẠY":"Tắt";
    $("run").className="v "+(s.running?"on":"off");
    $("sent").textContent=s.sent; $("hits").textContent=s.hits;
    if(s.running){
      const sec=((Date.now()/1000)-s.started)||1;
      const rate=Math.round(s.sent/Math.max(sec,1));
      const names={flood:"SYN Flood",slow:"Flood chậm",scan:"Quét cổng",slowscan:"Quét chậm"};
      const nm=names[s.mode]||s.mode;
      const showPort=(s.mode==="flood"||s.mode==="slow");
      $("status").textContent=`Chế độ ${nm} → ${s.target}`
        +(showPort?`:${s.port}`:"")+` · ~${rate} gói/giây`;
    } else if(s.sent>0){$("status").textContent=`Đã dừng. Tổng đã bắn: ${s.sent} gói.`;}
  }catch(e){}
}
setInterval(tick,700); tick();
</script></body></html>"""


class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # tắt log rác
        pass

    def _send(self, body: bytes, ctype="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        import json
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return {}

    def do_GET(self):
        import json
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(PAGE.encode("utf-8"), "text/html")
        elif path == "/api/state":
            with _lock:
                self._send(json.dumps(STATE).encode("utf-8"))
        else:
            self._send(b'{"error":"not found"}')

    def do_POST(self):
        import json
        path = urlparse(self.path).path
        body = self._read_json()
        if path == "/api/start":
            m = body.get("mode")
            mode = m if m in ("flood", "scan", "slow", "slowscan") else "scan"
            target = str(body.get("target", "")).strip()
            port = int(body.get("port", 80) or 80)
            if not target:
                self._send(b'{"ok":false,"msg":"thieu IP"}')
                return
            _start(mode, target, port)
            self._send(json.dumps({"ok": True}).encode("utf-8"))
        elif path == "/api/stop":
            stop_current()
            self._send(b'{"ok":true}')
        else:
            self._send(b'{"error":"not found"}')


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run():
    srv = _Server(("127.0.0.1", UI_PORT), _H)
    url = f"http://127.0.0.1:{UI_PORT}"
    print(f"[attacker] Giao dien: {url}")
    print("[attacker] Mo trinh duyet, dien IP dich roi bam nut. Ctrl+C de thoat.")
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        stop_current()
        srv.shutdown()


if __name__ == "__main__":
    run()
