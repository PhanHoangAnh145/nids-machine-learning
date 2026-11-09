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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    color-scheme:dark;
    --bg:#0B0F17; --surface:#111827; --surface-2:#0E1420; --raised:#1F2937;
    --line:rgba(255,255,255,.07); --line-strong:#374151;
    --text:#E5E7EB; --text-2:#9CA3AF; --text-3:#6B7280;
    --green:#34D399; --red:#F87171; --blue:#60A5FA; --amber:#FBBF24; --orange:#FB923C;
    --font:"Inter","Segoe UI",system-ui,-apple-system,sans-serif;
    --mono:"JetBrains Mono","Fira Code",ui-monospace,Consolas,monospace;
  }
  *{box-sizing:border-box}
  html,body{background:var(--bg)}
  body{margin:0;font-family:var(--font);font-size:13px;line-height:1.45;color:var(--text);
    -webkit-font-smoothing:antialiased}
  svg.i{width:15px;height:15px;flex:none;fill:none;stroke:currentColor;stroke-width:1.75;
    stroke-linecap:round;stroke-linejoin:round}
  .m{font-family:var(--mono);font-variant-numeric:tabular-nums}

  header{height:56px;display:flex;align-items:center;gap:12px;padding:0 24px;
    border-bottom:1px solid var(--line);background:var(--bg)}
  .brand{display:flex;align-items:center;gap:10px;min-width:0}
  .brand .logo{width:28px;height:28px;border-radius:6px;display:grid;place-items:center;
    background:var(--raised);border:1px solid var(--line-strong);color:var(--red)}
  .brand h1{font-size:14px;font-weight:600;margin:0;letter-spacing:.01em}
  .brand .sep{width:1px;height:16px;background:var(--line-strong)}
  .brand .sub{color:var(--text-3);font-size:13px;font-weight:400;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .pill{margin-left:auto;display:inline-flex;align-items:center;gap:8px;height:26px;padding:0 10px;
    border-radius:4px;border:1px solid var(--line);background:var(--surface);
    font-family:var(--mono);font-size:12px;color:var(--text-2);white-space:nowrap}
  .pill::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--text-3);flex:none}
  .pill.on{color:var(--text)}
  .pill.on::before{background:var(--red);box-shadow:0 0 0 3px rgba(248,113,113,.15);animation:pulse 1.4s infinite}
  @keyframes pulse{50%{box-shadow:0 0 0 5px rgba(248,113,113,.04)}}

  .wrap{max-width:860px;margin:0 auto;padding:20px 24px 32px;display:flex;flex-direction:column;gap:16px}
  .panel{background:var(--surface);border:1px solid var(--line);border-radius:6px;overflow:hidden}
  .ph{display:flex;align-items:center;gap:8px;padding:0 16px;height:44px;border-bottom:1px solid var(--line)}
  .ph h2{display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:600;margin:0}
  .ph h2 svg{color:var(--text-2)}
  .ph .hint{color:var(--text-3);font-size:12px;font-weight:400;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
  .body{padding:16px}

  .row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:200px}
  label{display:block;font-size:11px;font-weight:500;letter-spacing:.05em;text-transform:uppercase;color:var(--text-2);margin-bottom:6px}
  input{width:100%;height:36px;padding:0 12px;border-radius:4px;border:1px solid var(--line-strong);
    background:var(--surface-2);color:var(--text);font-family:var(--mono);
    font-variant-numeric:tabular-nums;font-size:13px;outline:none;transition:border-color .15s}
  input:hover{border-color:#4B5563}
  input:focus-visible{border-color:var(--blue);box-shadow:0 0 0 3px rgba(96,165,250,.18)}

  .btns{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px}
  button{display:flex;align-items:flex-start;gap:10px;text-align:left;cursor:pointer;
    border:1px solid var(--line-strong);border-radius:4px;padding:11px 13px;
    background:var(--raised);color:var(--text);font-family:var(--font);
    transition:background .15s,border-color .15s}
  button:hover{background:#273244;border-color:#4B5563}
  button:active{background:#1B2430}
  button:focus-visible{border-color:var(--blue);box-shadow:0 0 0 3px rgba(96,165,250,.18);outline:none}
  button .ico{width:26px;height:26px;flex:none;border-radius:4px;display:grid;place-items:center;
    background:var(--surface-2);border:1px solid var(--line);margin-top:1px}
  button .txt{display:flex;flex-direction:column;gap:2px;min-width:0}
  button .t{font-size:13px;font-weight:600}
  button .d{font-size:11.5px;color:var(--text-3);font-weight:400;line-height:1.35}
  .act-flood .ico{color:var(--red)} .act-scan .ico{color:var(--blue)} .act-slow .ico{color:var(--amber)}
  .btn-stop{grid-column:1/3;justify-content:center;align-items:center;color:var(--text-2)}
  .btn-stop:hover{color:var(--red);border-color:rgba(248,113,113,.45);background:rgba(248,113,113,.06)}
  .btn-stop .t{font-weight:500}

  .kpis{display:grid;grid-template-columns:repeat(3,1fr);background:var(--surface-2);
    border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-top:16px}
  .kpi{padding:12px 16px 13px;border-left:1px solid var(--line)}
  .kpi:first-child{border-left:none}
  .kpi .k{display:flex;align-items:center;gap:7px;font-size:11px;font-weight:500;letter-spacing:.05em;
    text-transform:uppercase;color:var(--text-2)}
  .kpi .k::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--dot,var(--text-3));flex:none}
  .kpi.c-red{--dot:var(--red)} .kpi.c-blue{--dot:var(--blue)}
  .v{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:22px;font-weight:500;
    margin-top:6px;letter-spacing:-.01em;color:var(--text)}
  .v.on{color:#FCA5A5} .v.off{color:var(--text-3)}

  .status{margin-top:14px;font-family:var(--mono);font-variant-numeric:tabular-nums;
    font-size:12px;color:var(--text-2);padding:9px 12px;background:var(--surface-2);
    border:1px solid var(--line);border-radius:4px}
  .warn{display:flex;gap:10px;align-items:flex-start;color:var(--amber);font-size:12.5px;line-height:1.45;
    background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.22);border-radius:6px;padding:12px 14px}
  .warn svg{margin-top:1px}
  @media(max-width:560px){header{padding:0 16px}.wrap{padding:16px}.brand .sub,.brand .sep{display:none}
    .btns{grid-template-columns:1fr}.btn-stop{grid-column:auto}}
</style></head><body>
<header>
  <div class="brand">
    <span class="logo"><svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1"/></svg></span>
    <h1>Lab Attacker</h1>
    <span class="sep"></span>
    <span class="sub">Công cụ kiểm thử net_shield</span>
  </div>
  <span id="pill" class="pill off">Tắt</span>
</header>
<div class="wrap">
  <section class="panel">
    <div class="ph">
      <h2><svg class="i" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>Sinh lưu lượng tấn công</h2>
      <span class="hint">Chỉ nhắm máy của chính bạn</span>
    </div>
    <div class="body">
      <div class="row">
        <div><label>IP đích (máy chạy net_shield)</label>
          <input id="ip" value="192.168.137.1"></div>
        <div><label>Cổng (cho chế độ Flood)</label>
          <input id="port" value="80"></div>
      </div>
      <div class="btns">
        <button class="act-flood" onclick="go('flood')">
          <span class="ico"><svg class="i" viewBox="0 0 24 24"><path d="M3 15h18M6 15a6 6 0 0 1 12 0M12 3v6M9 6l3-3 3 3"/></svg></span>
          <span class="txt"><span class="t">SYN Flood</span><span class="d">Dồn 1 cổng → DoS (chặn tức thì)</span></span></button>
        <button class="act-scan" onclick="go('scan')">
          <span class="ico"><svg class="i" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></span>
          <span class="txt"><span class="t">Quét cổng</span><span class="d">1–2000 → Probe (nhanh)</span></span></button>
        <button class="act-slow" onclick="go('slow')">
          <span class="ico"><svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>
          <span class="txt"><span class="t">Flood chậm</span><span class="d">DoS chậm → đếm bò lên 20/5s rồi chặn</span></span></button>
        <button class="act-slow" onclick="go('slowscan')">
          <span class="ico"><svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>
          <span class="txt"><span class="t">Quét chậm</span><span class="d">Probe chậm → đếm bò lên 20/5s rồi chặn</span></span></button>
        <button class="btn-stop" onclick="stop()">
          <span class="ico"><svg class="i" viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="1.5"/></svg></span>
          <span class="txt"><span class="t">Dừng tấn công</span></span></button>
      </div>
      <div class="kpis">
        <div class="kpi c-red"><div class="k">Trạng thái</div><div class="v off" id="run">—</div></div>
        <div class="kpi"><div class="k">Gói đã bắn</div><div class="v" id="sent">0</div></div>
        <div class="kpi c-blue"><div class="k">Cổng mở gặp</div><div class="v" id="hits">0</div></div>
      </div>
      <div class="status" id="status">Chưa chạy.</div>
    </div>
  </section>

  <div class="warn"><svg class="i" viewBox="0 0 24 24"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>
    <span>Công cụ dành cho phòng lab. Chỉ nhắm máy/mạng bạn sở hữu (ví dụ hotspot của bạn). Không dùng để nhắm máy người khác.</span></div>
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
    $("pill").className="pill "+(s.running?"on":"off");
    $("pill").textContent=s.running?"Đang tấn công":"Tắt";
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
