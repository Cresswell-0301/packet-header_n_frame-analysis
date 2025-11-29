import os, sys, asyncio, subprocess
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Optional deps
try: import pandas as pd
except Exception: pd = None
try: import numpy as np
except Exception: np = None
try: import joblib
except Exception: joblib = None
try: from scapy.arch.windows import get_windows_if_list
except Exception: get_windows_if_list = None
try: from scapy.all import get_if_list
except Exception: get_if_list = None

app = FastAPI()
BASE = Path.cwd()
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# --- process and ws state ---
class Proc:
    def __init__(self): self.p=None; self.task=None
PROC = Proc()
CLIENTS: List[WebSocket] = []

def py(): return sys.executable

def discover_npcap():
    lst = []
    if os.name == "nt" and get_windows_if_list:
        try:
            for itf in get_windows_if_list():
                name = itf.get("name","")
                guid = (itf.get("guid","") or "").strip()
                desc = itf.get("description","")
                # Build \Device\NPF_{GUID} exactly once
                if guid:
                    # guid may already be "{...}" or bare
                    if guid.startswith("{") and guid.endswith("}"):
                        dev = rf"\Device\NPF_{guid}"
                    else:
                        dev = rf"\Device\NPF_{{{guid}}}"
                else:
                    dev = name  # fallback
                disp = f"{name} | {desc}".strip(" |")
                lst.append({"device": dev, "display": disp})
        except Exception:
            pass
    # fallback(s) unchanged...
    if not lst and get_if_list:
        try:
            for name in get_if_list():
                lst.append({"device": name, "display": name})
        except Exception:
            pass
    # dedupe
    seen=set(); out=[]
    for d in lst:
        t=(d["device"], d["display"])
        if t not in seen:
            seen.add(t); out.append(d)
    return out

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/interfaces")
async def api_interfaces():
    return JSONResponse(discover_npcap())

class StartBody(BaseModel):
    iface: str
    pcap: str = "capture_live.pcap"
    features_csv: str = "features.csv"
    seconds: int = 60

@app.post("/api/start")
async def api_start(body: StartBody):
    if PROC.p and PROC.p.poll() is None:
        return JSONResponse({"error":"capture already running"}, status_code=409)
    main_py = str(BASE / "main.py")
    if not os.path.exists(main_py):
        return JSONResponse({"error":"main.py not found"}, status_code=400)
    cmd = [py(), main_py, "-i", body.iface, "-o", body.pcap, "--features-csv", body.features_csv]
    if body.seconds and body.seconds > 0:
        cmd += ["-t", str(body.seconds)]
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name=="nt" else 0
    PROC.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=flags)

    async def reader():
        try:
            for line in PROC.p.stdout:
                await broadcast(line.rstrip("\n"))
        finally:
            rc = PROC.p.poll()
            await broadcast(f"[process-exit] code={rc}")
    PROC.task = asyncio.create_task(reader())
    return JSONResponse({"ok": True, "cmd": cmd})

@app.post("/api/stop")
async def api_stop():
    if PROC.p and PROC.p.poll() is None:
        try:
            if os.name=="nt":
                PROC.p.send_signal(subprocess.signal.CTRL_BREAK_EVENT)
        except Exception: pass
        try: PROC.p.terminate()
        except Exception: pass
        return JSONResponse({"ok": True, "stopped": True})
    return JSONResponse({"ok": True, "stopped": False})

@app.websocket("/ws")
async def ws_logs(websocket: WebSocket):
    await websocket.accept(); CLIENTS.append(websocket)
    try:
        while True:
            await websocket.receive_text()  # keepalive
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in CLIENTS: CLIENTS.remove(websocket)

async def broadcast(text: str):
    dead=[]
    for ws in CLIENTS:
        try: await ws.send_text(text)
        except Exception: dead.append(ws)
    for ws in dead:
        if ws in CLIENTS: CLIENTS.remove(ws)

class ScoreBody(BaseModel):
    features_csv: str = "features.csv"
    out_csv: str = "scored.csv"

@app.post("/api/score")
async def api_score(body: ScoreBody):
    if pd is None or np is None:
        return JSONResponse({"error":"install pandas and numpy"}, status_code=400)
    if not os.path.exists(body.features_csv):
        return JSONResponse({"error": f"not found: {body.features_csv}"}, status_code=404)
    df = pd.read_csv(body.features_csv)
    X = df.select_dtypes(include=["number"]).copy()
    if X.empty:
        return JSONResponse({"error":"no numeric features"}, status_code=400)

    proba = None
    if proba is None:
        s = np.zeros(len(X))
        def first(*cols):
            for c in cols:
                if c in X.columns: return X[c].astype(float).to_numpy()
            return None
        v = first("ipv4_checksum_ok");  s += 1.5*(1 - np.clip(v,0,1)) if v is not None else 0
        v = first("l4_checksum_ok");    s += 1.2*(1 - np.clip(v,0,1)) if v is not None else 0
        v = first("flow_iat_avg");      s += np.tanh(v/0.5) if v is not None else 0
        v = first("flow_pkts");         s += np.tanh(v/10) if v is not None else 0
        proba = 1/(1+np.exp(-s))

    risk = (proba*100).round().astype(int)
    out = X.copy(); out.insert(0, "risk_0_100", risk.astype(int))
    for c in ["frame_no","ts_epoch","ip_src","ip_dst","sport","dport","l4_proto"]:
        if c in df.columns and c not in out.columns: out[c]=df[c]
    out.to_csv(body.out_csv, index=False)

    top=[]
    for i, r in sorted(enumerate(risk.tolist()), key=lambda t:t[1], reverse=True)[:50]:
        summ=[]
        for c in ["ip_src","ip_dst","sport","dport","l4_proto","ttl_hlim"]:
            if c in df.columns: summ.append(f"{c}={df.iloc[i][c]}")
        top.append({"idx": int(i), "risk": int(r), "summary": "  ".join(summ)})
    return JSONResponse({"ok": True, "rows": top, "out_csv": body.out_csv})

@app.get("/download")
async def download(path: str):
    p = Path(path).resolve()
    if not p.exists(): return JSONResponse({"error":"file not found"}, status_code=404)
    return FileResponse(str(p), filename=p.name)

@app.get("/healthz")
async def health(): return {"ok": True}
