# NetRisk — Packet Header & Frame Analyst (Web GUI)

Capture live traffic with Scapy/Npcap. Extract L2–L7 features to `features.csv`. Score risk to `scored.csv`. Operate from a local FastAPI Web GUI.

---

## 1) Folder layout
```text
packet-header_n_frame-analysis/
├─ app.py                  # FastAPI server + process manager
├─ test.py                 # Live capture + feature extraction
├─ templates/
│  └─ index.html           # Web UI (rename your iindex.html → index.html if needed)
└─ static/
   └─ app.js               # optional (can be empty)

---

## 2) Prereqs
- Windows 10/11
- **Npcap** installed with **“WinPcap API-compatible mode”**
- Python 3.9–3.12
- Run shell **as Administrator** for live capture

---

## 3) Setup
# In the project directory
py -m venv .venv
.\.venv\Scripts\activate

python -m pip install --upgrade pip wheel
pip install "fastapi==0.115.*" "uvicorn[standard]==0.30.*" "jinja2==3.1.*" "pydantic==2.8.*"
pip install scapy pandas numpy scikit-learn joblib

---

## 4) Start the Web GUI
```powershell
# from the project root with venv active
uvicorn app:app --reload
```
Open: http://127.0.0.1:8000

---

## 5) Use
1. **Refresh** interfaces. Pick your adapter.
2. Set **PCAP** path (default `capture_live.pcap`) and **Seconds** (`0` = run until **Stop**).
3. Click **Start**. Status shows `capturing…`. Logs stream below.
4. After timeout or **Stop**, status flips to `captured` / `stopped`.
5. **Score**:
   - Reads `features.csv`
   - Writes `scored.csv`
   - Shows top rows and a download link

### Outputs
- `capture_live.pcap` — raw packets  
- `features.csv` — per-packet features (L2–L7 + simple flow stats)  
- `scored.csv` — numeric features + `risk_0_100`

---

## 6) CLI (optional)
List interfaces:
```powershell
python test.py -l
```

Manual capture (10 seconds):
```powershell
python test.py -i \Device\NPF_{YOUR_GUID} -o capture_live.pcap --features-csv features.csv -t 10
```

