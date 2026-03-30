# NetRisk — Network Traffic Risk Analysis Dashboard

A web-based system for **real-time packet capture, feature extraction, and threat classification** using:

- L2–L4 header analysis (Scapy)
- Machine learning (Random Forest)
- External threat intelligence (Scamalytics API)
- Interactive dashboard (FastAPI)

---

## 1) System Overview

Core capabilities:

- Capture live network packets
- Extract L2–L4 header features
- Perform ML-based anomaly detection
- Enrich IP risk using Scamalytics API
- Display results via web dashboard

---

## 2) Project Structure

```text
packet-header_n_frame-analysis/
├── app.py                  # FastAPI backend (dashboard controller)
├── fyp1.py                 # Capture + feature extraction + scoring engine
├── random_forest/
│   └── rf_model.joblib     # Trained ML model
├── templates/
│   └── index.html          # Dashboard UI
├── static/
│   └── app.js              # Frontend logic (optional)
├── .env                    # API credentials (DO NOT COMMIT)
└── README.md
```

---

## 3) Prerequisites

- Windows 10 / 11  
- **Npcap** (Install with *WinPcap API-compatible mode*)  
- Python 3.9 – 3.12  
- Run terminal as **Administrator** (required for packet capture)

---

## 4) Setup

```powershell
py -m venv .venv
.\.venv\Scripts\activate

python -m pip install --upgrade pip wheel

pip install fastapi uvicorn jinja2 pydantic
pip install scapy pandas numpy scikit-learn joblib python-dotenv
```

---

## 5) Configure Scamalytics API

Create a `.env` file in the root directory:

```env
SCAMALYTICS_USER=your_user
SCAMALYTICS_KEY=your_api_key
SCAMALYTICS_BASE_URL=https://api13.scamalytics.com/v3
SCAMALYTICS_TIMEOUT=3.0
```
⚠️ Do NOT commit .env to GitHub

---

## 6) Run the Web Dashboard

```powershell
uvicorn app:app --reload
```

```Open
http://127.0.0.1:8000
```

---

## 7) How to Use

### Step 1 — Start Capture

- Select interface  
- Set duration (seconds)  
- Click **Start Capture**

**Output:**
- `capture_live.pcap`  
- `features.csv`  

---

### Step 2 — Run Scoring

Click **Score**

**Pipeline:**

1. Load `features.csv`  
2. Run ML detection  
3. Apply risk scoring:
   - Scamalytics API (public IP)  
   - Heuristic fallback (private/API fail)  

**Output:**
- `scores.csv`

---

## 8) Output Files

| File                | Description                        |
|---------------------|------------------------------------|
| `capture_live.pcap` | Raw packet capture                 |
| `features.csv`      | Extracted L2–L4 features           |
| `scores.csv`        | Final detection + risk scoring     |

---

## 9) Scoring Model

### 1. Machine Learning (RF Model)

Classifies packets into:
- `attack`  
- `tampered`  
- `benign`  

---

### 2. Risk Scoring

**External (Primary)**
- Scamalytics API  
- Returns:
  - `ip_fraud_score` (0–100)  
  - `risk_level` (low → very high)  

**Internal (Fallback)**  
Header-based heuristic:
- checksum errors  
- fragmentation  
- abnormal TTL  
- suspicious TCP flags  
- DSCP anomalies  

---

### 3. Final Output Columns

| Column                   | Description                         |
|--------------------------|-------------------------------------|
| `ip_fraud_score`         | Numeric score (0–100)               |
| `ip_fraud_score_display` | Formatted score (e.g. 87/100)       |
| `risk_level`             | low / medium / high / very high     |
| `label`                  | ML classification                   |

---

## 10) CLI Usage (Optional)

**List interfaces:**
```powershell
python fyp1.py -l
```

**Capture traffic:**
```powershell
python fyp1.py -t 10
```

**Custom interface:**
```powershell
python fyp1.py -i \Device\NPF_{GUID} -t 10
```