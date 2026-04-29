# 🍯 EdTech Honeypot Network — Threat Intelligence System
### BCA Project | Python & Socket Programming

---

## ✅ REQUIREMENTS

- Python 3.7 or higher (no extra libraries needed!)
- Two terminal windows (one for the server, one for testing)

Check your Python version:
```bash
python --version
```

---

## 📁 PROJECT FILE STRUCTURE

```
honeypot_project/
├── config.py           ← Settings (change port, thresholds here)
├── honeypot.py         ← Main server — RUN THIS FIRST
├── logger.py           ← Handles saving logs
├── detector.py         ← Detects suspicious IPs
├── test_honeypot.py    ← Test script — RUN IN SECOND TERMINAL
├── report_viewer.py    ← View logs nicely
├── PROJECT_WRITEUP.txt ← Abstract, Intro, Methodology, Conclusion
├── logs/               ← Created automatically
│   ├── connections.csv
│   └── suspicious.json
└── reports/            ← Created automatically
    └── summary.txt
```

---

## 🚀 HOW TO RUN (Step-by-Step)

### Step 1 — Open Terminal and go to the project folder
```bash
cd path/to/honeypot_project
```
> On Windows: Right-click in folder → "Open in Terminal"
> On Mac/Linux: `cd ~/Downloads/honeypot_project`

### Step 2 — Start the Honeypot Server
```bash
python honeypot.py
```

You should see:
```
============================================================
  🍯 EDTECH HONEYPOT NETWORK — THREAT INTELLIGENCE SYSTEM
============================================================
  Listening on  : 0.0.0.0:8888
  Suspicious if : 3+ connections in 60s
  Logs saved to : logs/connections.csv
  Press Ctrl+C to stop and generate report
============================================================
```

### Step 3 — Open a SECOND terminal and run the tests
```bash
python test_honeypot.py
```

Watch both terminals! You'll see connections appearing in the server terminal.

### Step 4 — View your logs
```bash
python report_viewer.py
```

### Step 5 — Stop the server and generate a full report
Press `Ctrl+C` in the server terminal. A summary report will be generated in reports/summary.txt

---

## 🔬 HOW TO TEST MANUALLY (Optional)

You can also test with telnet or curl:

```bash
# Using curl (if installed)
curl http://localhost:8888

# Using telnet
telnet localhost 8888

# Using Python one-liner
python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1',8888)); s.send(b'test'); print(s.recv(1024))"
```

---

## ⚙️ CUSTOMIZATION

Edit `config.py` to change:
- `PORT = 8888`               → Change the listening port
- `SUSPICIOUS_THRESHOLD = 3`  → How many connections before flagging
- `TIME_WINDOW_SECONDS = 60`  → Time window for counting connections
- `FAKE_RESPONSE = ...`       → What to send back to attackers

---

## 📊 UNDERSTANDING THE LOG FILES

**logs/connections.csv** — Every connection, one per row:
```
timestamp,ip_address,port,data_received,is_suspicious
2024-01-15 14:23:01,127.0.0.1,54321,GET / HTTP/1.0,False
2024-01-15 14:23:05,127.0.0.1,54322,GET / HTTP/1.0,True
```

**logs/suspicious.json** — Rich data on flagged IPs:
```json
{
  "127.0.0.1": {
    "ip_address": "127.0.0.1",
    "total_attempts": 5,
    "first_seen": "2024-01-15 14:23:01",
    "last_seen": "2024-01-15 14:23:08",
    "status": "FLAGGED"
  }
}
```

---

## ❓ TROUBLESHOOTING

**"Address already in use" error:**
Another program is using port 8888. Either stop that program, or change PORT in config.py to 9999.

**"Connection refused" in test script:**
The honeypot server isn't running. Start it first with `python honeypot.py`.

**Permission denied on port:**
On Linux/Mac, ports below 1024 need admin rights. Port 8888 should be fine.
If needed: `sudo python honeypot.py`
