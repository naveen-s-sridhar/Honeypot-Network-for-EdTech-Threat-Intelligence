# =============================================================
# dashboard.py — Complete rewrite, clean and simple
# Runs the fake EdTech portal AND the threat dashboard
# =============================================================

from flask import Flask, request, jsonify
import csv, json, os, datetime
from collections import Counter
from logger import log_connection, log_suspicious_ip

app = Flask(__name__)

CONNECTIONS_LOG = "logs/connections.csv"
SUSPICIOUS_LOG  = "logs/suspicious.json"


# =============================================================
# HELPER FUNCTIONS
# =============================================================

def read_connections():
    rows = []
    if not os.path.exists(CONNECTIONS_LOG):
        return rows
    with open(CONNECTIONS_LOG, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows

def read_suspicious():
    if not os.path.exists(SUSPICIOUS_LOG):
        return {}
    with open(SUSPICIOUS_LOG, encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return {}

def count_recent_attempts(ip, seconds=60):
    """Count how many times an IP has connected in the last N seconds."""
    count = 0
    now = datetime.datetime.now()
    if not os.path.exists(CONNECTIONS_LOG):
        return 0
    with open(CONNECTIONS_LOG, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get("ip_address") == ip:
                try:
                    t = datetime.datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                    if (now - t).total_seconds() < seconds:
                        count += 1
                except:
                    pass
    return count


# =============================================================
# ROUTE 1 — Serve the fake EdTech website
# =============================================================

@app.route("/portal")
def portal():
    try:
        with open("edunova_portal.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h2>edunova_portal.html not found in project folder.</h2>", 404


# =============================================================
# ROUTE 2 — Login trap (the honeypot bait)
# =============================================================

@app.route("/login", methods=["POST"])
def fake_login():
    ip       = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    email    = request.form.get("email", "unknown")
    password = request.form.get("password", "unknown")
    data_str = f"LOGIN | email={email} | password={password}"

    # Count previous attempts from CSV
    prev_attempts = count_recent_attempts(ip)
    is_suspicious = prev_attempts >= 3

    # Log to CSV
    log_connection(ip, 80, data_str, is_suspicious)

    # Save to suspicious.json if flagged
    if is_suspicious:
        timestamps = []
        if os.path.exists(CONNECTIONS_LOG):
            with open(CONNECTIONS_LOG, newline='', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    if row.get("ip_address") == ip:
                        timestamps.append(row.get("timestamp", ""))
        log_suspicious_ip(ip, prev_attempts + 1, timestamps)

    # Terminal output
    flag = "SUSPICIOUS" if is_suspicious else "Normal"
    print(f"\n{'='*50}")
    print(f"  LOGIN ATTEMPT CAPTURED")
    print(f"  IP       : {ip}")
    print(f"  Email    : {email}")
    print(f"  Password : {password}")
    print(f"  Attempts : {prev_attempts + 1}  |  {flag}")
    print(f"{'='*50}\n")

    # Send fake Access Denied page back
    return """<!DOCTYPE html>
<html>
<head>
  <title>EduNova - Access Denied</title>
  <style>
    body { font-family: sans-serif; background: #f5f0e8;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
    .box { background:white; padding:48px; border-radius:12px;
           text-align:center; box-shadow:0 8px 32px rgba(0,0,0,.1); max-width:400px; }
    h2   { color:#c0392b; margin-bottom:12px; font-size:1.5rem; }
    p    { color:#666; margin-bottom:24px; line-height:1.6; }
    a    { display:inline-block; padding:10px 24px; background:#0d3d3a;
           color:white; border-radius:6px; text-decoration:none; font-weight:600; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Access Denied</h2>
    <p>Invalid credentials detected.<br>
       This incident has been logged and reported to the security team.</p>
    <a href="/portal">Back to Login</a>
  </div>
</body>
</html>""", 403


# =============================================================
# ROUTE 3 — Threat Intelligence Dashboard
# =============================================================

@app.route("/")
def dashboard():
    rows       = read_connections()
    suspicious = read_suspicious()

    total        = len(rows)
    unique_ips   = len(set(r["ip_address"] for r in rows))
    susp_count   = len(suspicious)
    normal_count = total - sum(1 for r in rows if r.get("is_suspicious") == "True")

    # Top IPs
    ip_counts = Counter(r["ip_address"] for r in rows)
    top_ips   = ip_counts.most_common(8)

    # Hourly data
    hourly = Counter()
    for r in rows:
        try:
            dt = datetime.datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
            hourly[dt.strftime("%H:00")] += 1
        except:
            pass
    hourly_sorted = sorted(hourly.items())

    # Recent connections (last 50, newest first)
    recent = rows[-50:][::-1]

    # Build suspicious IP rows
    susp_rows = ""
    for ip, d in suspicious.items():
        susp_rows += f"""
        <div style="border:1px solid rgba(255,62,62,.3);border-radius:6px;
                    padding:14px 16px;margin-bottom:10px;background:rgba(255,62,62,.05);">
          <div style="color:#ff3e3e;font-size:1rem;margin-bottom:6px;">&#128534; {d.get('ip_address','?')}</div>
          <div style="color:#3a5a4a;font-size:.78rem;line-height:1.8;">
            Attempts : {d.get('total_attempts','?')}<br>
            First seen : {d.get('first_seen','?')}<br>
            Last seen  : {d.get('last_seen','?')}
          </div>
        </div>"""
    if not susp_rows:
        susp_rows = '<div style="color:#3a5a4a;font-size:.85rem;">No suspicious IPs yet.<br>Try logging in 4+ times on the portal!</div>'

    # Build table rows
    table_rows = ""
    for r in recent:
        badge = ('⚠️ SUSPICIOUS' if r.get("is_suspicious") == "True" else "✓ Normal")
        color = "#ff3e3e" if r.get("is_suspicious") == "True" else "#00ff88"
        table_rows += f"""<tr>
          <td>{r.get('timestamp','')}</td>
          <td>{r.get('ip_address','')}</td>
          <td>{r.get('port','')}</td>
          <td style="color:{color};font-weight:600;">{badge}</td>
        </tr>"""
    if not table_rows:
        table_rows = '<tr><td colspan="4" style="color:#3a5a4a;padding:20px;">No connections yet. Go to /portal and try logging in!</td></tr>'

    # Build chart data as plain JS arrays (no Jinja2 filters needed)
    h_labels = str([h for h, _ in hourly_sorted])
    h_data   = str([c for _, c in hourly_sorted])
    i_labels = str([ip for ip, _ in top_ips])
    i_data   = str([c  for _,  c in top_ips])

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HoneyNet Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:#050a0e; --surface:#0b1318; --border:#0e2a1f;
    --glow:#00ff88; --glow2:#00cfff; --danger:#ff3e3e;
    --warn:#ffaa00; --text:#c8d8d0; --muted:#3a5a4a;
  }}
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:15px}}
  body::before{{content:'';position:fixed;inset:0;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.015) 2px,rgba(0,255,136,.015) 4px);
    pointer-events:none;z-index:9999}}
  header{{display:flex;align-items:center;justify-content:space-between;
    padding:18px 32px;border-bottom:1px solid var(--border);
    background:linear-gradient(90deg,#060f0a,#050a0e);position:sticky;top:0;z-index:100}}
  .logo{{font-family:'Share Tech Mono',monospace;font-size:1.1rem;color:var(--glow);
    text-shadow:0 0 12px rgba(0,255,136,.6);letter-spacing:.1em}}
  .logo span{{color:var(--glow2)}}
  .hdr-right{{font-family:'Share Tech Mono',monospace;font-size:.72rem;color:var(--muted)}}
  .dot{{display:inline-block;width:8px;height:8px;border-radius:50%;
    background:var(--glow);box-shadow:0 0 8px var(--glow);
    animation:pulse 1.4s ease-in-out infinite;margin-right:6px}}
  @keyframes pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:.4;transform:scale(.7)}}}}
  main{{padding:28px 32px;max-width:1400px;margin:0 auto}}
  .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}}
  @media(max-width:900px){{.cards{{grid-template-columns:repeat(2,1fr)}}}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;
    padding:22px 24px;position:relative;overflow:hidden}}
  .card::after{{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--glow)}}
  .card.danger::after{{background:var(--danger)}}
  .card.warn::after{{background:var(--warn)}}
  .card.blue::after{{background:var(--glow2)}}
  .clabel{{font-family:'Share Tech Mono',monospace;font-size:.62rem;letter-spacing:.15em;
    color:var(--muted);text-transform:uppercase;margin-bottom:10px}}
  .cval{{font-family:'Share Tech Mono',monospace;font-size:2.6rem;line-height:1;
    color:var(--glow);text-shadow:0 0 20px rgba(0,255,136,.35)}}
  .card.danger .cval{{color:var(--danger);text-shadow:0 0 20px rgba(255,62,62,.35)}}
  .card.warn   .cval{{color:var(--warn);text-shadow:0 0 20px rgba(255,170,0,.35)}}
  .card.blue   .cval{{color:var(--glow2);text-shadow:0 0 20px rgba(0,207,255,.35)}}
  .csub{{font-size:.75rem;color:var(--muted);margin-top:6px;font-family:'Share Tech Mono',monospace}}
  .row2{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:28px}}
  @media(max-width:800px){{.row2{{grid-template-columns:1fr}}}}
  .panel{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:20px 22px}}
  .ptitle{{font-family:'Share Tech Mono',monospace;font-size:.68rem;letter-spacing:.15em;
    color:var(--glow);text-transform:uppercase;margin-bottom:16px}}
  .ptitle::before{{content:'// ';color:var(--muted)}}
  table{{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:.76rem}}
  th{{text-align:left;color:var(--muted);font-size:.62rem;letter-spacing:.12em;
    text-transform:uppercase;padding:6px 10px;border-bottom:1px solid var(--border)}}
  td{{padding:8px 10px;border-bottom:1px solid rgba(14,42,31,.5);color:var(--text)}}
  tr:hover td{{background:rgba(0,255,136,.03)}}
  .btn{{background:transparent;border:1px solid var(--glow);color:var(--glow);
    font-family:'Share Tech Mono',monospace;font-size:.7rem;letter-spacing:.1em;
    padding:7px 18px;border-radius:3px;cursor:pointer;transition:background .15s}}
  .btn:hover{{background:rgba(0,255,136,.08)}}
  .rbar{{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}}
  .rbar a{{color:var(--glow2);font-family:'Share Tech Mono',monospace;font-size:.75rem;text-decoration:none}}
</style>
</head>
<body>
<header>
  <div class="logo">&#127855; HONEY<span>NET</span></div>
  <div class="hdr-right"><span class="dot"></span>EDTECH THREAT INTELLIGENCE &nbsp;|&nbsp; {now}</div>
</header>
<main>
  <div class="rbar">
    <a href="/portal">&#8594; Open Fake Portal</a>
    <button class="btn" onclick="location.reload()">&#8635; REFRESH</button>
  </div>
  <div class="cards">
    <div class="card">
      <div class="clabel">Total Connections</div>
      <div class="cval">{total}</div>
      <div class="csub">all time</div>
    </div>
    <div class="card blue">
      <div class="clabel">Unique IPs</div>
      <div class="cval">{unique_ips}</div>
      <div class="csub">distinct sources</div>
    </div>
    <div class="card danger">
      <div class="clabel">Suspicious IPs</div>
      <div class="cval">{susp_count}</div>
      <div class="csub">flagged</div>
    </div>
    <div class="card warn">
      <div class="clabel">Normal</div>
      <div class="cval">{normal_count}</div>
      <div class="csub">clean connections</div>
    </div>
  </div>
  <div class="row2">
    <div class="panel">
      <div class="ptitle">Connections by Hour</div>
      <canvas id="hChart" height="180"></canvas>
    </div>
    <div class="panel">
      <div class="ptitle">Top Attacker IPs</div>
      <canvas id="iChart" height="180"></canvas>
    </div>
  </div>
  <div class="row2">
    <div class="panel">
      <div class="ptitle">Recent Connections</div>
      <div style="overflow-x:auto">
        <table>
          <thead><tr><th>Timestamp</th><th>IP</th><th>Port</th><th>Status</th></tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="ptitle">Flagged Suspicious IPs</div>
      {susp_rows}
    </div>
  </div>
</main>
<script>
Chart.defaults.color = '#3a5a4a';
Chart.defaults.borderColor = '#0e2a1f';
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size = 11;

var hLabels = {h_labels};
var hData   = {h_data};
var iLabels = {i_labels};
var iData   = {i_data};

new Chart(document.getElementById('hChart'), {{
  type:'bar',
  data:{{
    labels: hLabels.length ? hLabels : ['No data yet'],
    datasets:[{{label:'Connections',data:hData.length?hData:[0],
      backgroundColor:'rgba(0,255,136,0.15)',borderColor:'#00ff88',borderWidth:1,borderRadius:2}}]
  }},
  options:{{responsive:true,plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'#0e2a1f'}}}},y:{{grid:{{color:'#0e2a1f'}},beginAtZero:true}}}}}}
}});

new Chart(document.getElementById('iChart'), {{
  type:'bar',
  data:{{
    labels: iLabels.length ? iLabels : ['No data yet'],
    datasets:[{{label:'Hits',data:iData.length?iData:[0],
      backgroundColor:'rgba(0,207,255,0.15)',borderColor:'#00cfff',borderWidth:1,borderRadius:2}}]
  }},
  options:{{responsive:true,indexAxis:'y',plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'#0e2a1f'}},beginAtZero:true}},y:{{grid:{{color:'#0e2a1f'}}}}}}}}
}});
</script>
</body>
</html>"""
    return html



# =============================================================
# HACKER TRAP ROUTES
# These are hidden URLs that real students NEVER visit.
# Only hackers and bots look for these pages.
# Anyone who visits = automatically suspicious!
# =============================================================

# List of all trap URLs we are monitoring
TRAP_URLS = [
    "/admin",           # Hackers look for admin panels
    "/wp-admin",        # WordPress admin (common target)
    "/phpmyadmin",      # Database admin panel
    "/.env",            # Config file with passwords
    "/config",          # Configuration page
    "/backup",          # Backup files
    "/database",        # Database access
    "/shell",           # Web shell (hackers upload these)
    "/cmd",             # Command execution
    "/root",            # Root access attempt
    "/administrator",   # Joomla admin panel
    "/login/admin",     # Admin login attempt
    "/api/users",       # User data theft attempt
    "/api/passwords",   # Password data theft attempt
    "/.git",            # Source code theft attempt
]

@app.route("/admin")
@app.route("/wp-admin")
@app.route("/phpmyadmin")
@app.route("/.env")
@app.route("/config")
@app.route("/backup")
@app.route("/database")
@app.route("/shell")
@app.route("/cmd")
@app.route("/root")
@app.route("/administrator")
@app.route("/login/admin")
@app.route("/api/users")
@app.route("/api/passwords")
@app.route("/.git")
def hacker_trap():
    """
    This function runs when ANYONE visits a trap URL.
    Real students never visit /admin or /phpmyadmin.
    So anyone here is definitely a hacker or a bot.
    We log them as SUSPICIOUS immediately — no 3 attempt rule needed!
    """
    import datetime as _dt
    from flask import request

    ip        = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    trap_url  = request.path          # Which trap URL did they visit?
    method    = request.method        # GET or POST?
    agent     = request.headers.get("User-Agent", "unknown")[:100]

    # Build detailed log entry
    captured  = f"HACKER TRAP HIT | url={trap_url} | method={method} | agent={agent}"

    # Log immediately as suspicious — no need to wait for 3 attempts
    # Anyone visiting these URLs is AUTOMATICALLY suspicious
    log_connection(ip, 80, captured, True)

    # Also save to suspicious.json straight away
    timestamps = []
    if os.path.exists(CONNECTIONS_LOG):
        with open(CONNECTIONS_LOG, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("ip_address") == ip:
                    timestamps.append(row.get("timestamp", ""))

    log_suspicious_ip(ip, len(timestamps), timestamps)

    # Print a big alert in terminal
    print(f"\n{'!'*55}")
    print(f"  🚨 HACKER TRAP TRIGGERED!")
    print(f"  IP Address  : {ip}")
    print(f"  Trap URL    : {trap_url}")
    print(f"  Method      : {method}")
    print(f"  User Agent  : {agent[:60]}")
    print(f"  Time        : {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'!'*55}\n")

    # Send a fake "almost real" response to keep hacker engaged longer
    # Different trap URLs return different fake responses
    responses = {
        "/admin":        ("<h2>Admin Login Required</h2><p>Enter admin credentials.</p>", 401),
        "/wp-admin":     ("<h2>WordPress Admin</h2><p>Session expired. Please log in again.</p>", 401),
        "/phpmyadmin":   ("<h2>phpMyAdmin</h2><p>Access restricted. Contact administrator.</p>", 403),
        "/.env":         ("APP_KEY=base64:FAKEKEYDONOTUSE\nDB_PASSWORD=FAKEPASSWORD\n", 200),
        "/config":       ("<h2>Configuration</h2><p>Unauthorized access detected.</p>", 403),
        "/backup":       ("<h2>Backup Manager</h2><p>No backups found for your IP.</p>", 403),
        "/database":     ("<h2>Database Console</h2><p>Connection refused.</p>", 503),
        "/shell":        ("<h2>Web Shell</h2><p>Shell access disabled by administrator.</p>", 403),
        "/.git":         ("fatal: repository not found\n", 403),
    }

    # Get the right fake response for this trap URL
    fake_body, status_code = responses.get(
        request.path,
        ("<h2>403 Forbidden</h2><p>Access denied. Incident logged.</p>", 403)
    )

    return fake_body, status_code


# =============================================================
# TRAP SCANNER — shows all trap URLs on the dashboard
# =============================================================

@app.route("/api/traps")
def api_traps():
    """Returns list of all active trap URLs as JSON."""
    return jsonify({
        "active_traps": TRAP_URLS,
        "total": len(TRAP_URLS),
        "message": "These URLs automatically flag any visitor as suspicious"
    })


# =============================================================
# API endpoint — returns stats as JSON
# =============================================================

@app.route("/api/stats")
def api_stats():
    rows = read_connections()
    suspicious = read_suspicious()
    return jsonify({
        "total": len(rows),
        "unique_ips": len(set(r["ip_address"] for r in rows)),
        "suspicious": len(suspicious)
    })


# =============================================================
# START
# =============================================================

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  HONEYNET - FULL SYSTEM RUNNING")
    print("="*55)
    print("  Fake EdTech Portal  ->  http://localhost:5000/portal")
    print("  Threat Dashboard    ->  http://localhost:5000")
    print("  Login Trap          ->  http://localhost:5000/login")
    print("\n  Press Ctrl+C to stop")
    print("="*55 + "\n")
    app.run(debug=False, port=5000)
