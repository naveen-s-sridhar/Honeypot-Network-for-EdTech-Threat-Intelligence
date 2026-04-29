# =============================================================
# config.py — Central configuration for the Honeypot project
# Think of this as the "settings panel" for the whole project.
# If you want to change any setting, only change it here.
# =============================================================

# --- Network Settings ---
HOST = "0.0.0.0"       # Listen on all available network interfaces
                        # "0.0.0.0" means accept connections from any IP
PORT = 8888             # The port our honeypot will listen on
                        # Real systems use ports like 80 (web), 22 (SSH), etc.
                        # We use 8888 so we don't conflict with real services

BUFFER_SIZE = 1024      # How many bytes of data to receive at once from attacker

# --- Fake Response ---
# This is what the honeypot sends back to anyone who connects.
# It sounds like a real system rejecting them, so the attacker
# thinks they hit a real server.
FAKE_RESPONSE = (
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: text/html\r\n"
    "Server: EduPortal-v2.1\r\n"
    "\r\n"
    "<html><body><h1>403 - Access Denied</h1>"
    "<p>Unauthorized access to EdTech portal. Incident logged.</p>"
    "</body></html>"
)

# --- Suspicious IP Detection ---
# If the same IP connects more than this many times, it gets flagged
SUSPICIOUS_THRESHOLD = 3      # Number of connections before flagging
TIME_WINDOW_SECONDS = 60      # Count connections within this time window (1 minute)

# --- File Paths ---
# Where to save the log files
CONNECTIONS_LOG = "logs/connections.csv"   # All connections go here
SUSPICIOUS_LOG  = "logs/suspicious.json"  # Suspicious IPs go here
SUMMARY_REPORT  = "reports/summary.txt"   # Human-readable summary

# --- Display Settings ---
MAX_DISPLAY_ROWS = 20   # How many rows to show in terminal summary
