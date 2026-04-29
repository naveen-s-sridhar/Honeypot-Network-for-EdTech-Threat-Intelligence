# =============================================================
# report_viewer.py — View your honeypot logs in a nice format
# Run this at any time to see what's been logged.
# =============================================================

import csv
import json
import os
from config import CONNECTIONS_LOG, SUSPICIOUS_LOG


def view_connections():
    """Print the last 20 connections from the CSV log."""
    print("\n" + "="*70)
    print("  📋 RECENT CONNECTIONS LOG")
    print("="*70)

    if not os.path.exists(CONNECTIONS_LOG):
        print("  No log file found. Run the honeypot first!")
        return

    rows = []
    with open(CONNECTIONS_LOG, mode='r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        print("  No connections logged yet.")
        return

    # Print header
    print(f"  {'TIMESTAMP':<22} {'IP ADDRESS':<18} {'PORT':<8} {'SUSPICIOUS':<12}")
    print("  " + "-"*65)

    # Print last 20 rows
    for row in rows[-20:]:
        flag = "⚠️ YES" if row['is_suspicious'] == 'True' else "No"
        print(f"  {row['timestamp']:<22} {row['ip_address']:<18} {row['port']:<8} {flag:<12}")

    print(f"\n  Total connections in log: {len(rows)}")


def view_suspicious():
    """Print all suspicious IPs from the JSON file."""
    print("\n" + "="*70)
    print("  🚨 SUSPICIOUS IPs")
    print("="*70)

    if not os.path.exists(SUSPICIOUS_LOG):
        print("  No suspicious IPs file found.")
        return

    with open(SUSPICIOUS_LOG, mode='r') as f:
        data = json.load(f)

    if not data:
        print("  No suspicious IPs detected yet.")
        return

    for ip, details in data.items():
        print(f"\n  IP Address   : {details['ip_address']}")
        print(f"  Attempts     : {details['total_attempts']}")
        print(f"  First Seen   : {details['first_seen']}")
        print(f"  Last Seen    : {details['last_seen']}")
        print(f"  Status       : 🔴 {details['status']}")
        print("  " + "-"*40)


if __name__ == "__main__":
    view_connections()
    view_suspicious()
    print("\n")
