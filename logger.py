import csv
import json
import os
import datetime

from config import CONNECTIONS_LOG, SUSPICIOUS_LOG, SUMMARY_REPORT


def setup_directories():
    """
    Create the 'logs' and 'reports' folders if they don't exist yet.
    Like setting up blank notebooks before you start writing.
    """
    os.makedirs("logs", exist_ok=True) 
    os.makedirs("reports", exist_ok=True)

    if not os.path.exists(CONNECTIONS_LOG):
        with open(CONNECTIONS_LOG, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "ip_address", "port", "data_received", "is_suspicious"])
        print(f"[LOGGER] Created new log file: {CONNECTIONS_LOG}")

    if not os.path.exists(SUSPICIOUS_LOG):
        with open(SUSPICIOUS_LOG, mode='w') as f:
            json.dump({}, f)   # Start with an empty dictionary {}
        print(f"[LOGGER] Created suspicious IPs file: {SUSPICIOUS_LOG}")


def log_connection(ip, port, data, is_suspicious=False):
    """
    Save one connection event to the CSV log file.
    
    Parameters:
        ip           : The attacker's IP address (e.g., "192.168.1.5")
        port         : The port they connected from (e.g., 54321)
        data         : Any data they sent us (e.g., HTTP request)
        is_suspicious: True if this IP has connected too many times
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    clean_data = str(data).replace('\n', ' ').replace('\r', '').strip()[:200]

    with open(CONNECTIONS_LOG, mode='a', newline='') as f:   # 'a' means append (add to end)
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, port, clean_data, is_suspicious])

    flag = "⚠️  SUSPICIOUS" if is_suspicious else "✅ Normal"
    print(f"[LOG] {timestamp} | {ip}:{port} | {flag}")


def log_suspicious_ip(ip, attempt_count, timestamps):
    """
    Save a suspicious IP's full details to the JSON file.
    JSON is great here because it can store nested data (like a list of timestamps).
    
    Parameters:
        ip            : The suspicious IP address
        attempt_count : How many times they've connected
        timestamps    : List of all the times they connected
    """
    with open(SUSPICIOUS_LOG, mode='r') as f:
        suspicious_data = json.load(f)


    suspicious_data[ip] = {
        "ip_address": ip,
        "total_attempts": attempt_count,
        "first_seen": timestamps[0] if timestamps else "unknown",
        "last_seen": timestamps[-1] if timestamps else "unknown",
        "all_timestamps": timestamps,
        "status": "FLAGGED"
    }

    with open(SUSPICIOUS_LOG, mode='w') as f:
        json.dump(suspicious_data, f, indent=4)

    print(f"[ALERT] 🚨 IP {ip} flagged as SUSPICIOUS after {attempt_count} attempts!")


def generate_summary():
    """
    Read all logs and write a human-readable summary to a text file.
    This is what you'd show your teacher or include in a project report.
    """
    summary_lines = []
    summary_lines.append("=" * 60)
    summary_lines.append("  HONEYPOT THREAT INTELLIGENCE SUMMARY REPORT")
    summary_lines.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_lines.append("=" * 60)

    total_connections = 0
    unique_ips = set() 
    if os.path.exists(CONNECTIONS_LOG):
        with open(CONNECTIONS_LOG, mode='r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_connections += 1
                unique_ips.add(row["ip_address"])

    summary_lines.append(f"\n📊 STATISTICS:")
    summary_lines.append(f"   Total connection attempts : {total_connections}")
    summary_lines.append(f"   Unique IP addresses       : {len(unique_ips)}")

    suspicious_count = 0
    if os.path.exists(SUSPICIOUS_LOG):
        with open(SUSPICIOUS_LOG, mode='r') as f:
            suspicious_data = json.load(f)
            suspicious_count = len(suspicious_data)

    summary_lines.append(f"   Suspicious IPs flagged    : {suspicious_count}")

    if suspicious_count > 0:
        summary_lines.append(f"\n🚨 SUSPICIOUS IPs:")
        for ip, details in suspicious_data.items():
            summary_lines.append(
                f"   {ip} — {details['total_attempts']} attempts "
                f"(First: {details['first_seen']}, Last: {details['last_seen']})"
            )

    summary_lines.append("\n" + "=" * 60)
    summary_lines.append("  END OF REPORT")
    summary_lines.append("=" * 60)

    with open(SUMMARY_REPORT, 'w') as f:
        f.write('\n'.join(summary_lines))

    print('\n'.join(summary_lines))
    print(f"\n[LOGGER] Summary saved to {SUMMARY_REPORT}")
