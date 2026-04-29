# =============================================================
# detector.py — Detects suspicious/repeated connection attempts
# Think of this as the honeypot's "brain" that notices patterns.
# For example: if the same IP connects 5 times in 1 minute,
# something is definitely wrong — it's probably a bot or attacker.
# =============================================================

import time        # For getting current time and comparing timestamps
import threading   # For thread-safe operations (explained below)

from config import SUSPICIOUS_THRESHOLD, TIME_WINDOW_SECONDS


class ConnectionDetector:
    """
    This class tracks connections per IP and decides which ones are suspicious.
    
    A "class" in Python is like a blueprint. This blueprint creates a 
    connection tracker with its own memory and methods (functions).
    """

    def __init__(self):
        """
        __init__ runs automatically when you create a ConnectionDetector object.
        It sets up empty storage to track IPs.
        """
        # A dictionary to store connection times for each IP
        # Example: { "192.168.1.5": [1700000001.5, 1700000010.2, ...] }
        self.ip_connections = {}

        # A set to store IPs we've already flagged as suspicious
        self.suspicious_ips = set()

        # A "lock" prevents two threads from editing the same data at the same time
        # Imagine two people trying to write in the same notebook simultaneously — chaos!
        # The lock makes them take turns.
        self.lock = threading.Lock()

    def record_connection(self, ip):
        """
        Record that an IP just connected. Returns whether it's suspicious.
        
        Parameters:
            ip : The IP address string (e.g., "192.168.1.5")
        
        Returns:
            True  → This IP is suspicious
            False → This IP looks normal so far
        """
        current_time = time.time()   # Current time as a big decimal number (Unix timestamp)

        # Use the lock — only one thread can run this block at a time
        with self.lock:
            # If we haven't seen this IP before, create a new entry for it
            if ip not in self.ip_connections:
                self.ip_connections[ip] = []

            # Remove old timestamps that are outside our time window
            # We only care about connections in the last TIME_WINDOW_SECONDS seconds
            # Example: if TIME_WINDOW_SECONDS = 60, forget connections older than 1 minute
            self.ip_connections[ip] = [
                t for t in self.ip_connections[ip]    # Keep timestamp 't' only if...
                if current_time - t < TIME_WINDOW_SECONDS   # ...it's within the time window
            ]

            # Add the current connection time
            self.ip_connections[ip].append(current_time)

            # Count how many connections in the current window
            attempt_count = len(self.ip_connections[ip])

            # Check if this IP has exceeded our threshold
            if attempt_count >= SUSPICIOUS_THRESHOLD:
                self.suspicious_ips.add(ip)   # Mark it as suspicious
                return True, attempt_count    # Tell the caller it's suspicious

        return False, attempt_count   # Not suspicious yet

    def is_suspicious(self, ip):
        """
        Quick check: is this IP already in our suspicious list?
        
        Returns True or False.
        """
        return ip in self.suspicious_ips

    def get_connection_count(self, ip):
        """
        How many times has this IP connected in the recent time window?
        """
        if ip not in self.ip_connections:
            return 0
        return len(self.ip_connections[ip])

    def get_all_timestamps_for_ip(self, ip):
        """
        Get all connection timestamps for a specific IP.
        We convert Unix timestamps to readable strings for the log.
        """
        import datetime
        if ip not in self.ip_connections:
            return []
        return [
            datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
            for t in self.ip_connections[ip]
        ]

    def get_stats(self):
        """
        Return a quick summary of what we've seen.
        """
        with self.lock:
            return {
                "total_unique_ips": len(self.ip_connections),
                "suspicious_ips": list(self.suspicious_ips),
                "suspicious_count": len(self.suspicious_ips)
            }
