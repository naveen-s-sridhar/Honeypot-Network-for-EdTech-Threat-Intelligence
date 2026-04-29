# =============================================================
# test_honeypot.py — Automated test script for your honeypot
#
# Run this in a SECOND terminal while honeypot.py is running.
# It simulates multiple attackers connecting to your honeypot
# so you can see the detection and logging in action.
# =============================================================

import socket    # For making test connections
import time      # For adding delays between tests
import threading # For simulating multiple attackers at once


HONEYPOT_HOST = "127.0.0.1"   # localhost — your own computer
HONEYPOT_PORT = 8888

def connect_and_send(attacker_id, message="GET / HTTP/1.0\r\nHost: edportal.local\r\n\r\n"):
    """
    Simulate one attacker connecting to the honeypot.
    
    Parameters:
        attacker_id : A label like "Attacker-1" for display purposes
        message     : The fake "attack" message to send
    """
    try:
        # Create a client socket (the attacker's socket)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)   # Don't wait more than 5 seconds for a response

        # Connect to the honeypot
        sock.connect((HONEYPOT_HOST, HONEYPOT_PORT))
        print(f"[TEST] {attacker_id} connected successfully.")

        # Send a fake attack message
        sock.sendall(message.encode('utf-8'))

        # Receive and display the honeypot's fake response
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"[TEST] {attacker_id} received: {response[:80]}...")   # Show first 80 chars

        sock.close()

    except ConnectionRefusedError:
        print(f"[TEST ERROR] {attacker_id}: Could not connect. Is the honeypot running?")
    except Exception as e:
        print(f"[TEST ERROR] {attacker_id}: {e}")


def test_single_connection():
    """Test 1: One normal connection"""
    print("\n" + "="*50)
    print("TEST 1: Single normal connection")
    print("="*50)
    connect_and_send("Normal-User")
    time.sleep(1)


def test_repeated_connections():
    """Test 2: Same IP connecting many times — should trigger suspicious detection"""
    print("\n" + "="*50)
    print("TEST 2: Repeated connections (same IP) — triggers suspicious flag")
    print("="*50)
    for i in range(5):
        connect_and_send(f"Attacker-RepeatedIP (attempt {i+1})")
        time.sleep(0.3)   # Small gap between attempts


def test_concurrent_connections():
    """Test 3: Multiple attackers connecting at the same time — tests threading"""
    print("\n" + "="*50)
    print("TEST 3: Concurrent connections — tests multi-threading")
    print("="*50)
    threads = []
    for i in range(8):
        t = threading.Thread(
            target=connect_and_send,
            args=(f"Concurrent-Attacker-{i+1}",)
        )
        threads.append(t)
        t.start()

    # Wait for all threads to finish
    for t in threads:
        t.join()


def test_different_payloads():
    """Test 4: Different kinds of attack payloads"""
    print("\n" + "="*50)
    print("TEST 4: Different attack payloads")
    print("="*50)
    payloads = [
        ("SQL-Injection-Bot",    "' OR 1=1; DROP TABLE students; --"),
        ("Admin-Brute-Force",    "POST /admin/login HTTP/1.0\r\nData: user=admin&pass=1234"),
        ("Scanner-Bot",          "HEAD / HTTP/1.0\r\nUser-Agent: masscan/1.0"),
        ("SSH-Probe",            "SSH-2.0-OpenSSH_7.4"),
    ]
    for attacker_name, payload in payloads:
        connect_and_send(attacker_name, payload)
        time.sleep(0.5)


# =============================================================
# RUN ALL TESTS
# =============================================================

if __name__ == "__main__":
    print("\n🧪 HONEYPOT TEST SUITE STARTING")
    print("Make sure honeypot.py is running in another terminal!\n")
    time.sleep(2)   # Give user time to read the message

    test_single_connection()
    time.sleep(1)

    test_repeated_connections()
    time.sleep(1)

    test_concurrent_connections()
    time.sleep(1)

    test_different_payloads()

    print("\n✅ All tests completed!")
    print("📁 Check logs/connections.csv and logs/suspicious.json")
    print("   to see the results of the tests.\n")
