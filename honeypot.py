import socket
import threading 
import signal
import sys
import time

from config import HOST, PORT, BUFFER_SIZE, FAKE_RESPONSE
from logger import setup_directories, log_connection, log_suspicious_ip, generate_summary
from detector import ConnectionDetector

detector = ConnectionDetector()

active_threads = []

def handle_client(client_socket, client_address):
    """
    This function handles ONE client connection.
    It runs in its own thread — so many of these can run simultaneously.
    
    Parameters:
        client_socket  : The connection object (lets us send/receive data)
        client_address : A tuple like ("192.168.1.5", 54321)
    """
    ip   = client_address[0]   
    port = client_address[1]  

    try:
        client_socket.settimeout(2)

        try:
            raw_data = client_socket.recv(BUFFER_SIZE)
        except:
            raw_data = b""  
        data = raw_data.decode('utf-8', errors='ignore') if raw_data else "EMPTY CONNECTION"

       
        is_suspicious, attempt_count = detector.record_connection(ip)

        if is_suspicious:
          
            timestamps = detector.get_all_timestamps_for_ip(ip)
        
            log_suspicious_ip(ip, attempt_count, timestamps)

     
        log_connection(ip, port, data, is_suspicious)

   
        client_socket.sendall(FAKE_RESPONSE.encode('utf-8'))

        time.sleep(0.3)

    except (ConnectionResetError, BrokenPipeError):
        pass

    except Exception as e:
        err = str(e)
        if "Extra data" in err or "Expecting value" in err:
            pass  
        else:
            print(f"[ERROR] Problem with client {ip}: {e}")

    finally:
        client_socket.close()


def shutdown_handler(sig, frame):
    """
    This runs when you press Ctrl+C to stop the server.
    It prints a summary of everything that happened.
    """
    print("\n\n[HONEYPOT] Shutdown signal received. Generating report...")
    generate_summary()
    print("[HONEYPOT] Goodbye! Check the logs/ and reports/ folders.")
    sys.exit(0)

def start_honeypot():
    """
    This is the main function that starts the honeypot server.
    It creates a socket, binds it to a port, and waits for connections.
    """

    setup_directories()

    signal.signal(signal.SIGINT, shutdown_handler)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


    server_socket.bind((HOST, PORT))


    server_socket.listen(50)

    print("=" * 60)
    print("  🍯 EDTECH HONEYPOT NETWORK — THREAT INTELLIGENCE SYSTEM")
    print("=" * 60)
    print(f"  Listening on  : {HOST}:{PORT}")
    print(f"  Suspicious if : {__import__('config').SUSPICIOUS_THRESHOLD}+ connections in {__import__('config').TIME_WINDOW_SECONDS}s")
    print(f"  Logs saved to : logs/connections.csv")
    print(f"  Press Ctrl+C to stop and generate report")
    print("=" * 60 + "\n")


    while True:
        try:
            client_socket, client_address = server_socket.accept()

            print(f"[HONEYPOT] New connection from {client_address[0]}:{client_address[1]}")

            client_thread = threading.Thread(
                target=handle_client,             
                args=(client_socket, client_address), 
                daemon=True                     
            )
            client_thread.start()

            active_threads.append(client_thread)

            active_threads[:] = [t for t in active_threads if t.is_alive()]

        except Exception as e:
            print(f"[ERROR] Accept failed: {e}")

if __name__ == "__main__":
    start_honeypot()
