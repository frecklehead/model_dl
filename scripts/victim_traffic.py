#!/usr/bin/env python3
"""
victim_traffic.py
Run this on the VICTIM host.
Simulates a real user browsing a banking site repeatedly.
CRITICAL for generating enough traffic for ML detection.

FIX: SERVER_IP can now be passed as first CLI arg,
     e.g.: python3 victim_traffic.py 10.0.0.2
"""

import requests
import time
import random
import sys
import os

# Ensure unbuffered output
sys.stdout.reconfigure(line_buffering=True)

# ── Configuration — accept CLI arg or use default ──────
SERVER_IP   = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
SERVER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
BASE_URL    = f"http://{SERVER_IP}:{SERVER_PORT}"

# ⚠️ Safety Check: Don't connect to self
try:
    import socket
    my_ip = socket.gethostbyname(socket.gethostname())
    if SERVER_IP == my_ip:
         print(f"⚠️  WARNING: Target IP {SERVER_IP} is same as local IP!")
         print("   If you are the VICTIM, you should connect to the SERVER (10.0.0.2).")
except:
    pass

SESSIONS = [
    {"user": "alice", "pass": "secret123"},
    {"user": "bob",   "pass": "password456"},
    {"user": "admin", "pass": "admin123"},
]

def log(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] {msg}", flush=True)

def run_user_session():
    session = requests.Session()
    user_creds = random.choice(SESSIONS)
    username = user_creds['user']

    try:
        # 1. Browse Homepage
        log(f"Victim browsing homepage as {username}...")
        resp = session.get(f"{BASE_URL}/", timeout=3)
        if resp.status_code != 200:
            log(f"⚠️  Unexpected status: {resp.status_code}")
            return

        time.sleep(random.uniform(0.5, 1.5))

        # 2. Login — this is what the attacker will steal
        log(f"Sending POST /login user={username} pass={user_creds['pass']}")
        login_data = {'username': username, 'password': user_creds['pass']}
        resp = session.post(f"{BASE_URL}/login", data=login_data, timeout=3)

        if "Login Successful" in resp.text:
            log("✅ Login successful (or appeared so — attacker may have relayed it)")
        else:
            log(f"❌ Login failed or modified response: {resp.text[:80]}")

        time.sleep(random.uniform(0.5, 1.5))

        # 3. View Dashboard
        log("Viewing dashboard...")
        session.get(f"{BASE_URL}/dashboard", timeout=3)

        # 4. Transfer Money (sometimes)
        if random.random() > 0.5:
            time.sleep(1)
            amount = random.randint(10, 500)
            log(f"Transferring ${amount}...")
            session.post(
                f"{BASE_URL}/transfer",
                data={'amount': amount, 'to': 'charity'},
                timeout=3
            )

    except requests.exceptions.ConnectionError as e:
        log(f"❌ Connection Error: Server unreachable — {e}")
        log("   (This is EXPECTED if Ryu has blocked the attacker and ARP table is poisoned)")
        log("   (Try: victim arp -d 10.0.0.2  to clear poisoned ARP entry)")
    except requests.exceptions.Timeout:
        log("⚠️  Timeout: Server slow to respond (possible MITM relay delay)")
    except Exception as e:
        log(f"❌ Unexpected Error: {e}")

if __name__ == "__main__":
    print(f"🚀 Starting simulated victim traffic to {BASE_URL}...")
    print(" Press Ctrl+C to stop.")
    print("-" * 40)

    # Brief wait for network to be ready
    time.sleep(2)

    while True:
        run_user_session()
        delay = random.uniform(2, 4)
        log(f"Sleeping {delay:.1f}s...")
        print("-" * 40)
        time.sleep(delay)