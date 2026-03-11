#!/usr/bin/env python3
"""
victim_traffic.py — Simulates a real user browsing a banking site.
Run on the VICTIM host.

Usage: python3 victim_traffic.py [server_ip] [server_port]
"""

import requests
import time
import random
import sys
import subprocess
import os

sys.stdout.reconfigure(line_buffering=True)

SERVER_IP   = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
SERVER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
BASE_URL    = f"http://{SERVER_IP}:{SERVER_PORT}"

SESSIONS = [
    {"user": "alice", "pass": "secret123"},
    {"user": "bob",   "pass": "password456"},
    {"user": "admin", "pass": "admin123"},
]

def log(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] {msg}", flush=True)

def refresh_arp(ip):
    """
    Delete the ARP entry for ip and re-resolve it with a fresh ping.
    This fixes "No route to host" when:
      - ARP table is poisoned (points to attacker MAC), OR
      - Ryu has blocked the attacker MAC so the old entry is dead
    """
    os.system(f"arp -d {ip} 2>/dev/null")          # flush stale entry
    os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")  # re-ARP

def run_user_session():
    session = requests.Session()
    user_creds = random.choice(SESSIONS)
    username = user_creds['user']

    try:
        # 1. Browse Homepage
        log(f"Victim browsing homepage as {username}...")
        resp = session.get(f"{BASE_URL}/", timeout=4)
        if resp.status_code != 200:
            log(f"⚠️  Unexpected status: {resp.status_code}")
            return

        time.sleep(random.uniform(0.5, 1.5))

        # 2. Login — this is what the attacker intercepts
        log(f"POST /login  user={username}  pass={user_creds['pass']}")
        resp = session.post(
            f"{BASE_URL}/login",
            data={'username': username, 'password': user_creds['pass']},
            timeout=4
        )
        if "Login Successful" in resp.text:
            log("✅ Login successful")
        else:
            log(f"⚠️  Login response: {resp.text[:80]}")

        time.sleep(random.uniform(0.5, 1.5))

        # 3. Dashboard
        log("Viewing dashboard...")
        session.get(f"{BASE_URL}/dashboard", timeout=4)

        # 4. Transfer (sometimes)
        if random.random() > 0.5:
            amount = random.randint(10, 500)
            log(f"Transferring ${amount}...")
            session.post(
                f"{BASE_URL}/transfer",
                data={'amount': amount, 'to': 'charity'},
                timeout=4
            )

    except requests.exceptions.ConnectionError as e:
        err = str(e)
        if 'Errno 113' in err or 'No route to host' in err:
            # ARP entry is dead — either poisoned or attacker was blocked by Ryu
            log(f"⚠️  No route to host — refreshing ARP for {SERVER_IP} ...")
            refresh_arp(SERVER_IP)
            log(f"   ARP refreshed. New entry: {os.popen(f'arp -n {SERVER_IP}').read().strip()}")
        elif 'Errno 111' in err or 'Connection refused' in err:
            log(f"❌ Connection refused — server not listening on port {SERVER_PORT}")
        elif 'timed out' in err.lower() or 'Errno 110' in err:
            log(f"⚠️  Timeout — MITM relay may be slow or Ryu blocking in progress")
        else:
            log(f"❌ Connection Error: {err[:200]}")

    except requests.exceptions.Timeout:
        log("⚠️  Request timed out — possible MITM relay delay")

    except Exception as e:
        log(f"❌ Unexpected: {e}")

if __name__ == "__main__":
    print(f"🚀 Victim traffic → {BASE_URL}")
    print("Press Ctrl+C to stop.")
    print("-" * 40)
    time.sleep(2)

    while True:
        run_user_session()
        delay = random.uniform(2, 4)
        log(f"Sleeping {delay:.1f}s...")
        print("-" * 40)
        time.sleep(delay)