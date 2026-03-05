#!/usr/bin/env python3
"""
victim_traffic.py
Run this on the VICTIM host (h1).
Simulates a real user browsing a banking site repeatedly.
CRITICAL for generating enough traffic for ML detection.
"""

import requests
import time
import random
import sys
import os

# Ensure unbuffered output
sys.stdout.reconfigure(line_buffering=True)

# Configuration
SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
SERVER_PORT = 8080
BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

SESSIONS = [
    {"user": "alice", "pass": "secret123"},
    {"user": "bob",   "pass": "password456"},
    {"user": "admin", "pass": "admin123"},
]

def log(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"[VICTIM] [{ts}] {msg}")

def run_user_session():
    session = requests.Session()
    user_creds = random.choice(SESSIONS)
    username = user_creds['user']
    
    try:
        # 1. Browse Homepage
        log(f"Browsing homepage as {username}...")
        resp = session.get(f"{BASE_URL}/", timeout=2)
        if resp.status_code != 200:
            log(f"⚠️  Error reaching server: {resp.status_code}")
            return

        time.sleep(random.uniform(0.5, 1.5))

        # 2. Login
        log(f"Sending POST /login user={username}")
        login_data = {'username': username, 'password': user_creds['pass']}
        resp = session.post(f"{BASE_URL}/login", data=login_data, timeout=2)
        
        if "Login Successful" in resp.text:
            log("✅ Login successful")
        else:
            log("❌ Login failed (maybe under attack?)")

        time.sleep(random.uniform(0.5, 1.5))

        # 3. View Dashboard
        log("Viewing dashboard...")
        session.get(f"{BASE_URL}/dashboard", timeout=2)

        # 4. Transfer Money (sometimes)
        if random.random() > 0.5:
            time.sleep(1)
            amount = random.randint(10, 500)
            log(f"Transferring ${amount}...")
            session.post(f"{BASE_URL}/transfer", data={'amount': amount, 'to': 'charity'}, timeout=2)

    except requests.exceptions.ConnectionError:
        log("❌ Connection Error: Server unreachable (Check if blocked?)")
    except requests.exceptions.Timeout:
        log("⚠️  Timeout: Server slow to respond")
    except Exception as e:
        log(f"❌ Error: {e}")

if __name__ == "__main__":
    print("==================================================")
    print("👤 VICTIM CLIENT STARTED")
    print(f"Target server: {SERVER_IP}")
    print("==================================================")
    print("-" * 40)
    
    # Wait for server to be ready
    time.sleep(2)
    
    while True:
        run_user_session()
        delay = random.uniform(2, 4)
        log(f"Sleeping {delay:.1f}s...")
        print("-" * 40)
        time.sleep(delay)
