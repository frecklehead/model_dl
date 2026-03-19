#!/usr/bin/env python3
"""
ssl_strip.py — SSL Stripping attack simulator (runs on device1)

Generates flow-level signatures of SSL stripping:
- Rapid TCP SYN packets to port 443 using a FIXED source port
- All packets land in the SAME flow entry in the controller
- After 20 packets, rule-based detection sees dst_port=443 → SSL STRIPPING

Usage (from Mininet CLI):
    device1 python3 /tmp/ssl_strip.py 10.0.0.2
"""
"check"
import sys, time, os

SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
IFACE = sys.argv[2] if len(sys.argv) > 2 else None
LOG = "/tmp/ssl_strip_output.txt"

def log(msg):
    ts = time.strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        open(LOG, 'a').write(line + "\n")
    except:
        pass

# Import scapy for raw packet control (fixed source port)
from scapy.all import *

# Detect interface
if not IFACE:
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip.startswith('10.0.0.'):
                IFACE = iface
                break
        except:
            continue
    if not IFACE:
        IFACE = str(conf.iface)

MY_MAC = get_if_hwaddr(IFACE)
MY_IP  = get_if_addr(IFACE)
FIXED_SPORT = 44300  # Fixed source port so all packets stay in ONE flow

log(f"[SSL-STRIP] Starting SSL Stripping simulation → {SERVER_IP}:443")
log(f"[SSL-STRIP] Interface: {IFACE}, IP: {MY_IP}, MAC: {MY_MAC}")
log(f"[SSL-STRIP] Using fixed sport={FIXED_SPORT} → dport=443 (single flow)")

# Send 30 SYN packets to port 443 with FIXED source port
# All land in the same flow → controller hits 20-packet threshold → SSL STRIPPING
for i in range(30):
    pkt = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=MY_IP, dst=SERVER_IP) /
        TCP(sport=FIXED_SPORT, dport=443, flags="S", seq=1000 + i * 100)
    )
    sendp(pkt, iface=IFACE, verbose=False)
    if i % 10 == 0:
        log(f"[SSL-STRIP] SYN burst {i+1}/30 → {SERVER_IP}:443")
    time.sleep(0.15)

log("[SSL-STRIP] Done — 30 SYN packets sent to port 443 (single flow)")
log("[SSL-STRIP] Check Ryu terminal for SSL STRIPPING detection")
