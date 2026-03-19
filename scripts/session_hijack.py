#!/usr/bin/env python3
"""
session_hijack.py — TCP Session Hijacking via RST injection (runs on device2)

Generates flow-level signatures of session hijacking:
- All packets use the SAME fixed src_port/dst_port so they land in ONE flow
- First sends ACK packets (ack_count > 5)
- Then sends RST packets (rst_ratio > 0.15)
- Controller sees the pattern → SESSION HIJACKING

Uses Scapy for raw packet injection.

Usage (from Mininet CLI):
    device2 python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2
"""
"try"
import sys, time, os
from scapy.all import *

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
IFACE     = sys.argv[3] if len(sys.argv) > 3 else None

LOG = "/tmp/session_hijack_output.txt"

def log(msg):
    ts = time.strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        open(LOG, 'a').write(line + "\n")
    except:
        pass

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

# FIXED ports so ALL packets land in the SAME flow entry
FIXED_SPORT = 55555
FIXED_DPORT = 8080

log(f"[HIJACK] Session Hijacking simulation on {IFACE}")
log(f"[HIJACK] Injecting into flow: {MY_IP}:{FIXED_SPORT} → {SERVER_IP}:{FIXED_DPORT}")
log(f"[HIJACK] All packets use same ports → single flow in controller")

# Phase 1: ACK packets (build ack_count > 5)
log("[HIJACK] Phase 1: Injecting ACK packets...")
for i in range(10):
    pkt = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=MY_IP, dst=SERVER_IP) /
        TCP(sport=FIXED_SPORT, dport=FIXED_DPORT, flags="A",
            seq=1000 + i * 100, ack=2000 + i * 100)
    )
    sendp(pkt, iface=IFACE, verbose=False)
    time.sleep(0.1)
log("[HIJACK] 10 ACK packets sent")

# Phase 2: RST injection (build rst_ratio > 0.15)
log("[HIJACK] Phase 2: RST injection...")
for i in range(25):
    pkt = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=MY_IP, dst=SERVER_IP) /
        TCP(sport=FIXED_SPORT, dport=FIXED_DPORT, flags="R",
            seq=5000 + i * 50)
    )
    sendp(pkt, iface=IFACE, verbose=False)
    if i % 10 == 0:
        log(f"[HIJACK] RST burst {i+1}/25")
    time.sleep(0.1)
log("[HIJACK] 25 RST packets sent")

log(f"[HIJACK] Total: 35 packets in flow {MY_IP}:{FIXED_SPORT}→{SERVER_IP}:{FIXED_DPORT}")
log("[HIJACK] Check Ryu for SESSION HIJACKING detection")
