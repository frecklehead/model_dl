#!/usr/bin/env python3
"""
ssl_strip.py — SSL Stripping attack simulator (runs on device1)

Generates flow-level signatures of SSL stripping:
- Rapid TCP connection attempts to port 443
- Each attempt creates SYN (s2d) + RST response (d2s) packets in the flow
- After 20 packets, the ML model sees dst_port=443 and classifies as SSL STRIPPING

Usage (from Mininet CLI):
    device1 python3 /tmp/ssl_strip.py 10.0.0.2
"""

import socket, time, sys, threading

SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
SSL_PORT  = 443   # HTTPS port — controller classifies port 443 flows as SSL Stripping
FALLBACK  = 8080  # For actual data transfer to ensure enough bytes flow

LOG = "/tmp/ssl_strip_output.txt"

def log(msg):
    ts = time.strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        open(LOG, 'a').write(line + "\n")
    except:
        pass

log(f"[SSL-STRIP] Starting SSL Stripping simulation → {SERVER_IP}:{SSL_PORT}")
log(f"[SSL-STRIP] Generating port-443 flow signatures (20 pkts needed for ML)")

# Phase 1: Rapid 443 connection attempts (each gets RST → 2 pkts per attempt)
# 15 attempts × ~2 pkts = ~30 packets → ML fires confidently
def ssl_port_flood():
    hits = 0
    for i in range(20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((SERVER_IP, SSL_PORT))   # Will get RST since nothing listens on 443
            s.close()
        except (ConnectionRefusedError, OSError):
            hits += 1  # RST received — this is exactly the packet we want
        except Exception:
            pass
        time.sleep(0.15)
    log(f"[SSL-STRIP] Phase 1 done: {hits} RST responses = ~{hits*2} packets in 443 flow")

# Phase 2: Bulk HTTP traffic with HTTPS upgrade markers (relay pattern)
def ssl_relay_traffic():
    time.sleep(1)  # after port flood has started
    for i in range(15):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((SERVER_IP, FALLBACK))
            # Send large payload with HTTPS upgrade header (SSL stripping relay signature)
            req = (b"GET / HTTP/1.1\r\n"
                   b"Host: " + SERVER_IP.encode() + b"\r\n"
                   b"Upgrade-Insecure-Requests: 1\r\n"
                   b"X-Forwarded-Proto: https\r\n\r\n")
            s.send(req)
            s.recv(4096)
            time.sleep(0.1)
            s.close()
        except Exception:
            pass
        time.sleep(0.2)
    log("[SSL-STRIP] Phase 2 done: HTTP relay traffic sent")

t1 = threading.Thread(target=ssl_port_flood, daemon=True)
t2 = threading.Thread(target=ssl_relay_traffic, daemon=True)
t1.start()
t2.start()
t1.join()
t2.join()

log("[SSL-STRIP] SSL Stripping simulation complete — check Ryu for SSL STRIPPING alert")
