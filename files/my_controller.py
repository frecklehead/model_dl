# -*- coding: utf-8 -*-
"""
my_controller.py  — Enhanced MITM Detection Controller v2.0
=========================================================
Improvements over v1.0:
  • DNS Hijacking detection (from sdn-mitm-attacks-research)
  • Dynamic ARP Inspection (DAI) — IP-to-MAC binding table
  • MAC-IP Binding Enforcement
  • Improved per-attack sub-classification
  • Detection latency measurement
  • Per-attack stats tracking
  • Structured JSON alert log
"""

import os, time, datetime, threading, json, collections
import numpy as np
import joblib
from tabulate import tabulate
from colorama import Fore, Style, init

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, ether_types
from ryu.lib import hub

init(autoreset=True)

try:
    import tensorflow as tf
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# ── Feature set (25 features, must match training) ──────────────────────────
FEATURES = [
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_packets', 'src2dst_bytes', 'dst2src_packets', 'dst2src_bytes',
    'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_mean_piat_ms',
    'bidirectional_stddev_piat_ms', 'bidirectional_syn_packets', 'bidirectional_ack_packets',
    'bidirectional_rst_packets', 'bidirectional_fin_packets', 'packet_asymmetry',
    'byte_asymmetry', 'bytes_per_packet', 'syn_ratio', 'rst_ratio',
    'piat_variance_ratio', 'protocol', 'src_port', 'dst_port', 'ps_variance_ratio'
]

# ── DNS tracking (from sdn-mitm-attacks-research) ───────────────────────────
DNS_PORT = 53


class FlowTracker:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = time.time()
        self.last_time  = time.time()
        self.first_pkt_time = time.time()  # for latency measurement

        self.s2d_packets = 0
        self.s2d_bytes   = 0
        self.d2s_packets = 0
        self.d2s_bytes   = 0

        self.packet_sizes = []
        self.piats        = []

        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0

        self.last_score  = 0.0
        self.is_mitm     = False
        self.detection_time = None  # set when first detected

    def update(self, size, direction, flags=0):
        now = time.time()
        self.piats.append((now - self.last_time) * 1000)
        self.last_time = now
        self.packet_sizes.append(size)

        if direction == 's2d':
            self.s2d_packets += 1
            self.s2d_bytes   += size
        else:
            self.d2s_packets += 1
            self.d2s_bytes   += size

        if flags & 0x02: self.syn_count += 1
        if flags & 0x10: self.ack_count += 1
        if flags & 0x04: self.rst_count += 1
        if flags & 0x01: self.fin_count += 1

    # ── Detection latency (packets elapsed) ──────────────
    @property
    def total_packets(self):
        return self.s2d_packets + self.d2s_packets

    def record_detection(self):
        if self.detection_time is None:
            self.detection_time = self.total_packets

    # ── Sub-type classification (enhanced + DNS) ──────────
    def classify_mitm_type(self):
        safe_pkts  = max(self.total_packets, 1)
        total_bytes = self.s2d_bytes + self.d2s_bytes
        pkt_asym   = abs(self.s2d_packets - self.d2s_packets) / safe_pkts
        byte_asym  = abs(self.s2d_bytes   - self.d2s_bytes)   / (total_bytes + 1)
        rst_r      = self.rst_count  / safe_pkts
        syn_r      = self.syn_count  / safe_pkts
        mean_piat  = np.mean(self.piats) if self.piats else 0
        std_piat   = np.std(self.piats)  if self.piats else 0
        piat_cv    = std_piat / (mean_piat + 1e-6)
        mean_ps    = np.mean(self.packet_sizes) if self.packet_sizes else 0

        # 1. DNS Hijacking (from sdn-mitm-attacks-research integration)
        if self.dst_port == DNS_PORT or self.src_port == DNS_PORT:
            if self.protocol == 17:  # UDP
                return ("DNS HIJACKING",
                        f"UDP/53 flow — possible DNS interception "
                        f"(pkts={safe_pkts}, mean_ps={mean_ps:.0f}B)")

        # 2. SSL Stripping — TLS-port flows
        if self.dst_port in (443, 8443) or self.src_port in (443, 8443):
            return ("SSL STRIPPING",
                    f"TLS port flow detected (port={self.dst_port or self.src_port}, "
                    f"pkts={safe_pkts})")

        # 3. Session Hijacking — RST injection
        if rst_r > 0.15 and self.ack_count > 5:
            return ("SESSION HIJACKING",
                    f"RST injection (rst_ratio={rst_r:.2f}, acks={self.ack_count})")

        # 4. Relay / Packet Interception
        if pkt_asym > 0.35 and byte_asym > 0.30:
            return ("PACKET INTERCEPTION",
                    f"Bidirectional asymmetry (pkt={pkt_asym:.2f}, byte={byte_asym:.2f})")

        # 5. Relay Flood — low PIAT variance (robotic traffic)
        if self.total_packets > 30 and piat_cv < 0.5 and mean_piat < 50:
            return ("RELAY FLOOD",
                    f"Automated relay (piat_cv={piat_cv:.2f}, mean_piat={mean_piat:.1f}ms)")

        # 6. Mild asymmetry
        if pkt_asym > 0.15:
            return ("TRAFFIC RELAY",
                    f"Mild asymmetry (pkt_asym={pkt_asym:.2f})")

        return ("ML ANOMALY", "Flow statistics deviate from normal baseline")

    def get_features(self):
        duration    = (self.last_time - self.start_time) * 1000
        total_pkts  = self.total_packets
        total_bytes = self.s2d_bytes + self.d2s_bytes
        mean_ps     = np.mean(self.packet_sizes) if self.packet_sizes else 0
        std_ps      = np.std(self.packet_sizes)  if self.packet_sizes else 0
        mean_piat   = np.mean(self.piats) if self.piats else 0
        std_piat    = np.std(self.piats)  if self.piats else 0
        safe_pkts   = max(total_pkts, 1)
        return {
            'bidirectional_duration_ms':    duration,
            'bidirectional_packets':        total_pkts,
            'bidirectional_bytes':          total_bytes,
            'src2dst_packets':              self.s2d_packets,
            'src2dst_bytes':                self.s2d_bytes,
            'dst2src_packets':              self.d2s_packets,
            'dst2src_bytes':                self.d2s_bytes,
            'bidirectional_mean_ps':        mean_ps,
            'bidirectional_stddev_ps':      std_ps,
            'bidirectional_mean_piat_ms':   mean_piat,
            'bidirectional_stddev_piat_ms': std_piat,
            'bidirectional_syn_packets':    self.syn_count,
            'bidirectional_ack_packets':    self.ack_count,
            'bidirectional_rst_packets':    self.rst_count,
            'bidirectional_fin_packets':    self.fin_count,
            'packet_asymmetry':  abs(self.s2d_packets - self.d2s_packets) / safe_pkts,
            'byte_asymmetry':    abs(self.s2d_bytes   - self.d2s_bytes)   / (total_bytes + 1),
            'bytes_per_packet':  total_bytes / safe_pkts,
            'syn_ratio':         self.syn_count / safe_pkts,
            'rst_ratio':         self.rst_count / safe_pkts,
            'piat_variance_ratio': (std_piat**2) / (mean_piat + 1),
            'protocol':          self.protocol,
            'src_port':          self.src_port,
            'dst_port':          self.dst_port,
            'ps_variance_ratio': (std_ps**2)   / (mean_ps   + 1),
        }


class MITMController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port   = {}
        self.arp_table     = {}           # IP → MAC  (legitimate bindings)
        self.dai_bindings  = {}           # IP → set of MACs seen (DAI)
        self.dns_responses = {}           # domain → set of IPs  (DNS hijack track)
        self.flows         = {}
        self.datapaths     = {}
        self.blocked_macs  = set()
        self.blocked_ips   = set()
        self.detections    = []
        self.triggered_alerts = set()

        # ── Per-attack-type counters ─────────────────────
        self.attack_counts = collections.defaultdict(int)
        self.latency_log   = []           # (attack_type, detection_packet_count)

        # ── Alert log (JSON) ─────────────────────────────
        self.alert_log_path = "/tmp/mitm_alerts.json"
        open(self.alert_log_path, 'w').write('[]')

        self.model  = None
        self.scaler = None
        self._load_model()
        self._print_header()
        self.stats_thread = hub.spawn(self._stats_timer)

    # ── Model loading ────────────────────────────────────
    def _load_model(self):
        m_path = "/app/model/mitm_model.h5"
        s_path = "/app/model/scaler.pkl"
        if ML_AVAILABLE and os.path.exists(m_path):
            try:
                self.model  = tf.keras.models.load_model(m_path)
                if os.path.exists(s_path):
                    self.scaler = joblib.load(s_path)
                self.logger.info("✅ CNN+LSTM Model loaded successfully.")
            except Exception as e:
                self.logger.error(f"Model load failed: {e}")

    def _print_header(self):
        print(Fore.CYAN + Style.BRIGHT + "╔══════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "║  MITM DETECTION CONTROLLER v2.0             ║")
        print(Fore.CYAN + Style.BRIGHT + "║  Layer 1: ARP Poisoning  (Rule-based)       ║")
        print(Fore.CYAN + Style.BRIGHT + "║  Layer 2: DNS Hijacking  (Rule-based)       ║")
        print(Fore.CYAN + Style.BRIGHT + "║  Layer 3: SSL/Session    (Rule-based)       ║")
        print(Fore.CYAN + Style.BRIGHT + "║  Layer 4: CNN+LSTM       (ML Model)         ║")
        print(Fore.CYAN + Style.BRIGHT + "╚══════════════════════════════════════════════╝")
        ml_status = "✅ LOADED" if self.model else "❌ NOT FOUND"
        print(f"  ML Model: {ml_status}")

    # ── Datapath tracking ────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp      = ev.msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser

        for attr in ('mac_to_port', 'arp_table', 'dai_bindings', 'dns_responses',
                     'flows', 'blocked_macs', 'blocked_ips', 'detections',
                     'triggered_alerts', 'attack_counts', 'latency_log'):
            obj = getattr(self, attr)
            if isinstance(obj, dict):   obj.clear()
            elif isinstance(obj, set):  obj.clear()
            elif isinstance(obj, list): obj.clear()
            elif isinstance(obj, collections.defaultdict): obj.clear()

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] Switch {dp.id} connected — state reset.")

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions, buffer_id=None):
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs  = dict(datapath=dp, priority=priority, match=match, instructions=inst)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        dp.send_msg(parser.OFPFlowMod(**kwargs))

    # ── Packet-in handler ────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        dp       = msg.datapath
        ofproto  = dp.ofproto
        parser   = dp.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ts       = datetime.datetime.now().strftime('%H:%M:%S')
        src_mac  = eth.src
        dst_mac  = eth.dst

        if src_mac in self.blocked_macs:
            return

        # ── ARP handling ─────────────────────────────────
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(dp, in_port, pkt_arp, eth, ts)

        # ── IP handling ──────────────────────────────────
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            if pkt_ipv4.src in self.blocked_ips:
                return
            self._handle_ipv4(dp, in_port, pkt, pkt_ipv4, eth, ts)

        # ── MAC learning + forwarding ─────────────────────
        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][src_mac] = in_port
        out_port = self.mac_to_port[dp.id].get(dst_mac, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        data    = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out     = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ── ARP handler (Layer 1 + DAI) ───────────────────────
    def _handle_arp(self, dp, in_port, pkt_arp, eth, ts):
        opcode  = "REQUEST" if pkt_arp.opcode == arp.ARP_REQUEST else "REPLY"
        print(f"[{ts}] [{Fore.YELLOW}ARP  {Style.RESET_ALL}] "
              f"{opcode:<8} {pkt_arp.src_ip} ({eth.src}) → {pkt_arp.dst_ip}")

        src_ip, src_mac = pkt_arp.src_ip, eth.src

        # ── Layer 1: Classic ARP spoof (IP-MAC mismatch) ──
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                known = self.arp_table[src_ip]
                self._trigger_detection(
                    "ARP POISONING", src_ip, src_mac, dp, in_port,
                    f"IP {src_ip} was bound to {known}, now claiming {src_mac}"
                )
        else:
            self.arp_table[src_ip] = src_mac

        # ── DAI: track all MACs claiming each IP ─────────
        self.dai_bindings.setdefault(src_ip, set()).add(src_mac)
        if len(self.dai_bindings[src_ip]) > 1:
            macs_str = ', '.join(sorted(self.dai_bindings[src_ip]))
            self._trigger_detection(
                "ARP POISONING (DAI)",
                src_ip, src_mac, dp, in_port,
                f"Dynamic ARP Inspection: {len(self.dai_bindings[src_ip])} "
                f"MACs claim IP {src_ip} — [{macs_str}]"
            )

    # ── IPv4 handler ──────────────────────────────────────
    def _handle_ipv4(self, dp, in_port, pkt, pkt_ipv4, eth, ts):
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        proto  = pkt_ipv4.proto

        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        src_port, dst_port, flags = 0, 0, 0

        if pkt_tcp:
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
            flags    = pkt_tcp.bits
            type_str = ("HTTP " if dst_port in (80, 443, 8080) or
                                   src_port in (80, 443, 8080) else "TCP  ")
        elif pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            type_str = "DNS  " if dst_port == DNS_PORT or src_port == DNS_PORT else "UDP  "

            # ── Layer 2: DNS Hijacking (sdn-mitm-attacks-research) ──
            self._check_dns_hijacking(pkt_udp, src_ip, dst_ip, eth.src, ts, dp, in_port)
        else:
            type_str = "IP   "

        print(f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] "
              f"{src_ip}:{src_port} → {dst_ip}:{dst_port}")

        # ── Flow tracking ─────────────────────────────────
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)

        direction = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        self.flows[key].update(pkt_ipv4.total_length, direction, flags)

        flow     = self.flows[key]
        total_p  = flow.total_packets

        # ── Layer 3: Rule-based (every 10 pkts after 20) ─
        if total_p >= 20 and total_p % 10 == 0:
            self._check_flow_rules(flow, ts, dp, eth.src)

        # ── Layer 4: ML (every 20 pkts) ──────────────────
        if total_p % 20 == 0:
            self._run_ml(key, ts, dp, eth.src)

    # ── DNS Hijacking detection ───────────────────────────
    def _check_dns_hijacking(self, pkt_udp, src_ip, dst_ip, src_mac, ts, dp, in_port):
        """
        Track DNS response IPs per domain.
        If the same domain resolves to different IPs → DNS hijacking.
        (Inspired by sdn-mitm-attacks-research / hijack_switch.py)
        """
        try:
            payload = bytes(pkt_udp.data) if pkt_udp.data else b''
            # Heuristic: DNS response has QR=1 (byte 2, bit 7 set) and ANCOUNT > 0
            if len(payload) >= 12:
                flags_hi = payload[2]
                qr_bit   = (flags_hi >> 7) & 1
                ancount  = int.from_bytes(payload[6:8], 'big')
                if qr_bit == 1 and ancount > 0:
                    # Very basic domain extraction (first query label)
                    pos = 12
                    domain_parts = []
                    while pos < len(payload) and payload[pos] != 0:
                        length = payload[pos]
                        if pos + 1 + length > len(payload):
                            break
                        domain_parts.append(payload[pos+1:pos+1+length].decode('ascii', errors='ignore'))
                        pos += 1 + length
                    domain = '.'.join(domain_parts) if domain_parts else f'unknown@{src_ip}'

                    self.dns_responses.setdefault(domain, set()).add(src_ip)
                    if len(self.dns_responses[domain]) > 1:
                        all_ips = ', '.join(sorted(self.dns_responses[domain]))
                        self._trigger_detection(
                            "DNS HIJACKING", src_ip, src_mac, dp, in_port,
                            f"Domain '{domain}' resolved to multiple IPs: [{all_ips}]"
                        )
        except Exception:
            pass  # DNS parsing is best-effort

    # ── Rule-based sub-type check ─────────────────────────
    def _check_flow_rules(self, flow, ts, dp, src_mac):
        total_pkts = flow.total_packets
        safe_pkts  = max(total_pkts, 1)
        rst_r      = flow.rst_count / safe_pkts

        if flow.dst_port in (443, 8443) or flow.src_port in (443, 8443):
            self._trigger_detection(
                "SSL STRIPPING", flow.src_ip, src_mac, dp, 0,
                f"TLS port flow (port={flow.dst_port}, pkts={total_pkts})"
            )

        if rst_r > 0.15 and flow.ack_count > 5:
            self._trigger_detection(
                "SESSION HIJACKING", flow.src_ip, src_mac, dp, 0,
                f"RST injection (rst_ratio={rst_r:.2f}, acks={flow.ack_count}, pkts={total_pkts})"
            )

    # ── ML detection ─────────────────────────────────────
    def _run_ml(self, key, ts, dp, src_mac):
        if not self.model:
            return
        flow = self.flows[key]
        feat_dict = flow.get_features()
        try:
            vector = np.array([[feat_dict[f] for f in FEATURES]], dtype=np.float32)
            if self.scaler:
                vector = self.scaler.transform(vector)
            vector = vector.reshape(1, vector.shape[1], 1)
            score  = float(self.model.predict(vector, verbose=0)[0][0])
        except Exception as e:
            self.logger.error(f"ML error: {e}")
            return

        flow.last_score = score
        status = f"{Fore.RED}MITM 🚨" if score > 0.5 else f"{Fore.GREEN}NORMAL ✅"
        print(f"[{ts}] [{Fore.MAGENTA}ML   {Style.RESET_ALL}] "
              f"{flow.src_ip}→{flow.dst_ip} | "
              f"pkts={flow.total_packets} | score={score:.4f} | {status}")

        if score > 0.8:
            flow.is_mitm = True
            attack_type, reason = flow.classify_mitm_type()
            flow.record_detection()
            self._trigger_detection(attack_type, flow.src_ip, src_mac, dp, 0, reason)

    # ── Central detection + blocking ─────────────────────
    def _trigger_detection(self, d_type, ip, mac, dp, port, details):
        alert_key = (ip, mac, d_type)
        if alert_key in self.triggered_alerts:
            return
        self.triggered_alerts.add(alert_key)

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self.attack_counts[d_type] += 1

        # ── Console output ────────────────────────────────
        print(Fore.RED + Style.BRIGHT +
              "\n╔════════════════════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT +
              f"║  🚨 MITM ATTACK DETECTED — {d_type:<36}║")
        print(Fore.RED + Style.BRIGHT +
              f"║  Time:    {ts:<48}║")
        print(Fore.RED + Style.BRIGHT +
              f"║  Host IP: {ip:<48}║")
        print(Fore.RED + Style.BRIGHT +
              f"║  MAC:     {mac:<48}║")
        print(Fore.RED + Style.BRIGHT +
              f"║  Details: {details[:48]:<48}║")
        print(Fore.RED + Style.BRIGHT +
              "║  Action:  MAC + IP DROP rule installed                    ║")
        print(Fore.RED + Style.BRIGHT +
              "╚════════════════════════════════════════════════════════════╝\n")

        # ── Log ───────────────────────────────────────────
        self.detections.append(f"[{ts}] {d_type:<26} {ip}")
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)

        # ── JSON alert log ────────────────────────────────
        alert = {
            "timestamp": ts,
            "attack_type": d_type,
            "src_ip": ip,
            "src_mac": mac,
            "details": details,
            "action": "BLOCKED"
        }
        try:
            existing = json.loads(open(self.alert_log_path).read() or '[]')
            existing.append(alert)
            open(self.alert_log_path, 'w').write(json.dumps(existing, indent=2))
        except Exception:
            pass

        # ── Install DROP rules ────────────────────────────
        parser      = dp.ofproto_parser
        match_mac   = parser.OFPMatch(eth_src=mac)
        self.add_flow(dp, 100, match_mac, [])
        match_ip    = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, 100, match_ip,  [])

    # ── Stats dashboard (every 30s) ───────────────────────
    def _stats_timer(self):
        while True:
            hub.sleep(30)
            self._print_stats()

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"\n{Fore.CYAN}══════════ NETWORK STATS [{ts}] ══════════")
        print(f"  Switches  : {len(self.datapaths)}")
        print(f"  MACs      : {sum(len(v) for v in self.mac_to_port.values())}")
        print(f"  ARP table : {len(self.arp_table)} entries")
        print(f"  Active flows: {len(self.flows)}")

        print(Fore.CYAN + "  ── Attack Counts ──")
        for atype, count in sorted(self.attack_counts.items()):
            print(f"    {atype:<28} : {count}")

        print(Fore.CYAN + "  ── Active Flows (last 5) ──")
        flow_rows = []
        for f in list(self.flows.values())[-5:]:
            dur  = int(time.time() - f.start_time)
            warn = " ⚠️" if f.last_score > 0.5 else ""
            flow_rows.append([
                f"{f.src_ip} → {f.dst_ip}",
                f.total_packets,
                f.s2d_bytes + f.d2s_bytes,
                f"{dur}s",
                f"{f.last_score:.2f}{warn}"
            ])
        if flow_rows:
            print(tabulate(flow_rows,
                           headers=["Flow", "Pkts", "Bytes", "Dur", "Score"],
                           tablefmt="simple"))

        print(Fore.CYAN + "  ── Recent Detections ──")
        for d in self.detections[-5:]:
            print(f"    {Fore.RED}{d}")
        if not self.detections:
            print("    (none)")

        print(f"{Fore.CYAN}  Blocked MACs: {', '.join(self.blocked_macs) or '(none)'}")
        print(f"{Fore.CYAN}  Blocked IPs : {', '.join(self.blocked_ips)  or '(none)'}")
        print(Fore.CYAN + "══════════════════════════════════════════\n")


if __name__ == '__main__':
    pass
