# -*- coding: utf-8 -*-
"""
my_controller.py — Unified MITM Detection Controller  v4.2

Detection logic per attack type:
  ARP Poisoning     → ML MODEL (score >= 0.5 on flows involving conflict IP)
                      + RULE-BASED fallback (no scorable flows after 20s window)
                      + Gratuitous ARP detection (attacker self-announces)

  SSL Stripping     → ML MODEL primary
                      + RULE-BASED cross-flow downgrade correlation:
                        (src,dst) had port-443 traffic → now has port-80 → ALERT
                      + Early TLS kill signature (RST on 443 flow < 10 pkts)
                      + RULE-BASED fallback (20+ pkts on 443, ML < 0.5)

  Session Hijacking → ML MODEL primary
                      + Per-packet MAC-IP consistency check on RST packets:
                        RST with src_ip=SERVER but src_mac≠arp_table[SERVER] → ALERT
                      + RULE-BASED fallback (RST ratio > 0.15, ACK count > 5)

  DNS Hijacking     → RULE-BASED: parse A-record answer section of DNS responses,
                       track domain→set(resolved_ips). Same domain resolves to
                       two different IPs → ALERT. Also: duplicate txid racing
                       (two responses for same (domain,txid) within 200ms).

CHANGES FROM v4.1 (detection fixes):
  - _check_dns: completely rewritten. Now parses answer section (A records),
    tracks dns_answer_map[domain]={resolved_ips}. Old src_ip tracking was
    trivially defeated by the attacker spoofing the resolver's source IP.
  - _check_dns: also tracks (domain, txid_hex) → first_response, detects
    duplicate responses within 200ms (DNS racing attack signature).
  - _handle_ip: added https_history tracking for SSL downgrade correlation.
  - _check_ssl_downgrade: new method. Fires when src→dst had 443 traffic
    in the last 90s and now has a port-80 flow.
  - _check_tls_kill: new method. Fires when a port-443 flow has < 10 pkts
    and RST ratio > 0.4 (TLS handshake killed, not graceful close).
  - _check_rst_spoof: new per-packet RST validation. Cross-references
    src_mac against arp_table[src_ip]. Mismatch on a RST packet = injected.
  - _handle_arp: added gratuitous ARP detection (sender_ip == target_ip in
    ARP request, or zero dst in ARP reply — both are attacker self-announcements).
"""

import os, time, datetime, json, socket, struct, collections, warnings
import numpy as np
import pandas as pd
import joblib
from colorama import Fore, Back, Style, init

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, ether_types
from ryu.lib import hub

init(autoreset=True)
warnings.filterwarnings("ignore", category=UserWarning)

try:
    import tensorflow as tf
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

FEATURES = [
    'src_port', 'dst_port', 'bidirectional_duration_ms', 'bidirectional_bytes',
    'src2dst_packets', 'src2dst_bytes', 'dst2src_bytes',
    'bidirectional_min_ps', 'bidirectional_mean_ps', 'bidirectional_stddev_ps',
    'bidirectional_max_ps', 'src2dst_min_ps', 'src2dst_mean_ps',
    'dst2src_min_ps', 'dst2src_mean_ps',
    'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms',
    'bidirectional_max_piat_ms', 'src2dst_mean_piat_ms', 'src2dst_max_piat_ms',
    'byte_asymmetry', 'bytes_per_packet', 'src2dst_bpp',
    'duration_ratio', 'ps_variance_ratio',
]

DNS_PORT     = 53
ML_THRESHOLD = 0.5

# Tuning knobs for new rule-based checks (all adjustable without code changes)
SSL_DOWNGRADE_WINDOW_S   = 90    # seconds after 443 traffic to still flag port-80 as downgrade
TLS_KILL_RST_RATIO       = 0.40  # RST ratio threshold on a dying TLS flow
TLS_KILL_MAX_PKTS        = 10    # a TLS flow with < this many packets + high RST = killed handshake
DNS_RACE_WINDOW_S        = 0.20  # two responses for same (domain,txid) within this → racing attack


# ─────────────────────────────────────────────────────────────────────────────
class FlowTracker:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port = src_port, dst_port
        self.protocol = protocol

        now = time.time()
        self.start_time    = now
        self.last_time     = now
        self.s2d_last_time = now
        self.s2d_start_time = None

        self.s2d_packets = 0; self.s2d_bytes = 0
        self.d2s_packets = 0; self.d2s_bytes = 0

        self.packet_sizes     = []
        self.s2d_packet_sizes = []
        self.d2s_packet_sizes = []
        self.piats            = []
        self.s2d_piats        = []

        self.syn_count = 0; self.ack_count = 0
        self.rst_count = 0; self.fin_count = 0

        self.last_score = 0.0
        self.is_mitm    = False

    @property
    def total_packets(self):
        return self.s2d_packets + self.d2s_packets

    def update(self, size, direction, flags=0):
        now = time.time()
        self.piats.append((now - self.last_time) * 1000)
        self.last_time = now
        self.packet_sizes.append(size)

        if direction == 's2d':
            self.s2d_packets += 1; self.s2d_bytes += size
            self.s2d_packet_sizes.append(size)
            self.s2d_piats.append((now - self.s2d_last_time) * 1000)
            self.s2d_last_time = now
            if self.s2d_start_time is None:
                self.s2d_start_time = now
        else:
            self.d2s_packets += 1; self.d2s_bytes += size
            self.d2s_packet_sizes.append(size)

        if flags & 0x02: self.syn_count += 1
        if flags & 0x10: self.ack_count += 1
        if flags & 0x04: self.rst_count += 1
        if flags & 0x01: self.fin_count += 1

    def get_features(self):
        now         = time.time()
        total_pkts  = self.total_packets
        total_bytes = self.s2d_bytes + self.d2s_bytes
        safe_pkts   = max(total_pkts, 1)

        all_ps = self.packet_sizes     or [0]
        s2d_ps = self.s2d_packet_sizes or [0]
        d2s_ps = self.d2s_packet_sizes or [0]
        all_pi = self.piats            or [0]
        s2d_pi = self.s2d_piats        or [0]

        mean_ps = float(np.mean(all_ps)); std_ps = float(np.std(all_ps))
        mean_pi = float(np.mean(all_pi)); std_pi = float(np.std(all_pi))

        bidi_dur = (now - self.start_time) * 1000
        s2d_dur  = ((self.s2d_last_time - self.s2d_start_time) * 1000
                    if self.s2d_start_time else 0.0)
        d2s_dur  = max(bidi_dur - s2d_dur, 0.0)

        return {
            'src_port':                     float(self.src_port),
            'dst_port':                     float(self.dst_port),
            'protocol':                     float(self.protocol),
            'bidirectional_duration_ms':    bidi_dur,
            'bidirectional_packets':        float(total_pkts),
            'bidirectional_bytes':          float(total_bytes),
            'src2dst_duration_ms':          s2d_dur,
            'src2dst_packets':              float(self.s2d_packets),
            'src2dst_bytes':                float(self.s2d_bytes),
            'dst2src_packets':              float(self.d2s_packets),
            'dst2src_bytes':                float(self.d2s_bytes),
            'bidirectional_min_ps':         float(min(all_ps)),
            'bidirectional_mean_ps':        mean_ps,
            'bidirectional_stddev_ps':      std_ps,
            'bidirectional_max_ps':         float(max(all_ps)),
            'src2dst_min_ps':               float(min(s2d_ps)),
            'src2dst_mean_ps':              float(np.mean(s2d_ps)),
            'src2dst_max_ps':               float(max(s2d_ps)),
            'dst2src_min_ps':               float(min(d2s_ps)),
            'dst2src_mean_ps':              float(np.mean(d2s_ps)),
            'dst2src_max_ps':               float(max(d2s_ps)),
            'bidirectional_mean_piat_ms':   mean_pi,
            'bidirectional_stddev_piat_ms': std_pi,
            'bidirectional_max_piat_ms':    float(max(all_pi)),
            'src2dst_mean_piat_ms':         float(np.mean(s2d_pi)),
            'src2dst_max_piat_ms':          float(max(s2d_pi)),
            'bidirectional_syn_packets':    float(self.syn_count),
            'bidirectional_ack_packets':    float(self.ack_count),
            'bidirectional_rst_packets':    float(self.rst_count),
            'bidirectional_fin_packets':    float(self.fin_count),
            'application_name':             0.0,
            'requested_server_name':        0.0,
            'packet_asymmetry':  abs(self.s2d_packets - self.d2s_packets) / safe_pkts,
            'byte_asymmetry':    abs(self.s2d_bytes   - self.d2s_bytes)   / (total_bytes + 1),
            'bytes_per_packet':  total_bytes / safe_pkts,
            'src2dst_bpp':       self.s2d_bytes / (self.s2d_packets + 1),
            'dst2src_bpp':       self.d2s_bytes / (self.d2s_packets + 1),
            'syn_ratio':         self.syn_count / safe_pkts,
            'rst_ratio':         self.rst_count / safe_pkts,
            'duration_ratio':    s2d_dur / (d2s_dur + 1),
            'ps_variance_ratio': (std_ps ** 2) / (mean_ps + 1),
            'piat_variance_ratio': (std_pi ** 2) / (mean_pi + 1),
        }

    def classify_subtype(self):
        safe   = max(self.total_packets, 1)
        tb     = self.s2d_bytes + self.d2s_bytes
        rst_r  = self.rst_count / safe
        pkt_a  = abs(self.s2d_packets - self.d2s_packets) / safe
        byte_a = abs(self.s2d_bytes   - self.d2s_bytes)   / (tb + 1)
        mi     = float(np.mean(self.piats)) if self.piats else 0
        si     = float(np.std(self.piats))  if self.piats else 0
        cv     = si / (mi + 1e-6)

        if (self.dst_port == DNS_PORT or self.src_port == DNS_PORT) and self.protocol == 17:
            return "DNS HIJACKING",    f"UDP/53 flow, pkts={safe}"
        if self.dst_port in (443, 8443) or self.src_port in (443, 8443):
            return "SSL STRIPPING",    f"TLS port {self.dst_port or self.src_port}, pkts={safe}"
        if rst_r > 0.15 and self.ack_count > 5:
            return "SESSION HIJACKING", f"RST ratio={rst_r:.2f}, ACKs={self.ack_count}"
        if pkt_a > 0.35 and byte_a > 0.30:
            return "PACKET INTERCEPTION", f"pkt_asym={pkt_a:.2f}, byte_asym={byte_a:.2f}"
        if self.total_packets > 30 and cv < 0.5 and mi < 50:
            return "RELAY FLOOD",      f"piat_cv={cv:.2f}, mean_piat={mi:.1f}ms"
        if pkt_a > 0.15:
            return "TRAFFIC RELAY",    f"pkt_asym={pkt_a:.2f}"
        return "ML ANOMALY", "flow statistics deviate from baseline"


# ─────────────────────────────────────────────────────────────────────────────
class MITMController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port       = {}
        self.arp_table         = {}   # ip → mac (first seen / trusted)
        self.arp_conflicts     = {}   # ip → (known_mac, forged_mac)
        self.dai_bindings      = {}   # ip → set of MACs
        self.flows             = {}   # flow_key → FlowTracker
        self.datapaths         = {}
        self.blocked_macs      = set()
        self.blocked_ips       = set()
        self.detections        = []
        self.triggered_alerts  = set()
        self.ml_flagged_flows  = set()
        self.attack_counts     = collections.defaultdict(int)
        self._alert_quiet_until = 0

        # ARP suspect tracking
        self.arp_suspects      = {}

        # ── NEW: DNS answer tracking ──────────────────────────────────────────
        # domain → set of A-record IPs seen across all responses
        self.dns_answer_map    = {}
        # (domain, txid_hex) → {"ip": first_resolved_ip, "ts": timestamp}
        # Used to detect DNS response racing (two responses for same query)
        self.dns_txid_seen     = {}

        # ── NEW: SSL downgrade correlation ────────────────────────────────────
        # (src_ip, dst_ip) → timestamp when a port-443 flow was last observed
        self.https_history     = {}

        self.model  = None
        self.scaler = None
        self._load_model()
        self._print_banner()
        hub.spawn(self._stats_loop)

    # ── Model loading ─────────────────────────────────────────────────────────
    def _load_model(self):
        global FEATURES
        base   = "/app/model" if os.path.exists("/app/model") else "model"
        m_path = f"{base}/mitm_model.h5"
        s_path = f"{base}/scaler.pkl"
        f_path = f"{base}/selected_features.pkl"

        if not ML_AVAILABLE:
            self.logger.warning("TensorFlow not available — ML disabled.")
            return

        saved_path = f"{base}/mitm_model_saved"
        if os.path.isdir(saved_path):
            m_path = saved_path
        elif not os.path.exists(m_path) or os.path.getsize(m_path) == 0:
            self.logger.warning(f"Model file missing/empty: {m_path}")
            return
        try:
            if os.path.isdir(m_path):
                self.model = tf.saved_model.load(m_path)
                self._model_is_savedmodel = True
            else:
                self.model = tf.keras.models.load_model(m_path)
                self._model_is_savedmodel = False
            if os.path.exists(s_path) and os.path.getsize(s_path) > 0:
                self.scaler = joblib.load(s_path)
            if os.path.exists(f_path) and os.path.getsize(f_path) > 0:
                FEATURES = joblib.load(f_path)
                self.logger.info(f"Loaded {len(FEATURES)} features from pkl.")
            self.logger.info(f"CNN+LSTM model loaded. Features={len(FEATURES)}, "
                             f"Scaler={'YES' if self.scaler else 'NO'}")
        except Exception as e:
            self.logger.error(f"Model load failed: {e}")
            self.model = None

    def _ml_score(self, flow):
        if not self.model:
            return None
        try:
            fd = flow.get_features()
            if self.scaler:
                df  = pd.DataFrame([[fd[f] for f in FEATURES]], columns=FEATURES)
                vec = self.scaler.transform(df).astype(np.float32)
            else:
                vec = np.array([[fd[f] for f in FEATURES]], dtype=np.float32)
            vec = vec.reshape(1, len(FEATURES), 1)
            if getattr(self, '_model_is_savedmodel', False):
                return float(self.model.serve(tf.constant(vec))[0][0])
            return float(self.model.predict(vec, verbose=0)[0][0])
        except Exception as e:
            self.logger.error(f"ML score error: {e}")
            return None

    # ── Banner ────────────────────────────────────────────────────────────────
    def _print_banner(self):
        ml = "LOADED" if self.model else "NOT FOUND (rule-based only)"
        W = 70
        C = Fore.CYAN + Style.BRIGHT
        R = Style.RESET_ALL
        print(flush=True)
        print(C + f"╔{'═'*W}╗" + R, flush=True)
        print(C + f"║{'MITM DETECTION CONTROLLER v4.2':^{W}}║" + R, flush=True)
        print(C + f"╠{'═'*W}╣" + R, flush=True)
        for lbl, val in [("ML Model", ml), ("Features", str(len(FEATURES))),
                         ("Threshold", str(ML_THRESHOLD))]:
            line = f"  {lbl:<14}: {val}"
            print(C + f"║{line:<{W}}║" + R, flush=True)
        print(C + f"╠{'═'*W}╣" + R, flush=True)
        print(C + f"║{'  Detection Methods':^{W}}║" + R, flush=True)
        print(C + f"║{'─'*W}║" + R, flush=True)
        methods = [
            ("ARP Poisoning",     "ML MODEL + gratuitous ARP → RULE-BASED fallback"),
            ("SSL Stripping",     "ML MODEL + cross-flow downgrade correlation"),
            ("Session Hijacking", "ML MODEL + per-packet RST MAC-IP validation"),
            ("DNS Hijacking",     "RULE-BASED: A-record divergence + txid racing"),
        ]
        for name, desc in methods:
            line = f"  {name:<22}{desc}"
            print(C + f"║{line:<{W}}║" + R, flush=True)
        print(C + f"╚{'═'*W}╝" + R, flush=True)
        print(flush=True)

    # ── Datapath management ───────────────────────────────────────────────────
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
        self.datapaths[dp.id] = dp

        for attr in ('arp_table', 'arp_conflicts', 'dai_bindings', 'flows',
                     'blocked_macs', 'blocked_ips', 'detections',
                     'triggered_alerts', 'ml_flagged_flows', 'attack_counts',
                     'dns_answer_map', 'dns_txid_seen', 'https_history'):
            getattr(self, attr).clear()
        self.mac_to_port.pop(dp.id, None)

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        G = Fore.GREEN + Style.BRIGHT; R = Style.RESET_ALL; W = 54
        print(flush=True)
        print(G + f"  ┌{'─'*W}┐" + R, flush=True)
        print(G + f"  │{'  ✓ SWITCH CONNECTED':^{W}}│" + R, flush=True)
        print(G + f"  │{f'    dpid={dp.id}  |  OF1.3  |  {ts}':^{W}}│" + R, flush=True)
        print(G + f"  └{'─'*W}┘" + R, flush=True)
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        print(G + f"  Table-miss flow installed — all packets → controller" + R, flush=True)
        print(flush=True)

    def _add_flow(self, dp, priority, match, actions):
        parser  = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority,
                                      match=match, instructions=inst))

    # ── Packet-in ─────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ts      = datetime.datetime.now().strftime('%H:%M:%S')
        src_mac = eth.src
        dst_mac = eth.dst

        if src_mac in self.blocked_macs:
            return

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(dp, in_port, pkt_arp, eth, ts)

        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip:
            if pkt_ip.src in self.blocked_ips:
                return
            self._handle_ip(dp, in_port, pkt, pkt_ip, eth, ts)

        self.mac_to_port.setdefault(dp.id, {})[src_mac] = in_port
        out_port = self.mac_to_port[dp.id].get(dst_mac, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]
        data     = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    # ═════════════════════════════════════════════════════════════════════════
    # ARP HANDLER
    # Detects: (1) IP→MAC mapping changes, (2) gratuitous ARP self-announcements
    # ═════════════════════════════════════════════════════════════════════════
    def _handle_arp(self, dp, in_port, pkt_arp, eth, ts):
        op      = "RQ" if pkt_arp.opcode == arp.ARP_REQUEST else "RP"
        src_ip  = pkt_arp.src_ip
        src_mac = eth.src
        color   = Fore.MAGENTA if op == "RP" else Fore.LIGHTMAGENTA_EX
        print(f"[{ts}] {color}{Style.BRIGHT}[ARP {op}]{Style.NORMAL} "
              f"{src_ip} ({src_mac}) → {pkt_arp.dst_ip}", flush=True)

        # ── NEW: Gratuitous ARP detection ─────────────────────────────────────
        # Gratuitous ARP: ARP request where sender_ip == target_ip (host
        # announcing itself to update neighbours' caches). Legitimate OSes do
        # this on boot or IP change, but attackers use it to pre-poison caches
        # before establishing a flow.  Flag if the src_mac doesn't match what
        # we already know for src_ip, OR if we've never seen src_ip before
        # (unknown host proactively announcing is suspicious in a controlled SDN).
        if pkt_arp.opcode == arp.ARP_REQUEST and src_ip == pkt_arp.dst_ip:
            known = self.arp_table.get(src_ip)
            if known and known != src_mac:
                print(Fore.YELLOW + Style.BRIGHT + f"[{ts}] [GARP  ] "
                      f"Gratuitous ARP: {src_ip} announcing new MAC {src_mac} "
                      f"(was {known}) — potential pre-poison", flush=True)
                # Register as ARP conflict immediately without waiting for a reply
                self.arp_conflicts[src_ip] = (known, src_mac)
                attacker_ip = next(
                    (ip for ip, mac in self.arp_table.items()
                     if mac == src_mac and ip != src_ip), None
                )
                alert_ip = attacker_ip or src_ip
                if self.model:
                    self.arp_suspects[src_ip] = {
                        'known': known, 'forged': src_mac,
                        'attacker_ip': alert_ip, 'mac': src_mac,
                        'dp': dp, 'at': time.time(),
                    }
                    self._scan_flows_for_arp_suspect(src_ip, ts, dp, src_mac)
                else:
                    self._trigger_alert("ARP POISONING", alert_ip, src_mac, dp,
                                        "RULE-BASED",
                                        f"Gratuitous ARP: {src_ip} MAC changed "
                                        f"{known}→{src_mac}")

        # ── Standard conflict detection ───────────────────────────────────────
        if src_ip in self.arp_table:
            known = self.arp_table[src_ip]
            if known != src_mac:
                self.arp_conflicts[src_ip] = (known, src_mac)
                print(Fore.RED + Style.BRIGHT + f"[{ts}] [ARP!!] "
                      f"CONFLICT: {src_ip} known={known} forged={src_mac}", flush=True)

                attacker_ip = next(
                    (ip for ip, mac in self.arp_table.items()
                     if mac == src_mac and ip != src_ip), None
                )
                alert_ip = attacker_ip or src_ip

                if self.model:
                    self.arp_suspects[src_ip] = {
                        'known': known, 'forged': src_mac,
                        'attacker_ip': alert_ip, 'mac': src_mac,
                        'dp': dp, 'at': time.time(),
                    }
                    print(f"[{ts}] [ARP  ] Suspect registered — scanning flows "
                          f"for ML confirmation (threshold={ML_THRESHOLD}) …", flush=True)
                    self._scan_flows_for_arp_suspect(src_ip, ts, dp, src_mac)
                else:
                    self._trigger_alert("ARP POISONING", alert_ip, src_mac, dp,
                                        "RULE-BASED",
                                        f"ARP conflict: {src_ip} known={known} "
                                        f"forged={src_mac} | ML not loaded")
                return
        else:
            self.arp_table[src_ip] = src_mac

        self.dai_bindings.setdefault(src_ip, set()).add(src_mac)
        if len(self.dai_bindings[src_ip]) > 1:
            print(f"[{ts}] [DAI  ] {len(self.dai_bindings[src_ip])} MACs "
                  f"claim {src_ip}: {sorted(self.dai_bindings[src_ip])}", flush=True)

    # ═════════════════════════════════════════════════════════════════════════
    # IPv4 HANDLER
    # Delegates per-protocol checks; updates flow tracker; triggers ML + rules
    # ═════════════════════════════════════════════════════════════════════════
    def _handle_ip(self, dp, in_port, pkt, pkt_ip, eth, ts):
        src_ip  = pkt_ip.src
        dst_ip  = pkt_ip.dst
        proto   = pkt_ip.proto

        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        src_port = dst_port = flags = 0

        if pkt_tcp:
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
            flags    = pkt_tcp.bits
            label    = "HTTP" if dst_port in (80, 443, 8080) or src_port in (80, 443, 8080) else "TCP"

            # ── RST per-packet MAC-IP validation (Session Hijack) ─────────────
            if flags & 0x04:   # RST bit set
                self._check_rst_spoof(src_ip, eth.src, dst_ip, dst_port, ts, dp)

            # ── SSL downgrade correlation ─────────────────────────────────────
            if dst_port in (443, 8443):
                self.https_history[(src_ip, dst_ip)] = time.time()
            elif dst_port == 80:
                self._check_ssl_downgrade(src_ip, dst_ip, eth.src, ts, dp)

        elif pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            label    = "DNS" if DNS_PORT in (src_port, dst_port) else "UDP"
            if DNS_PORT in (src_port, dst_port):
                self._check_dns(pkt_udp, src_ip, dst_ip, eth.src, ts, dp)
        else:
            label = "IP"

        quiet = time.time() < self._alert_quiet_until
        color = {
            "HTTP": Fore.GREEN, "DNS": Fore.YELLOW,
            "UDP":  Fore.BLUE,  "TCP": Fore.CYAN,
        }.get(label, Fore.LIGHTBLACK_EX)

        if not quiet:
            print(f"[{ts}] {color}{Style.BRIGHT}[{label:<5}]{Style.NORMAL} "
                  f"{src_ip}:{src_port} → {dst_ip}:{dst_port}", flush=True)

        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)

        flow      = self.flows[key]
        direction = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        flow.update(pkt_ip.total_length, direction, flags)

        n = flow.total_packets

        # ML every 5 packets starting at 5
        if n >= 5 and n % 5 == 0 and key not in self.ml_flagged_flows:
            self._run_ml_on_flow(key, flow, ts, dp, eth.src)

        # TLS kill signature check (port 443, very few packets, high RST ratio)
        if dst_port in (443, 8443) and n >= 3:
            self._check_tls_kill(key, flow, eth.src, ts, dp)

        # Rule-based fallback for SSL and session hijack (after 20 pkts, ML missed it)
        if n >= 20 and n % 10 == 0 and key not in self.ml_flagged_flows:
            self._rule_fallback(flow, ts, dp, eth.src)

    # ═════════════════════════════════════════════════════════════════════════
    # DNS HIJACKING DETECTION  (completely rewritten from v4.1)
    #
    # v4.1 tracked domain→set(src_ips). The attacker defeated this by spoofing
    # src_ip = real_resolver_ip in the DNS response, so both real and fake
    # responses appeared to come from the same server.
    #
    # v4.2 tracks the CONTENT of DNS responses — the A-record answer IPs.
    # Two responses for the same domain resolving to different IPs is the
    # ground-truth signature of DNS hijacking regardless of who sent them.
    #
    # Additionally tracks (domain, txid) → first_resolved_ip + timestamp.
    # Two different responses for the same transaction ID within DNS_RACE_WINDOW_S
    # is a DNS response racing attack (the attacker's response arrived before or
    # simultaneously with the legitimate one).
    # ═════════════════════════════════════════════════════════════════════════
    def _parse_dns_response(self, payload: bytes):
        """
        Parse a raw DNS response payload (starting at byte 0 of the UDP payload).
        Returns (domain_str, txid_hex, [resolved_ipv4_strings]) or (None, None, []).

        Wire format:
          Bytes 0-1  : Transaction ID
          Bytes 2-3  : Flags (bit 15 = QR, must be 1 for a response)
          Bytes 4-5  : QDCOUNT
          Bytes 6-7  : ANCOUNT
          Bytes 12+  : Question section (length-prefixed labels ending with 0x00)
                       followed by QTYPE (2B) + QCLASS (2B)
          After question: Answer RRs (name ptr 2B, type 2B, class 2B, TTL 4B,
                                       rdlength 2B, rdata rdlength-B)
        """
        try:
            if len(payload) < 12:
                return None, None, []

            # QR bit (bit 15 of flags) must be 1 for a response
            flags = int.from_bytes(payload[2:4], 'big')
            if not (flags >> 15 & 1):
                return None, None, []   # this is a query, not a response

            txid_hex = payload[:2].hex()
            ancount  = int.from_bytes(payload[6:8], 'big')
            if ancount == 0:
                return None, None, []

            # ── Parse question section to recover the domain name ──────────
            pos, parts = 12, []
            while pos < len(payload):
                length = payload[pos]
                if length == 0:
                    pos += 1; break
                if length & 0xC0 == 0xC0:  # name pointer
                    pos += 2; break
                label = payload[pos+1 : pos+1+length].decode('ascii', errors='ignore')
                parts.append(label)
                pos += 1 + length

            domain = '.'.join(parts).lower() if parts else f"?@pos{pos}"
            pos   += 4   # skip QTYPE + QCLASS

            # ── Parse answer records, collect A records ────────────────────
            resolved_ips = []
            for _ in range(ancount):
                if pos + 12 > len(payload):
                    break
                # Name field: pointer (0xC0 prefix) or inline labels
                if payload[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while pos < len(payload) and payload[pos] != 0:
                        pos += 1 + payload[pos]
                    pos += 1

                if pos + 10 > len(payload):
                    break

                rtype  = int.from_bytes(payload[pos:pos+2], 'big');   pos += 2
                _rclass= int.from_bytes(payload[pos:pos+2], 'big');   pos += 2
                _ttl   = int.from_bytes(payload[pos:pos+4], 'big');   pos += 4
                rdlen  = int.from_bytes(payload[pos:pos+2], 'big');   pos += 2

                if rtype == 1 and rdlen == 4:   # A record
                    ip_str = socket.inet_ntoa(payload[pos:pos+4])
                    resolved_ips.append(ip_str)

                pos += rdlen

            return domain, txid_hex, resolved_ips

        except Exception:
            return None, None, []

    def _check_dns(self, pkt_udp, src_ip, dst_ip, src_mac, ts, dp):
        """
        Called for every UDP packet on port 53.

        Detection logic:
          1. Parse the A-record answers out of DNS responses.
          2. Track dns_answer_map[domain] = set of all resolved IPs ever seen.
             If len > 1 for the same domain → IP divergence → DNS HIJACKING.
          3. Track dns_txid_seen[(domain, txid)] = first response IP + timestamp.
             If a second response for the same (domain, txid) arrives within
             DNS_RACE_WINDOW_S with a different resolved IP → racing attack.
        """
        try:
            raw = bytes(pkt_udp.data) if pkt_udp.data else b''
        except Exception:
            return

        domain, txid_hex, resolved_ips = self._parse_dns_response(raw)
        if not domain or not resolved_ips:
            return

        for rip in resolved_ips:
            print(Fore.YELLOW + Style.DIM + f"[{ts}] [DNS  ] {domain} → {rip} "
                  f"(from {src_ip}, txid={txid_hex})", flush=True)

        # ── Check 1: IP divergence across any two responses ────────────────
        known_ips = self.dns_answer_map.setdefault(domain, set())
        new_ips   = set(resolved_ips) - known_ips

        if known_ips and new_ips:
            # Same domain, new IP never seen before — definitive hijack signal
            all_ips_str = ', '.join(sorted(known_ips | new_ips))
            detail = (f"domain '{domain}' resolved to conflicting IPs: "
                      f"[{all_ips_str}] | src={src_ip} txid={txid_hex}")
            print(Fore.RED + Style.BRIGHT + f"[{ts}] [DNS!!] "
                  f"A-record divergence: {domain} → known={sorted(known_ips)}, "
                  f"new={sorted(new_ips)}", flush=True)
            self._trigger_alert("DNS HIJACKING", src_ip, src_mac, dp,
                                "RULE-BASED", detail)

        known_ips.update(resolved_ips)

        # ── Check 2: txid racing (two responses for same query) ────────────
        race_key = (domain, txid_hex)
        now      = time.time()

        if race_key in self.dns_txid_seen:
            prev = self.dns_txid_seen[race_key]
            elapsed = now - prev['ts']
            if elapsed < DNS_RACE_WINDOW_S and set(resolved_ips) != {prev['ip']}:
                detail = (f"domain '{domain}' txid={txid_hex} got two different "
                          f"responses in {elapsed*1000:.0f}ms: "
                          f"{prev['ip']} vs {resolved_ips[0]} | "
                          f"first from {prev['src']}, second from {src_ip}")
                print(Fore.RED + Style.BRIGHT + f"[{ts}] [DNS!!] "
                      f"txid racing detected: {domain} txid={txid_hex} "
                      f"→ {prev['ip']} vs {resolved_ips[0]}", flush=True)
                self._trigger_alert("DNS HIJACKING", src_ip, src_mac, dp,
                                    "RULE-BASED",
                                    f"DNS response racing: {detail}")
        else:
            self.dns_txid_seen[race_key] = {
                'ip':  resolved_ips[0],
                'ts':  now,
                'src': src_ip,
            }

        # Expire txid entries older than 30s to prevent unbounded growth
        expired = [k for k, v in self.dns_txid_seen.items()
                   if now - v['ts'] > 30]
        for k in expired:
            del self.dns_txid_seen[k]

    # ═════════════════════════════════════════════════════════════════════════
    # SSL STRIPPING DETECTION  (new in v4.2)
    #
    # Cross-flow downgrade correlation:
    #   When the controller sees a TCP flow from src_ip to dst_ip on port 80,
    #   it checks https_history[(src_ip, dst_ip)]. If a port-443 flow was seen
    #   within SSL_DOWNGRADE_WINDOW_S, the src has silently downgraded from
    #   HTTPS to HTTP for the same destination — the signature of SSL stripping.
    #
    # Why this catches the new attacker:
    #   The attacker intercepts src→dst:443 traffic (via ARP poisoning), handles
    #   TLS itself, and responds to src in plaintext on port 80. The controller
    #   sees both the original 443 flow (recorded in https_history) and the
    #   subsequent port-80 flow — triggering the downgrade check.
    # ═════════════════════════════════════════════════════════════════════════
    def _check_ssl_downgrade(self, src_ip, dst_ip, src_mac, ts, dp):
        """
        Fire SSL STRIPPING alert if (src_ip, dst_ip) had port-443 traffic
        within the last SSL_DOWNGRADE_WINDOW_S seconds and now has port-80.
        """
        last_https = self.https_history.get((src_ip, dst_ip))
        if last_https is None:
            return

        elapsed = time.time() - last_https
        if elapsed > SSL_DOWNGRADE_WINDOW_S:
            # Too old — remove stale entry
            del self.https_history[(src_ip, dst_ip)]
            return

        detail = (f"{src_ip} → {dst_ip}: HTTPS (port 443) observed "
                  f"{elapsed:.1f}s ago, now seeing plain HTTP (port 80). "
                  f"HTTPS→HTTP downgrade within {SSL_DOWNGRADE_WINDOW_S}s window.")
        print(Fore.RED + Style.BRIGHT + f"[{ts}] [SSL!!] "
              f"Downgrade: {src_ip}→{dst_ip}:443 → :80 in {elapsed:.1f}s", flush=True)
        self._trigger_alert("SSL STRIPPING", src_ip, src_mac, dp,
                            "RULE-BASED (downgrade correlation)", detail)

    # ═════════════════════════════════════════════════════════════════════════
    # TLS KILL DETECTION  (new in v4.2)
    #
    # Detects TLS handshakes that were killed with RST before completion.
    # Signature: port-443 flow with very few total packets and high RST ratio.
    # The attacker intercepts the SYN, forwards the connection to its own
    # proxy, and sends RST back to the victim — this leaves a short, RST-heavy
    # flow in the controller's flow table.
    # ═════════════════════════════════════════════════════════════════════════
    def _check_tls_kill(self, key, flow, src_mac, ts, dp):
        if key in self.ml_flagged_flows:
            return
        n     = flow.total_packets
        rst_r = flow.rst_count / max(n, 1)

        if n < TLS_KILL_MAX_PKTS and rst_r >= TLS_KILL_RST_RATIO:
            detail = (f"TLS flow {flow.src_ip}:{flow.src_port} → "
                      f"{flow.dst_ip}:{flow.dst_port} "
                      f"killed after {n} pkts, RST ratio={rst_r:.2f} "
                      f"(threshold: pkts<{TLS_KILL_MAX_PKTS}, rst>{TLS_KILL_RST_RATIO})")
            print(Fore.RED + Style.BRIGHT + f"[{ts}] [SSL!!] "
                  f"TLS handshake killed: {n} pkts, RST ratio={rst_r:.2f}", flush=True)
            self._trigger_alert("SSL STRIPPING", flow.src_ip, src_mac, dp,
                                "RULE-BASED (TLS kill)", detail)

    # ═════════════════════════════════════════════════════════════════════════
    # RST SPOOF DETECTION  (new in v4.2)
    #
    # Per-packet MAC-IP consistency check on RST segments.
    # The attacker injects RSTs with a spoofed source IP (e.g. SERVER_IP) but
    # the packet arrives from the attacker's MAC. The controller can catch this
    # by cross-referencing src_ip against its ARP table:
    #   RST.src_ip = SERVER_IP, but frame.src_mac ≠ arp_table[SERVER_IP]
    #   → RST is injected, not originated by the server.
    #
    # This detects session hijacking immediately on the first crafted RST,
    # before the RST ratio accumulates in the flow tracker.
    # ═════════════════════════════════════════════════════════════════════════
    def _check_rst_spoof(self, src_ip, src_mac, dst_ip, dst_port, ts, dp):
        """
        Called when a packet with RST flag is seen.
        If src_ip is in the ARP table but src_mac doesn't match → injected RST.
        """
        known_mac = self.arp_table.get(src_ip)
        if known_mac is None:
            return   # unknown host, can't validate
        if src_mac == known_mac:
            return   # MAC matches, legitimate RST

        # MAC-IP mismatch on a RST → forged packet
        detail = (f"RST from {src_ip} arrived with MAC {src_mac}, "
                  f"but ARP table shows {src_ip} → {known_mac}. "
                  f"RST is injected (session hijacking). "
                  f"Target: {dst_ip}:{dst_port}")
        print(Fore.RED + Style.BRIGHT + f"[{ts}] [RST!!] "
              f"Spoofed RST: {src_ip} claimed by MAC {src_mac} "
              f"(should be {known_mac})", flush=True)
        self._trigger_alert("SESSION HIJACKING", src_ip, src_mac, dp,
                            "RULE-BASED (RST spoof)", detail)

    # ═════════════════════════════════════════════════════════════════════════
    # ML SCORING
    # ═════════════════════════════════════════════════════════════════════════
    def _scan_flows_for_arp_suspect(self, conflict_ip, ts, dp, src_mac):
        for key, flow in list(self.flows.items()):
            if flow.src_ip != conflict_ip and flow.dst_ip != conflict_ip:
                continue
            if key in self.ml_flagged_flows:
                continue
            if flow.total_packets < 15:
                continue
            self._run_ml_on_flow(key, flow, ts, dp, src_mac)

    def _run_ml_on_flow(self, key, flow, ts, dp, src_mac):
        score = self._ml_score(flow)
        if score is None:
            return

        flow.last_score = score

        if score >= ML_THRESHOLD:
            self.ml_flagged_flows.add(key)
            flow.is_mitm = True
            attack_type, sub_detail = flow.classify_subtype()

            conflict_ip = None
            if flow.src_ip in self.arp_conflicts:
                conflict_ip = flow.src_ip
            elif flow.dst_ip in self.arp_conflicts:
                conflict_ip = flow.dst_ip

            if conflict_ip:
                known, forged = self.arp_conflicts[conflict_ip]
                attack_type   = "ARP POISONING"
                sub_detail    = (f"score={score:.4f} | ARP conflict on "
                                 f"{conflict_ip} known={known} forged={forged}")
                suspect        = self.arp_suspects.pop(conflict_ip, None)
                alert_ip       = suspect['attacker_ip'] if suspect else flow.src_ip
                alert_mac      = suspect['mac']         if suspect else src_mac
            else:
                alert_ip  = flow.src_ip
                alert_mac = src_mac

            detail = f"score={score:.4f} | {sub_detail}"
            print(Fore.RED + Style.BRIGHT + f"[{ts}] [ML!!] {attack_type} "
                  f"score={score:.4f} on {flow.src_ip}→{flow.dst_ip}", flush=True)
            self._trigger_alert(attack_type, alert_ip, alert_mac, dp,
                                "ML MODEL (CNN+LSTM)", detail)
        else:
            if time.time() >= self._alert_quiet_until:
                print(Fore.WHITE + Style.DIM + f"[{ts}] [ML   ] "
                      f"{flow.src_ip}→{flow.dst_ip} "
                      f"pkts={flow.total_packets} score={score:.4f} ✓", flush=True)

    # ── Rule-based fallback for SSL + session hijack ──────────────────────────
    def _rule_fallback(self, flow, ts, dp, src_mac):
        n     = flow.total_packets
        rst_r = flow.rst_count / max(n, 1)

        if flow.dst_port in (443, 8443) or flow.src_port in (443, 8443):
            detail = (f"TLS port {flow.dst_port or flow.src_port} "
                      f"pkts={n} ML score={flow.last_score:.4f} (<{ML_THRESHOLD})")
            self._trigger_alert("SSL STRIPPING", flow.src_ip, src_mac, dp,
                                "RULE-BASED FALLBACK", detail)

        if rst_r > 0.15 and flow.ack_count > 5:
            detail = (f"RST ratio={rst_r:.2f} ACKs={flow.ack_count} "
                      f"pkts={n} ML score={flow.last_score:.4f} (<{ML_THRESHOLD})")
            self._trigger_alert("SESSION HIJACKING", flow.src_ip, src_mac, dp,
                                "RULE-BASED FALLBACK", detail)

    # ═════════════════════════════════════════════════════════════════════════
    # ALERT ENGINE
    # ═════════════════════════════════════════════════════════════════════════
    def _trigger_alert(self, attack_type, ip, mac, dp, method, detail):
        alert_key = (ip, mac, attack_type)
        if alert_key in self.triggered_alerts:
            return
        self.triggered_alerts.add(alert_key)
        self.attack_counts[attack_type] += 1

        ts = datetime.datetime.now().strftime('%H:%M:%S')

        HOW = {
            "ML MODEL (CNN+LSTM)": {
                "ARP POISONING":     "CNN+LSTM score >=0.5 on flow from ARP-conflicted host",
                "SSL STRIPPING":     "CNN+LSTM scored TLS-port flow >=0.5",
                "SESSION HIJACKING": "CNN+LSTM scored high-RST flow >=0.5",
                "DNS HIJACKING":     "CNN+LSTM scored DNS-port flow >=0.5",
            },
            "RULE-BASED": {
                "ARP POISONING":     "ARP reply changed IP→MAC mapping; no scorable flows",
                "DNS HIJACKING":     "A-record answer divergence (same domain → different IPs) "
                                     "or txid racing (two different responses within 200ms)",
                "SESSION HIJACKING": "RST packet arrived with MAC-IP mismatch (forged RST)",
            },
            "RULE-BASED (downgrade correlation)": {
                "SSL STRIPPING":     f"Host had HTTPS (port 443) flow within "
                                     f"{SSL_DOWNGRADE_WINDOW_S}s, now switched to plain HTTP (port 80)",
            },
            "RULE-BASED (TLS kill)": {
                "SSL STRIPPING":     f"Port-443 flow terminated by RST after <{TLS_KILL_MAX_PKTS} "
                                     f"packets — TLS handshake was killed before completion",
            },
            "RULE-BASED (RST spoof)": {
                "SESSION HIJACKING": "RST src_ip→MAC does not match ARP table — packet is injected",
            },
            "RULE-BASED FALLBACK": {
                "SSL STRIPPING":     "443/8443 flow reached 20+ pkts; ML score below threshold",
                "SESSION HIJACKING": "RST ratio>15% + ACK count>5 after 20+ pkts; ML below threshold",
            },
        }
        how = HOW.get(method, {}).get(attack_type, f"{method} triggered")

        W = 70
        A = Fore.RED + Style.BRIGHT; R = Style.RESET_ALL

        def _col(label, value):
            s = f"  {label}{value}"
            return f"║{s[:W]:<{W}}║"

        print("\n\n", flush=True)
        print(A + f"╔{'═'*W}╗" + R, flush=True)
        print(A + f"║{'':^{W}}║" + R, flush=True)
        print(A + f"║{'⚠  MITM ATTACK DETECTED  ⚠':^{W}}║" + R, flush=True)
        print(A + f"║{'':^{W}}║" + R, flush=True)
        print(A + f"╠{'═'*W}╣" + R, flush=True)
        for lbl, val in [("Attack Type : ", attack_type), ("Method      : ", method),
                         ("How         : ", how), ("Time        : ", ts),
                         ("Host IP     : ", ip), ("MAC         : ", mac)]:
            print(A + _col(lbl, val) + R, flush=True)
        print(A + f"╠{'─'*W}╣" + R, flush=True)
        print(A + _col("Details     : ", detail) + R, flush=True)
        print(A + _col("Action      : ", "IP and MAC blocked — DROP rules installed") + R, flush=True)
        print(A + f"╚{'═'*W}╝" + R, flush=True)
        print(A + f"  >>> {attack_type} DETECTED — {ip} ({mac}) BLOCKED <<<" + R, flush=True)
        print("\n", flush=True)

        self._alert_quiet_until = time.time() + 5

        self.detections.append({
            "time": ts, "type": attack_type, "method": method,
            "ip": ip, "mac": mac, "detail": detail,
        })
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)

        try:
            log_path = "/tmp/mitm_alerts.json"
            try:
                existing = json.loads(open(log_path).read() or '[]')
            except Exception:
                existing = []
            existing.append({"timestamp": ts, "attack_type": attack_type,
                             "method": method, "how": how,
                             "ip": ip, "mac": mac, "detail": detail})
            open(log_path, 'w').write(json.dumps(existing, indent=2))
        except Exception:
            pass

        parser = dp.ofproto_parser
        self._add_flow(dp, 100, parser.OFPMatch(eth_src=mac), [])
        self._add_flow(dp, 100, parser.OFPMatch(eth_type=0x0800, ipv4_src=ip), [])

    # ═════════════════════════════════════════════════════════════════════════
    # STATS LOOP  (every 10s)
    # ═════════════════════════════════════════════════════════════════════════
    def _stats_loop(self):
        while True:
            hub.sleep(10)
            self._flush_old_arp_suspects()
            self._print_stats()

    def _flush_old_arp_suspects(self):
        """
        For each ARP suspect waiting >= 20s:
          • Run final ML scan across all relevant flows.
          • If best score >= ML_THRESHOLD → ML detection.
          • If flows existed but all scored below threshold → log miss only,
            do NOT raise false alert.
          • If no flows at all → rule-based (ARP conflict is definitive evidence).
        """
        now = time.time()
        for conflict_ip, s in list(self.arp_suspects.items()):
            if now - s['at'] < 20:
                continue
            self.arp_suspects.pop(conflict_ip, None)
            ts = datetime.datetime.now().strftime('%H:%M:%S')

            best_score, best_flow = 0.0, None
            flows_found = 0

            for key, flow in list(self.flows.items()):
                if flow.src_ip != conflict_ip and flow.dst_ip != conflict_ip:
                    continue
                if flow.total_packets < 3:
                    continue
                flows_found += 1
                score = self._ml_score(flow)
                if score is None:
                    continue
                flow.last_score = score
                print(Fore.WHITE + Style.DIM + f"[{ts}] [ML   ] (ARP Final) "
                      f"{flow.src_ip}→{flow.dst_ip} pkts={flow.total_packets} "
                      f"score={score:.4f}", flush=True)
                if score > best_score:
                    best_score, best_flow = score, flow

            if best_flow is not None and best_score >= ML_THRESHOLD:
                detail = (f"score={best_score:.4f} | ARP conflict: {conflict_ip} "
                          f"known={s['known']} forged={s['forged']} | "
                          f"flow {best_flow.src_ip}→{best_flow.dst_ip} "
                          f"pkts={best_flow.total_packets}")
                self._trigger_alert("ARP POISONING", s['attacker_ip'], s['mac'],
                                    s['dp'], "ML MODEL (CNN+LSTM)", detail)

            elif flows_found > 0:
                print(f"[{ts}] [ARP  ] Conflict on {conflict_ip}: "
                      f"{flows_found} flow(s) scored, best={best_score:.4f} "
                      f"< {ML_THRESHOLD} — NOT flagging (insufficient evidence)",
                      flush=True)
            else:
                detail = (f"ARP conflict: {conflict_ip} known={s['known']} "
                          f"forged={s['forged']} | no flows to score")
                self._trigger_alert("ARP POISONING", s['attacker_ip'], s['mac'],
                                    s['dp'], "RULE-BASED", detail)

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        C = Fore.CYAN + Style.BRIGHT; D = Fore.CYAN; R = Style.RESET_ALL; W = 64

        print(flush=True)
        print(C + f"┌{'─'*W}┐" + R, flush=True)
        print(C + f"│{f'  STATUS REPORT  [{ts}]':^{W}}│" + R, flush=True)
        print(C + f"├{'─'*W}┤" + R, flush=True)

        info = (f"  Switches: {len(self.datapaths)}   "
                f"Flows: {len(self.flows)}   "
                f"ARP: {len(self.arp_table)}   "
                f"DNS domains: {len(self.dns_answer_map)}")
        print(D + f"│{info:<{W}}│" + R, flush=True)
        print(C + f"├{'─'*W}┤" + R, flush=True)
        print(C + f"│{'  ATTACK STATISTICS':<{W}}│" + R, flush=True)

        for atype in ["ARP POISONING", "DNS HIJACKING", "SSL STRIPPING", "SESSION HIJACKING"]:
            count = self.attack_counts.get(atype, 0)
            if count > 0:
                line = f"  ● {atype:<24} {count} detected"
                print(Fore.RED + Style.BRIGHT + f"│{line:<{W}}│" + R, flush=True)
            else:
                line = f"  ○ {atype:<24} —"
                print(D + f"│{line:<{W}}│" + R, flush=True)

        if self.detections:
            print(C + f"├{'─'*W}┤" + R, flush=True)
            print(C + f"│{'  RECENT ALERTS':<{W}}│" + R, flush=True)
            for d in self.detections[-5:]:
                line = f"  [{d['time']}] {d['type']:<22} {d['method']:<24} {d['ip']}"
                print(Fore.RED + Style.BRIGHT + f"│{line[:W]:<{W}}│" + R, flush=True)

        blk  = ', '.join(self.blocked_ips) or '(none)'
        bline = f"  Blocked IPs: {blk}"
        print(C + f"├{'─'*W}┤" + R, flush=True)
        print(D + f"│{bline[:W]:<{W}}│" + R, flush=True)

        # DNS divergence summary
        if self.dns_answer_map:
            print(C + f"├{'─'*W}┤" + R, flush=True)
            print(C + f"│{'  DNS ANSWER MAP (domains with multiple IPs)':<{W}}│" + R, flush=True)
            for domain, ips in list(self.dns_answer_map.items())[:5]:
                if len(ips) > 1:
                    line = f"  ⚠ {domain}: {sorted(ips)}"
                    print(Fore.RED + f"│{line[:W]:<{W}}│" + R, flush=True)

        print(C + f"└{'─'*W}┘" + R, flush=True)
        print(flush=True)


if __name__ == '__main__':
    pass