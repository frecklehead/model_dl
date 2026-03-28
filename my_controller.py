# -*- coding: utf-8 -*-
"""
my_controller.py - Unified MITM Detection Controller 

Detection rules:
  ARP Poisoning     -> ML MODEL first (score >= 0.5), RULE-BASED FALLBACK if no flows
  SSL Stripping     -> ML MODEL first, RULE-BASED FALLBACK after 20 pkts
  Session Hijacking -> ML MODEL first, RULE-BASED FALLBACK after 20 pkts
  DNS Hijacking     -> RULE-BASED (DNS response divergence)

CHANGES FROM v4.0 (honesty fixes):
  - _flush_old_arp_suspects: only fires alert if best_score >= THRESHOLD (was always firing)
  - _run_ml_on_flow: arp_suspect lower threshold (0.3) removed; all paths use 0.5
  - _arp_ml_or_rule: removed (was returning misleading method label on sub-threshold scores)
  - Rule-based ARP fallback only fires when there are genuinely NO scorable flows,
    not as a consolation prize for a low-scoring flow
"""

import os, time, datetime, json, collections, warnings
import numpy as np
import pandas as pd
import joblib
from tabulate import tabulate
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

# Feature list — overwritten from selected_features.pkl at startup
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

DNS_PORT   = 53
ML_THRESHOLD = 0.5   # single authoritative threshold used everywhere


# ─────────────────────────────────────────────────────────────────────────────
class FlowTracker:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        now = time.time()
        self.start_time     = now
        self.last_time      = now
        self.s2d_last_time  = now
        self.s2d_start_time = None

        self.s2d_packets = 0;  self.s2d_bytes = 0
        self.d2s_packets = 0;  self.d2s_bytes = 0

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

        all_ps  = self.packet_sizes     or [0]
        s2d_ps  = self.s2d_packet_sizes or [0]
        d2s_ps  = self.d2s_packet_sizes or [0]
        all_pi  = self.piats            or [0]
        s2d_pi  = self.s2d_piats        or [0]

        mean_ps = float(np.mean(all_ps));  std_ps = float(np.std(all_ps))
        mean_pi = float(np.mean(all_pi));  std_pi = float(np.std(all_pi))

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
        """Return (attack_type, detail_str) based on flow heuristics."""
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

        self.mac_to_port      = {}
        self.arp_table        = {}   # ip -> mac  (first seen / trusted)
        self.arp_conflicts    = {}   # ip -> (known_mac, forged_mac)
        self.dai_bindings     = {}   # ip -> set of MACs
        self.dns_responses    = {}   # domain -> set of IPs
        self.flows            = {}   # flow_key -> FlowTracker
        self.datapaths        = {}
        self.blocked_macs     = set()
        self.blocked_ips      = set()
        self.detections       = []
        self.triggered_alerts = set()
        self.ml_flagged_flows = set()
        self.attack_counts    = collections.defaultdict(int)
        self._alert_quiet_until = 0   # suppress packet-in logs right after alert

        # ip -> {known, forged, attacker_ip, mac, dp, at}
        # Cleared only after an alert fires OR after the 20s window with no evidence
        self.arp_suspects = {}

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
        """Run ML inference on a flow. Returns float in [0,1] or None on error."""
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
        W = 66
        C = Fore.CYAN + Style.BRIGHT
        R = Style.RESET_ALL
        print(flush=True)
        print(C + f"╔{'═'*W}╗" + R, flush=True)
        print(C + f"║{'MITM DETECTION CONTROLLER v4.1':^{W}}║" + R, flush=True)
        print(C + f"╠{'═'*W}╣" + R, flush=True)
        for lbl, val in [("ML Model", ml),
                         ("Features", str(len(FEATURES))),
                         ("Threshold", str(ML_THRESHOLD))]:
            line = f"  {lbl:<14}: {val}"
            print(C + f"║{line:<{W}}║" + R, flush=True)
        print(C + f"╠{'═'*W}╣" + R, flush=True)
        print(C + f"║{'  Detection Methods':<{W}}║" + R, flush=True)
        print(C + f"║{'─'*W}║" + R, flush=True)
        methods = [
            ("ARP Poisoning",     "ML MODEL → RULE-BASED fallback"),
            ("SSL Stripping",     "ML MODEL → RULE-BASED after 20 pkts"),
            ("Session Hijacking", "ML MODEL → RULE-BASED after 20 pkts"),
            ("DNS Hijacking",     "RULE-BASED (response divergence)"),
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

        for attr in ('arp_table', 'arp_conflicts', 'dai_bindings', 'dns_responses',
                     'flows', 'blocked_macs', 'blocked_ips', 'detections',
                     'triggered_alerts', 'ml_flagged_flows', 'attack_counts'):
            getattr(self, attr).clear()
        self.mac_to_port.pop(dp.id, None)

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        G = Fore.GREEN + Style.BRIGHT
        R = Style.RESET_ALL
        W = 50
        print(flush=True)
        print(G + f"  ┌{'─'*W}┐" + R, flush=True)
        print(G + f"  │{'  ✓ SWITCH CONNECTED':^{W}}│" + R, flush=True)
        print(G + f"  │{f'    dpid={dp.id}  |  OF1.3  |  {ts}':^{W}}│" + R, flush=True)
        print(G + f"  └{'─'*W}┘" + R, flush=True)

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
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

    # ── ARP handler ───────────────────────────────────────────────────────────
    def _handle_arp(self, dp, in_port, pkt_arp, eth, ts):
        op      = "RQ" if pkt_arp.opcode == arp.ARP_REQUEST else "RP"
        src_ip  = pkt_arp.src_ip
        src_mac = eth.src
        color   = Fore.MAGENTA if op == "RP" else Fore.LIGHTMAGENTA_EX
        print(f"[{ts}] {color}{Style.BRIGHT}[ARP {op}]{Style.NORMAL} {src_ip} ({src_mac}) \u2794 {pkt_arp.dst_ip}", flush=True)

        if src_ip in self.arp_table:
            known = self.arp_table[src_ip]
            if known != src_mac:
                # ── ARP CONFLICT DETECTED ──────────────────────────────────
                self.arp_conflicts[src_ip] = (known, src_mac)
                print(Fore.RED + Style.BRIGHT + f"[{ts}] [ARP!! ] *** CONFLICT: {src_ip} "
                      f"known={known} forged={src_mac} ***", flush=True)

                attacker_ip = next(
                    (tbl_ip for tbl_ip, tbl_mac in self.arp_table.items()
                     if tbl_mac == src_mac and tbl_ip != src_ip),
                    None
                )
                alert_ip = attacker_ip if attacker_ip else src_ip

                if self.model:
                    # Register suspect and immediately try scoring existing flows.
                    # The alert will only fire if a flow scores >= ML_THRESHOLD.
                    self.arp_suspects[src_ip] = {
                        'known': known, 'forged': src_mac,
                        'attacker_ip': alert_ip, 'mac': src_mac,
                        'dp': dp, 'at': time.time(),
                    }
                    print(f"[{ts}] [ARP  ] Suspect registered — scanning existing "
                          f"flows for ML confirmation (threshold={ML_THRESHOLD}) …",
                          flush=True)
                    self._scan_flows_for_arp_suspect(src_ip, ts, dp, src_mac)
                else:
                    # No ML available: rule-based is the only option.
                    detail = (f"ARP table conflict: {src_ip} "
                              f"known={known} forged={src_mac} | ML not loaded")
                    self._trigger_alert("ARP POISONING", alert_ip, src_mac, dp,
                                        "RULE-BASED", detail)
                return   # never update table with forged MAC
        else:
            self.arp_table[src_ip] = src_mac

        self.dai_bindings.setdefault(src_ip, set()).add(src_mac)
        if len(self.dai_bindings[src_ip]) > 1:
            print(f"[{ts}] [DAI  ] {len(self.dai_bindings[src_ip])} MACs "
                  f"claim {src_ip}: {sorted(self.dai_bindings[src_ip])}", flush=True)

    # ── IPv4 handler ──────────────────────────────────────────────────────────
    def _handle_ip(self, dp, in_port, pkt, pkt_ip, eth, ts):
        src_ip = pkt_ip.src
        dst_ip = pkt_ip.dst
        proto  = pkt_ip.proto

        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        src_port = dst_port = flags = 0

        if pkt_tcp:
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
            flags    = pkt_tcp.bits
            label    = "HTTP" if dst_port in (80, 443, 8080) or src_port in (80, 443, 8080) else "TCP"
        elif pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            label    = "DNS" if DNS_PORT in (src_port, dst_port) else "UDP"
            self._check_dns(pkt_udp, src_ip, dst_ip, eth.src, ts, dp)
        else:
            label = "IP"

        # Suppress noisy packet-in logs right after an alert so the box stays visible
        quiet = time.time() < self._alert_quiet_until

        # Neat log for packet-in (skipped during quiet period)
        color = Fore.LIGHTBLACK_EX
        if "HTTP" in label: color = Fore.GREEN
        elif "DNS" in label: color = Fore.YELLOW
        elif "UDP" in label: color = Fore.BLUE
        elif "TCP" in label: color = Fore.CYAN

        if not quiet:
            print(f"[{ts}] {color}{Style.BRIGHT}[{label:<5}]{Style.NORMAL} {src_ip}:{src_port} \u2794 {dst_ip}:{dst_port}", flush=True)

        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)

        flow      = self.flows[key]
        direction = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        flow.update(pkt_ip.total_length, direction, flags)

        n = flow.total_packets

        # ML: check every 5 packets starting at 5
        if n >= 5 and n % 5 == 0 and key not in self.ml_flagged_flows:
            self._run_ml_on_flow(key, flow, ts, dp, eth.src)

        # Rule-based fallback for SSL / session hijack after 20 pkts
        if n >= 20 and n % 10 == 0 and key not in self.ml_flagged_flows:
            self._rule_fallback(flow, ts, dp, eth.src)

    # ── Immediate ML scan when ARP suspect is registered ─────────────────────
    def _scan_flows_for_arp_suspect(self, conflict_ip, ts, dp, src_mac):
        """Score all existing flows involving conflict_ip right now."""
        for key, flow in list(self.flows.items()):
            if flow.src_ip != conflict_ip and flow.dst_ip != conflict_ip:
                continue
            if key in self.ml_flagged_flows:
                continue
            if flow.total_packets < 15:
                continue
            self._run_ml_on_flow(key, flow, ts, dp, src_mac)

    # ── ML on a specific flow ─────────────────────────────────────────────────
    def _run_ml_on_flow(self, key, flow, ts, dp, src_mac):
        """
        Score one flow with the ML model.
        Alert fires ONLY if score >= ML_THRESHOLD (0.5).
        The arp_suspect lower threshold from v4.0 has been removed — it was
        the root cause of dishonest detections.
        """
        score = self._ml_score(flow)
        if score is None:
            return   # model not loaded

        flow.last_score = score

        if score >= ML_THRESHOLD:
            self.ml_flagged_flows.add(key)
            flow.is_mitm = True
            attack_type, sub_detail = flow.classify_subtype()

            # Check if this flow involves an ARP-conflicted IP
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
            print(Fore.RED + Style.BRIGHT + f"[{ts}] [ML ALERT] {attack_type} "
                  f"CONFIRMED on {flow.src_ip} \u2794 {flow.dst_ip} | score={score:.4f}", flush=True)
            self._trigger_alert(attack_type, alert_ip, alert_mac, dp,
                                "ML MODEL (CNN+LSTM)", detail)
        else:
            # Subtle log for normal ML scan (suppressed during alert quiet period)
            if time.time() >= self._alert_quiet_until:
                print(Fore.WHITE + Style.DIM + f"[{ts}] [ML SCAN ] {flow.src_ip} \u2794 {flow.dst_ip} "
                      f"| pkts={flow.total_packets} | score={score:.4f} \u2714", flush=True)

    # ── Rule-based fallback for SSL strip / session hijack ────────────────────
    def _rule_fallback(self, flow, ts, dp, src_mac):
        n     = flow.total_packets
        rst_r = flow.rst_count / max(n, 1)

        if flow.dst_port in (443, 8443) or flow.src_port in (443, 8443):
            detail = (f"TLS port {flow.dst_port or flow.src_port} | "
                      f"pkts={n} | ML score={flow.last_score:.4f} (<{ML_THRESHOLD})")
            self._trigger_alert("SSL STRIPPING", flow.src_ip, src_mac, dp,
                                "RULE-BASED FALLBACK", detail)

        if rst_r > 0.15 and flow.ack_count > 5:
            detail = (f"RST ratio={rst_r:.2f} ACKs={flow.ack_count} | "
                      f"pkts={n} | ML score={flow.last_score:.4f} (<{ML_THRESHOLD})")
            self._trigger_alert("SESSION HIJACKING", flow.src_ip, src_mac, dp,
                                "RULE-BASED FALLBACK", detail)

    # ── DNS hijacking check ───────────────────────────────────────────────────
    def _check_dns(self, pkt_udp, src_ip, dst_ip, src_mac, ts, dp):
        try:
            payload = bytes(pkt_udp.data) if pkt_udp.data else b''
            if len(payload) < 12:
                return
            if not ((payload[2] >> 7) & 1):   # QR bit must be 1 (response)
                return
            if int.from_bytes(payload[6:8], 'big') == 0:  # ANCOUNT must be > 0
                return
            pos, parts = 12, []
            while pos < len(payload) and payload[pos] != 0:
                ln = payload[pos]
                parts.append(payload[pos+1:pos+1+ln].decode('ascii', errors='ignore'))
                pos += 1 + ln
            domain = '.'.join(parts) or f'?@{src_ip}'
            self.dns_responses.setdefault(domain, set()).add(src_ip)

            if len(self.dns_responses[domain]) > 1:
                ips    = ', '.join(sorted(self.dns_responses[domain]))
                detail = f"domain '{domain}' -> multiple IPs: [{ips}]"
                self._trigger_alert("DNS HIJACKING", src_ip, src_mac, dp,
                                    "RULE-BASED", detail)
        except Exception:
            pass

    # ── Central alert printer + blocker ───────────────────────────────────────
    def _trigger_alert(self, attack_type, ip, mac, dp, method, detail):
        alert_key = (ip, mac, attack_type)
        if alert_key in self.triggered_alerts:
            return
        self.triggered_alerts.add(alert_key)
        self.attack_counts[attack_type] += 1

        ts = datetime.datetime.now().strftime('%H:%M:%S')

        HOW = {
            "ML MODEL (CNN+LSTM)": {
                "ARP POISONING":     "CNN+LSTM scored flow >=0.5 AND ARP table conflict confirmed",
                "SSL STRIPPING":     "CNN+LSTM scored TLS-port flow >=0.5",
                "SESSION HIJACKING": "CNN+LSTM scored RST/ACK flow >=0.5",
                "DNS HIJACKING":     "CNN+LSTM scored DNS-port flow >=0.5",
            },
            "RULE-BASED": {
                "ARP POISONING":  "ARP reply changed IP->MAC mapping; no scorable flows available",
                "DNS HIJACKING":  "Domain resolved to a different IP than previous records (DNS Response Divergence)",
            },
            "RULE-BASED FALLBACK": {
                "SSL STRIPPING":     "TCP flow to 443/8443 seen 20+ pkts; ML score below 0.5",
                "SESSION HIJACKING": "RST ratio>15% + ACK count>5 after 20+ pkts; ML score below 0.5",
            },
        }
        how = HOW.get(method, {}).get(attack_type, f"{method} detection triggered")

        W = 66
        A = Fore.RED + Style.BRIGHT
        R = Style.RESET_ALL
        def _col(label, value):
            s = f"  {label}{value}"
            if len(s) > W:
                s = s[:W-2] + ".."
            return f"║{s:<{W}}║"

        print("\n\n", flush=True)
        print(A + f"╔{'═'*W}╗" + R, flush=True)
        print(A + f"║{'':^{W}}║" + R, flush=True)
        print(A + f"║{'⚠  MITM ATTACK DETECTED  ⚠':^{W}}║" + R, flush=True)
        print(A + f"║{'':^{W}}║" + R, flush=True)
        print(A + f"╠{'═'*W}╣" + R, flush=True)
        print(A + _col("Attack Type : ", attack_type) + R, flush=True)
        print(A + _col("Method      : ", method) + R, flush=True)
        print(A + _col("How         : ", how) + R, flush=True)
        print(A + _col("Time        : ", ts) + R, flush=True)
        print(A + _col("Host IP     : ", ip) + R, flush=True)
        print(A + _col("MAC         : ", mac) + R, flush=True)
        print(A + f"╠{'─'*W}╣" + R, flush=True)
        print(A + _col("Details     : ", detail) + R, flush=True)
        print(A + _col("Action      : ", "IP and MAC blocked — DROP rules installed") + R, flush=True)
        print(A + f"╚{'═'*W}╝" + R, flush=True)
        # Sticky one-liner that stays visible even as logs scroll
        print(A + f"  >>> {attack_type} DETECTED — {ip} ({mac}) BLOCKED <<<" + R, flush=True)
        print("\n", flush=True)

        # Suppress noisy packet-in logs for 5s so the alert box stays on screen
        self._alert_quiet_until = time.time() + 5

        self.detections.append({
            "time": ts, "type": attack_type, "method": method,
            "ip": ip, "mac": mac, "detail": detail
        })
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)

        try:
            log_path = "/tmp/mitm_alerts.json"
            existing = json.loads(open(log_path).read() or '[]')
            existing.append({"timestamp": ts, "attack_type": attack_type,
                             "method": method, "how": how,
                             "ip": ip, "mac": mac, "detail": detail})
            open(log_path, 'w').write(json.dumps(existing, indent=2))
        except Exception:
            pass

        parser = dp.ofproto_parser
        self._add_flow(dp, 100, parser.OFPMatch(eth_src=mac), [])
        self._add_flow(dp, 100, parser.OFPMatch(eth_type=0x0800, ipv4_src=ip), [])

    # ── Stats loop ────────────────────────────────────────────────────────────
    def _stats_loop(self):
        while True:
            hub.sleep(10)
            self._flush_old_arp_suspects()
            self._print_stats()

    def _flush_old_arp_suspects(self):
        """
        Called every 10s. For each ARP suspect that has waited >= 20s:

          1. Run a final ML scan across all relevant flows.
          2. If ANY flow scores >= ML_THRESHOLD → alert as ML detection.
          3. If flows exist but all scored < ML_THRESHOLD → log the miss,
             do NOT raise a false alert. The rule-based path would not fire
             here because a) it already had a chance via _rule_fallback, and
             b) a low ML score is evidence AGAINST this being an attack.
          4. If NO scorable flows at all → fire RULE-BASED (the ARP conflict
             itself is definitive evidence; we just have no flow to score).
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
                print(Fore.WHITE + Style.DIM + f"[{ts}] [ML SCAN ] (ARP Final) {flow.src_ip} \u2794 {flow.dst_ip} "
                      f"| pkts={flow.total_packets} | score={score:.4f}", flush=True)
                if score > best_score:
                    best_score, best_flow = score, flow

            if best_flow is not None and best_score >= ML_THRESHOLD:
                # ── ML confirmed ──────────────────────────────────────────
                detail = (f"score={best_score:.4f} | ARP conflict: {conflict_ip} "
                          f"known={s['known']} forged={s['forged']} "
                          f"| best flow: {best_flow.src_ip}->{best_flow.dst_ip} "
                          f"pkts={best_flow.total_packets}")
                print(f"[{ts}] [ML   ] ARP POISONING confirmed — "
                      f"score={best_score:.4f} >= {ML_THRESHOLD}", flush=True)
                self._trigger_alert("ARP POISONING", s['attacker_ip'], s['mac'],
                                    s['dp'], "ML MODEL (CNN+LSTM)", detail)

            elif flows_found > 0:
                # ── Flows existed but all scored below threshold ───────────
                # Do NOT raise an alert — low ML score is evidence of normalcy.
                print(f"[{ts}] [ARP  ] ARP conflict on {conflict_ip}: "
                      f"{flows_found} flow(s) scored, best={best_score:.4f} "
                      f"< {ML_THRESHOLD} — NOT flagging (insufficient ML evidence)",
                      flush=True)

            else:
                # ── No flows at all — only rule-based evidence available ───
                print(f"[{ts}] [ARP  ] ARP conflict on {conflict_ip}: "
                      f"no scorable flows — rule-based only", flush=True)
                detail = (f"ARP table conflict: {conflict_ip} "
                          f"known={s['known']} forged={s['forged']} "
                          f"| no flows to score")
                self._trigger_alert("ARP POISONING", s['attacker_ip'], s['mac'],
                                    s['dp'], "RULE-BASED", detail)

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        C = Fore.CYAN + Style.BRIGHT
        D = Fore.CYAN
        R = Style.RESET_ALL
        W = 60

        print(flush=True)
        print(C + f"┌{'─'*W}┐" + R, flush=True)
        print(C + f"│{f'  STATUS REPORT  [{ts}]':^{W}}│" + R, flush=True)
        print(C + f"├{'─'*W}┤" + R, flush=True)
        info = f"  Switches: {len(self.datapaths)}   Flows: {len(self.flows)}   ARP: {len(self.arp_table)}"
        print(D + f"│{info:<{W}}│" + R, flush=True)
        print(C + f"├{'─'*W}┤" + R, flush=True)
        print(C + f"│{'  ATTACK STATISTICS':<{W}}│" + R, flush=True)

        all_types = ["ARP POISONING", "DNS HIJACKING", "SSL STRIPPING", "SESSION HIJACKING"]
        for atype in all_types:
            count = self.attack_counts.get(atype, 0)
            if count > 0:
                mark = Fore.RED + Style.BRIGHT + f"  ● {atype:<24} {count} detected"
            else:
                mark = D + f"  ○ {atype:<24} —"
            print(mark + ' ' * (W - len(f"  ● {atype:<24} {count} detected")) + D + "│" + R, flush=True)

        if self.detections:
            print(C + f"├{'─'*W}┤" + R, flush=True)
            print(C + f"│{'  RECENT ALERTS':<{W}}│" + R, flush=True)
            for d in self.detections[-5:]:
                line = f"  [{d['time']}] {d['type']:<20} {d['method']:<26} {d['ip']}"
                if len(line) > W:
                    line = line[:W-2] + ".."
                print(Fore.RED + Style.BRIGHT + f"│{line:<{W}}│" + R, flush=True)

        blk = ', '.join(self.blocked_ips) or '(none)'
        print(C + f"├{'─'*W}┤" + R, flush=True)
        bline = f"  Blocked IPs: {blk}"
        if len(bline) > W:
            bline = bline[:W-2] + ".."
        print(D + f"│{bline:<{W}}│" + R, flush=True)
        print(C + f"└{'─'*W}┘" + R, flush=True)
        print(flush=True)


if __name__ == '__main__':
    pass