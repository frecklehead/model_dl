# -*- coding: utf-8 -*-
"""
my_controller.py - Unified MITM Detection Controller v5.1

Detection matrix:
  Attack               Primary               Fallback
  ─────────────────────────────────────────────────────────────
  ARP Poisoning      ML >= 0.5 + conflict   RULE: no flows after 20s
  Transparent Relay  MAC/IP binding         Ingress port anomaly
  SSL Stripping      ML >= 0.5              RULE: port 443 + 20 pkts
  Session Hijacking  ML >= 0.5              RULE: RST>15% + ACK>5
  DNS Hijacking      Response timing<2ms    RULE: multi-IP divergence

v5.1 changes (bug-fixes + combined confidence):
  - All syntax errors corrected (_rule_fallback, _get_best_flow_score).
  - _combined_confidence(): merges ML score and rule-based evidence into a
    single [0,1] confidence value shown in every alert.
      • ML only            : raw ML score
      • Rule only          : 0.70
      • Both               : 0.6*ml + 0.4*1.0, capped at 1.0
  - ARP-poisoning alerts now always print ML Score + Confidence lines.
  - _check_mac_ip_binding fixed: retrieves best ML score from existing flows
    before calling _trigger_alert so ml_score is always defined.
  - _rule_fallback fixed: port_anomaly block rewritten with correct variable
    references and valid Python syntax throughout.
  - _get_best_flow_score: removed space in name, fixed `retuurn` typo.
"""

import os, time, datetime, json, collections
import numpy as np
import joblib
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

# ── Feature list (overwritten from selected_features.pkl at startup) ──────────
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

DNS_PORT         = 53
ML_THRESHOLD     = 0.5
DNS_SPOOF_RTT_MS = 2.0


# ─────────────────────────────────────────────────────────────────────────────
class FlowTracker:
    """
    Per-flow statistics accumulator.

    v5.0 attributes:
      port_anomaly     — set True by controller when this flow's src IP
                         arrived on the wrong ingress port (transparent relay)
      mac_ip_mismatch  — set True when src MAC doesn't match ip_to_mac entry
    """

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

        self.last_score      = 0.0
        self.is_mitm         = False
        self.port_anomaly    = False
        self.mac_ip_mismatch = False

    @property
    def total_packets(self):
        return self.s2d_packets + self.d2s_packets

    def update(self, size, direction, flags=0):
        now = time.time()
        self.piats.append((now - self.last_time) * 1000)
        self.last_time = now
        self.packet_sizes.append(size)

        if direction == 's2d':
            self.s2d_packets += 1;  self.s2d_bytes += size
            self.s2d_packet_sizes.append(size)
            self.s2d_piats.append((now - self.s2d_last_time) * 1000)
            self.s2d_last_time = now
            if self.s2d_start_time is None:
                self.s2d_start_time = now
        else:
            self.d2s_packets += 1;  self.d2s_bytes += size
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
            'port_anomaly':      1.0 if self.port_anomaly    else 0.0,
            'mac_ip_mismatch':   1.0 if self.mac_ip_mismatch else 0.0,
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

        if self.port_anomaly or self.mac_ip_mismatch:
            flags = []
            if self.port_anomaly:    flags.append("ingress_port_mismatch")
            if self.mac_ip_mismatch: flags.append("mac_ip_mismatch")
            return "TRANSPARENT RELAY / MITM", " + ".join(flags)
        if (self.dst_port == DNS_PORT or self.src_port == DNS_PORT) and self.protocol == 17:
            return "DNS HIJACKING",     f"UDP/53 flow, pkts={safe}"
        if self.dst_port in (443, 8443) or self.src_port in (443, 8443):
            return "SSL STRIPPING",     f"TLS port {self.dst_port or self.src_port}, pkts={safe}"
        if rst_r > 0.15 and self.ack_count > 5:
            return "SESSION HIJACKING", f"RST ratio={rst_r:.2f}, ACKs={self.ack_count}"
        if pkt_a > 0.35 and byte_a > 0.30:
            return "PACKET INTERCEPTION", f"pkt_asym={pkt_a:.2f}, byte_asym={byte_a:.2f}"
        if self.total_packets > 30 and cv < 0.5 and mi < 50:
            return "RELAY FLOOD",       f"piat_cv={cv:.2f}, mean_piat={mi:.1f}ms"
        if pkt_a > 0.15:
            return "TRAFFIC RELAY",     f"pkt_asym={pkt_a:.2f}"
        return "ML ANOMALY", "flow statistics deviate from baseline"


# ─────────────────────────────────────────────────────────────────────────────
class MITMController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port   = {}
        self.datapaths     = {}

        self.arp_table     = {}
        self.arp_conflicts = {}
        self.dai_bindings  = {}

        self.ip_to_mac  = {}
        self.ip_to_port = {}

        self.dns_responses   = {}
        self.dns_query_times = {}

        self.flows = {}

        self.blocked_macs     = set()
        self.blocked_ips      = set()
        self.detections       = []
        self.triggered_alerts = set()
        self.ml_flagged_flows = set()
        self.attack_counts    = collections.defaultdict(int)
        self.arp_suspects     = {}

        self.model  = None
        self.scaler = None
        self._load_model()
        self._print_banner()
        hub.spawn(self._stats_loop)

    # ─────────────────────────────────────────────────────────────────────────
    # COMBINED CONFIDENCE SCORE
    # ─────────────────────────────────────────────────────────────────────────
    def _combined_confidence(self, ml_score, rule_triggered):
        """
        Merge ML probability and rule-based evidence into a single [0,1]
        confidence value that is printed in every alert.

        Logic:
          ML only   (rule_triggered=False) : confidence = ml_score
          Rule only (ml_score=None)        : confidence = 0.70
          Both                             : confidence = min(1.0, 0.6*ml + 0.4*1.0)
        """
        if ml_score is None and not rule_triggered:
            return 0.0
        if ml_score is None:
            return 0.70
        if not rule_triggered:
            return float(ml_score)
        return min(1.0, 0.6 * float(ml_score) + 0.4)

    # ─────────────────────────────────────────────────────────────────────────
    # MODEL LOADING
    # ─────────────────────────────────────────────────────────────────────────
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
            self.logger.info(
                f"CNN+LSTM model loaded. Features={len(FEATURES)}, "
                f"Scaler={'YES' if self.scaler else 'NO'}"
            )
        except Exception as e:
            self.logger.error(f"Model load failed: {e}")
            self.model = None

    def _ml_score(self, flow):
        """Run ML inference. Returns float in [0,1] or None on error/no model."""
        if not self.model:
            return None
        try:
            fd  = flow.get_features()
            vec = np.array([[fd[f] for f in FEATURES]], dtype=np.float32)
            if self.scaler:
                vec = self.scaler.transform(vec)
            vec = vec.reshape(1, len(FEATURES), 1)
            if getattr(self, '_model_is_savedmodel', False):
                return float(self.model.serve(tf.constant(vec))[0][0])
            return float(self.model.predict(vec, verbose=0)[0][0])
        except Exception as e:
            self.logger.error(f"ML score error: {e}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # BANNER
    # ─────────────────────────────────────────────────────────────────────────
    def _print_banner(self):
        ml = "LOADED" if self.model else "NOT FOUND (rule-based only)"
        lines = [
            "=" * 66,
            "  MITM DETECTION CONTROLLER v5.1",
            f"  ML Model    : {ml}",
            f"  Features    : {len(FEATURES)}",
            f"  ML Threshold: {ML_THRESHOLD}  (single value, used everywhere)",
            f"  DNS RTT     : {DNS_SPOOF_RTT_MS}ms spoof threshold",
            f"  Confidence  : 0.6*ML + 0.4*Rule when both active",
            "-" * 66,
            "  Attack              Primary                  Fallback",
            "  ──────────────────────────────────────────────────────",
            "  ARP Poisoning     ML>=0.5 + conflict       RULE: no flows after 20s",
            "  Transparent Relay MAC/IP binding table      Ingress port anomaly",
            "  SSL Stripping     ML>=0.5                  RULE: port 443 + 20pkts",
            "  Session Hijacking ML>=0.5                  RULE: RST>15% + ACK>5",
            "  DNS Hijacking     Timing <2ms              RULE: multi-IP divergence",
            "=" * 66,
        ]
        for l in lines:
            print(Fore.CYAN + Style.BRIGHT + l, flush=True)

    # ─────────────────────────────────────────────────────────────────────────
    # DATAPATH MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────────
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
                     'triggered_alerts', 'ml_flagged_flows', 'attack_counts',
                     'arp_suspects', 'ip_to_mac', 'ip_to_port', 'dns_query_times'):
            getattr(self, attr).clear()
        self.mac_to_port.pop(dp.id, None)

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(Fore.GREEN + Style.BRIGHT +
              f"\n[{ts}] *** Switch CONNECTED: dpid={dp.id} ***", flush=True)

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        print(f"[{ts}]   Table-miss flow installed.", flush=True)

    def _add_flow(self, dp, priority, match, actions):
        parser  = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority,
                                      match=match, instructions=inst))

    # ─────────────────────────────────────────────────────────────────────────
    # PACKET-IN
    # ─────────────────────────────────────────────────────────────────────────
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

        if src_mac in self.blocked_macs:
            return

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._check_mac_ip_binding(src_mac, pkt_arp.src_ip, in_port, dp, ts)
            self._handle_arp(dp, in_port, pkt_arp, eth, ts)

        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip:
            if pkt_ip.src in self.blocked_ips:
                return
            self._check_mac_ip_binding(src_mac, pkt_ip.src, in_port, dp, ts)
            self._handle_ip(dp, in_port, pkt, pkt_ip, eth, ts)

        self.mac_to_port.setdefault(dp.id, {})[src_mac] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]
        data     = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # v5.0 — MAC / IP BINDING CHECK
    # ─────────────────────────────────────────────────────────────────────────
    def _check_mac_ip_binding(self, src_mac, src_ip, in_port, dp, ts):
        """
        Maintains ip_to_mac and ip_to_port tables.  First sighting = ground truth.
        Subsequent sightings with a different MAC or port fire alerts.

        BUG FIX (v5.1): ml_score is now fetched from existing flows for this IP
        before calling _trigger_alert, so it is always defined in scope.
        Confidence is computed with _combined_confidence(ml_score, rule=True).
        """
        if not src_ip or src_ip in ('0.0.0.0', '255.255.255.255'):
            return

        dpid   = dp.id
        ip_key = (dpid, src_ip)

        # ── MAC binding check ─────────────────────────────────────────────────
        if ip_key in self.ip_to_mac:
            known_mac = self.ip_to_mac[ip_key]
            if known_mac != src_mac:
                # FIX: retrieve best ML score from existing flows (may be 0 if
                # no flow has been scored yet — that is fine and honest).
                ml_score   = self._get_best_flow_score(src_ip)
                confidence = self._combined_confidence(
                    ml_score if ml_score > 0 else None, rule_triggered=True
                )
                print(
                    f"[{ts}] [BIND ] MAC/IP CONFLICT  "
                    f"ip={src_ip} was={known_mac} now={src_mac} "
                    f"port={in_port}  conf={confidence:.2f}",
                    flush=True
                )
                self._set_flow_flag(src_ip, 'mac_ip_mismatch', True)
                self._trigger_alert(
                    "ARP POISONING",
                    src_ip, src_mac, dp,
                    "RULE + ML",
                    f"ip={src_ip} previously at MAC {known_mac}, "
                    f"now claiming MAC {src_mac} on port {in_port}",
                    ml_score   = ml_score if ml_score > 0 else None,
                    confidence = confidence,
                )
                if src_ip not in self.arp_suspects:
                    attacker_ip = next(
                        (ip for (d, ip), mac in self.ip_to_mac.items()
                         if mac == src_mac and ip != src_ip and d == dpid),
                        src_ip
                    )
                    self.arp_suspects[src_ip] = {
                        'known': known_mac, 'forged': src_mac,
                        'attacker_ip': attacker_ip,
                        'mac': src_mac, 'dp': dp, 'at': time.time(),
                    }
                return
        else:
            self.ip_to_mac[ip_key] = src_mac

        # ── Ingress port binding check ────────────────────────────────────────
        if ip_key in self.ip_to_port:
            registered_port = self.ip_to_port[ip_key]
            if registered_port != in_port:
                ml_score   = self._get_best_flow_score(src_ip)
                confidence = self._combined_confidence(
                    ml_score if ml_score > 0 else None, rule_triggered=True
                )
                print(
                    f"[{ts}] [BIND ] INGRESS PORT ANOMALY  "
                    f"ip={src_ip} registered_port={registered_port} "
                    f"actual_port={in_port}  → TRANSPARENT RELAY  "
                    f"conf={confidence:.2f}",
                    flush=True
                )
                self._set_flow_flag(src_ip, 'port_anomaly', True)
                self._trigger_alert(
                    "TRANSPARENT RELAY / MITM",
                    src_ip, src_mac, dp,
                    "INGRESS PORT ANOMALY",
                    f"ip={src_ip} normally on port {registered_port}, "
                    f"arrived on port {in_port} — packets forwarded by another host",
                    ml_score   = ml_score if ml_score > 0 else None,
                    confidence = confidence,
                )
        else:
            self.ip_to_port[ip_key] = in_port

    def _set_flow_flag(self, ip, flag_name, value):
        """Set a boolean flag on all flows whose src or dst IP matches."""
        for flow in self.flows.values():
            if flow.src_ip == ip or flow.dst_ip == ip:
                setattr(flow, flag_name, value)

    # ─────────────────────────────────────────────────────────────────────────
    # ARP HANDLER
    # ─────────────────────────────────────────────────────────────────────────
    def _handle_arp(self, dp, in_port, pkt_arp, eth, ts):
        op      = "REQUEST" if pkt_arp.opcode == arp.ARP_REQUEST else "REPLY"
        src_ip  = pkt_arp.src_ip
        src_mac = eth.src
        print(
            f"[{ts}] [ARP  ] {op:<8} {src_ip} ({src_mac}) -> {pkt_arp.dst_ip}",
            flush=True
        )

        if src_ip in self.arp_table:
            known = self.arp_table[src_ip]
            if known != src_mac:
                self.arp_conflicts[src_ip] = (known, src_mac)
                print(
                    f"[{ts}] [ARP  ] *** CONFLICT: {src_ip} "
                    f"known={known} forged={src_mac} ***",
                    flush=True
                )
                attacker_ip = next(
                    (ip for ip, mac in self.arp_table.items()
                     if mac == src_mac and ip != src_ip),
                    src_ip
                )
                if self.model:
                    self.arp_suspects.setdefault(src_ip, {
                        'known': known, 'forged': src_mac,
                        'attacker_ip': attacker_ip, 'mac': src_mac,
                        'dp': dp, 'at': time.time(),
                    })
                    print(
                        f"[{ts}] [ARP  ] Suspect registered — scanning flows "
                        f"for ML confirmation (threshold={ML_THRESHOLD}) …",
                        flush=True
                    )
                    self._scan_flows_for_arp_suspect(src_ip, ts, dp, src_mac)
                else:
                    alert_key = (src_ip, src_mac, "ARP POISONING")
                    if alert_key not in self.triggered_alerts:
                        self._trigger_alert(
                            "ARP POISONING", attacker_ip, src_mac, dp,
                            "RULE-BASED",
                            f"ARP conflict: {src_ip} known={known} forged={src_mac} | ML not loaded",
                            ml_score=None, confidence=0.70,
                        )
                return
        else:
            self.arp_table[src_ip] = src_mac

        self.dai_bindings.setdefault(src_ip, set()).add(src_mac)
        if len(self.dai_bindings[src_ip]) > 1:
            print(
                f"[{ts}] [DAI  ] {len(self.dai_bindings[src_ip])} MACs "
                f"claim {src_ip}: {sorted(self.dai_bindings[src_ip])}",
                flush=True
            )

    # ─────────────────────────────────────────────────────────────────────────
    # IPv4 HANDLER
    # ─────────────────────────────────────────────────────────────────────────
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
            label    = ("HTTP " if dst_port in (80, 443, 8080)
                        or src_port in (80, 443, 8080) else "TCP  ")
        elif pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            label    = "DNS  " if DNS_PORT in (src_port, dst_port) else "UDP  "
            self._handle_dns(pkt_udp, src_ip, dst_ip, eth.src, ts, dp)
        else:
            label = "IP   "

        print(
            f"[{ts}] [{label}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            flush=True
        )

        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)

        flow      = self.flows[key]
        direction = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        flow.update(pkt_ip.total_length, direction, flags)

        ip_key_src = (dp.id, src_ip)
        if ip_key_src in self.ip_to_port:
            if self.ip_to_port[ip_key_src] != in_port:
                flow.port_anomaly = True
        if ip_key_src in self.ip_to_mac:
            if self.ip_to_mac[ip_key_src] != eth.src:
                flow.mac_ip_mismatch = True

        n = flow.total_packets

        if n >= 5 and n % 5 == 0 and key not in self.ml_flagged_flows:
            self._run_ml_on_flow(key, flow, ts, dp, eth.src)

        if n >= 20 and n % 10 == 0 and key not in self.ml_flagged_flows:
            self._rule_fallback(flow, ts, dp, eth.src)

    # ─────────────────────────────────────────────────────────────────────────
    # v5.0 — DNS HANDLER
    # ─────────────────────────────────────────────────────────────────────────
    def _handle_dns(self, pkt_udp, src_ip, dst_ip, src_mac, ts, dp):
        try:
            payload = bytes(pkt_udp.data) if pkt_udp.data else b''
            if len(payload) < 12:
                return

            txid    = int.from_bytes(payload[0:2], 'big')
            is_qr   = bool((payload[2] >> 7) & 1)
            ancount = int.from_bytes(payload[6:8], 'big')

            if not is_qr:
                self.dns_query_times[(src_ip, txid)] = time.time()
                return

            if ancount == 0:
                return

            query_key = (dst_ip, txid)
            if query_key in self.dns_query_times:
                query_ts   = self.dns_query_times.pop(query_key)
                elapsed_ms = (time.time() - query_ts) * 1000.0
                print(
                    f"[{ts}] [DNS  ] TxID=0x{txid:04x} response to {dst_ip} "
                    f"from {src_ip}  elapsed={elapsed_ms:.2f}ms",
                    flush=True
                )
                if elapsed_ms < DNS_SPOOF_RTT_MS:
                    confidence = self._combined_confidence(None, rule_triggered=True)
                    self._trigger_alert(
                        "DNS HIJACKING", src_ip, src_mac, dp,
                        "RESPONSE TIMING",
                        f"TxID=0x{txid:04x} response in {elapsed_ms:.2f}ms "
                        f"< threshold {DNS_SPOOF_RTT_MS}ms — on-path spoof",
                        ml_score=None, confidence=confidence,
                    )
                    return

            pos, parts = 12, []
            while pos < len(payload) and payload[pos] != 0:
                ln = payload[pos]
                if pos + 1 + ln > len(payload):
                    break
                parts.append(payload[pos+1:pos+1+ln].decode('ascii', errors='ignore'))
                pos += 1 + ln
            domain = '.'.join(parts) if parts else f'?@{src_ip}'

            self.dns_responses.setdefault(domain, set()).add(src_ip)
            if len(self.dns_responses[domain]) > 1:
                ips        = ', '.join(sorted(self.dns_responses[domain]))
                confidence = self._combined_confidence(None, rule_triggered=True)
                self._trigger_alert(
                    "DNS HIJACKING", src_ip, src_mac, dp,
                    "RULE-BASED (IP DIVERGENCE)",
                    f"domain '{domain}' answered by multiple IPs: [{ips}]",
                    ml_score=None, confidence=confidence,
                )

        except Exception as e:
            self.logger.debug(f"DNS parse error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # ML — scan flows for an ARP suspect immediately
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_flows_for_arp_suspect(self, conflict_ip, ts, dp, src_mac):
        for key, flow in list(self.flows.items()):
            if flow.src_ip != conflict_ip and flow.dst_ip != conflict_ip:
                continue
            if key in self.ml_flagged_flows:
                continue
            if flow.total_packets < 3:
                continue
            self._run_ml_on_flow(key, flow, ts, dp, src_mac)

    # ─────────────────────────────────────────────────────────────────────────
    # ML — score one flow
    # ─────────────────────────────────────────────────────────────────────────
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
                sub_detail    = (
                    f"score={score:.4f} | ARP conflict: {conflict_ip} "
                    f"known={known} forged={forged}"
                )
                suspect    = self.arp_suspects.pop(conflict_ip, None)
                alert_ip   = suspect['attacker_ip'] if suspect else flow.src_ip
                alert_mac  = suspect['mac']         if suspect else src_mac
            else:
                alert_ip  = flow.src_ip
                alert_mac = src_mac

            # Rule condition: is there an ARP conflict OR structural flag?
            rule_triggered = (
                conflict_ip is not None
                or flow.port_anomaly
                or flow.mac_ip_mismatch
            )
            confidence = self._combined_confidence(score, rule_triggered)

            print(
                f"[{ts}] [ML   ] DETECTED {attack_type} "
                f"{flow.src_ip}->{flow.dst_ip} "
                f"score={score:.4f} conf={confidence:.2f}",
                flush=True
            )
            self._trigger_alert(
                attack_type, alert_ip, alert_mac, dp,
                "ML + RULE",
                sub_detail,
                ml_score   = score,
                confidence = confidence,
            )
        else:
            print(
                f"[{ts}] [ML   ] {flow.src_ip}->{flow.dst_ip} "
                f"pkts={flow.total_packets} score={score:.4f} NORMAL",
                flush=True
            )

    # ─────────────────────────────────────────────────────────────────────────
    # RULE-BASED FALLBACK
    # BUG FIX (v5.1): rewrote port_anomaly block — src_ip was undefined,
    # score= assignment was embedded in the function call, f-string was a stray
    # expression outside the call.  All fixed below.
    # ─────────────────────────────────────────────────────────────────────────
    def _rule_fallback(self, flow, ts, dp, src_mac):
        n     = flow.total_packets
        rst_r = flow.rst_count / max(n, 1)

        # Port anomaly — transparent relay
        if flow.port_anomaly:
            ml_score   = self._get_best_flow_score(flow.src_ip)  # FIX: was src_ip (undefined)
            score      = ml_score if ml_score > 0 else None       # FIX: assigned before use
            confidence = self._combined_confidence(score, rule_triggered=True)
            self._trigger_alert(                                   # FIX: single valid call
                "TRANSPARENT RELAY / MITM",
                flow.src_ip, src_mac, dp,
                "INGRESS PORT ANOMALY (FALLBACK)",
                f"src_ip={flow.src_ip} arrived on unexpected switch port "
                f"| ML score={score:.4f if score is not None else 'N/A'} "
                f"| conf={confidence:.2f}",
                ml_score   = score,
                confidence = confidence,
            )

        # MAC/IP mismatch — ARP poison confirmed by flow data
        if flow.mac_ip_mismatch:
            ml_score   = self._get_best_flow_score(flow.src_ip)
            score      = ml_score if ml_score > 0 else None
            confidence = self._combined_confidence(score, rule_triggered=True)
            self._trigger_alert(
                "ARP POISONING",
                flow.src_ip, src_mac, dp,
                "MAC/IP BINDING (FALLBACK)",
                f"src_ip={flow.src_ip} MAC mismatch in active flow "
                f"| pkts={n} | ML score={flow.last_score:.4f} "
                f"| conf={confidence:.2f}",
                ml_score   = score,
                confidence = confidence,
            )

        # SSL stripping
        if flow.dst_port in (443, 8443) or flow.src_port in (443, 8443):
            confidence = self._combined_confidence(
                flow.last_score if flow.last_score > 0 else None, rule_triggered=True
            )
            self._trigger_alert(
                "SSL STRIPPING",
                flow.src_ip, src_mac, dp,
                "RULE-BASED FALLBACK",
                f"TLS port {flow.dst_port or flow.src_port} | pkts={n} "
                f"| ML score={flow.last_score:.4f} (<{ML_THRESHOLD}) "
                f"| conf={confidence:.2f}",
                ml_score   = flow.last_score if flow.last_score > 0 else None,
                confidence = confidence,
            )

        # Session hijacking
        if rst_r > 0.15 and flow.ack_count > 5:
            confidence = self._combined_confidence(
                flow.last_score if flow.last_score > 0 else None, rule_triggered=True
            )
            self._trigger_alert(
                "SESSION HIJACKING",
                flow.src_ip, src_mac, dp,
                "RULE-BASED FALLBACK",
                f"RST ratio={rst_r:.2f} ACKs={flow.ack_count} | pkts={n} "
                f"| ML score={flow.last_score:.4f} (<{ML_THRESHOLD}) "
                f"| conf={confidence:.2f}",
                ml_score   = flow.last_score if flow.last_score > 0 else None,
                confidence = confidence,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # ALERT PRINTER + BLOCKER
    # ─────────────────────────────────────────────────────────────────────────
    def _trigger_alert(self, attack_type, ip, mac, dp, method, detail,
                       ml_score=None, confidence=None):
        alert_key = (ip, mac, attack_type)
        if alert_key in self.triggered_alerts:
            return
        self.triggered_alerts.add(alert_key)
        self.attack_counts[attack_type] += 1

        # Compute confidence if not provided by caller
        if confidence is None:
            rule_triggered = method not in ("ML MODEL (CNN+LSTM)",)
            confidence = self._combined_confidence(ml_score, rule_triggered)

        ts = datetime.datetime.now().strftime('%H:%M:%S')

        HOW = {
            "ML MODEL (CNN+LSTM)": {
                "ARP POISONING":            "CNN+LSTM scored flow >=0.5 AND ARP table conflict confirmed",
                "TRANSPARENT RELAY / MITM": "CNN+LSTM scored relayed flow >=0.5 (port/MAC anomaly features)",
                "SSL STRIPPING":            "CNN+LSTM scored TLS-port flow >=0.5",
                "SESSION HIJACKING":        "CNN+LSTM scored RST/ACK flow >=0.5",
                "DNS HIJACKING":            "CNN+LSTM scored DNS-port flow >=0.5",
            },
            "ML + RULE": {
                "ARP POISONING":            "CNN+LSTM >=0.5 AND ARP table conflict; confidence=0.6*ML+0.4*rule",
                "TRANSPARENT RELAY / MITM": "CNN+LSTM >=0.5 AND port/MAC anomaly; confidence=0.6*ML+0.4*rule",
                "SSL STRIPPING":            "CNN+LSTM >=0.5 AND port 443/8443; confidence=0.6*ML+0.4*rule",
                "SESSION HIJACKING":        "CNN+LSTM >=0.5 AND RST>15%+ACK>5; confidence=0.6*ML+0.4*rule",
            },
            "RULE + ML": {
                "ARP POISONING": "MAC/IP binding violation; ML score folded into confidence",
            },
            "MAC/IP BINDING": {
                "ARP POISONING": "IP seen from a different MAC than registered during warm-up (RFC 5227)",
            },
            "INGRESS PORT ANOMALY": {
                "TRANSPARENT RELAY / MITM":
                    "IP arrived on a different switch port — host forwarding another host's packets",
            },
            "RESPONSE TIMING": {
                "DNS HIJACKING":
                    f"DNS response arrived in <{DNS_SPOOF_RTT_MS}ms — "
                    "faster than any real DNS server on this network (RFC 5452)",
            },
            "RULE-BASED": {
                "ARP POISONING":  "ARP reply changed IP->MAC; no scorable flows available",
                "DNS HIJACKING":  "Same domain resolved to different IPs by different servers",
            },
            "RULE-BASED (IP DIVERGENCE)": {
                "DNS HIJACKING":  "Same domain answered by multiple source IPs",
            },
            "INGRESS PORT ANOMALY (FALLBACK)": {
                "TRANSPARENT RELAY / MITM": "Port anomaly flag set on flow; rule-based confirmation",
            },
            "MAC/IP BINDING (FALLBACK)": {
                "ARP POISONING":  "MAC mismatch flag set on flow; rule-based confirmation",
            },
            "RULE-BASED FALLBACK": {
                "SSL STRIPPING":     "TCP flow to 443/8443 seen 20+ pkts; ML score below 0.5",
                "SESSION HIJACKING": "RST ratio>15% + ACK count>5 after 20+ pkts; ML score below 0.5",
            },
        }
        how = HOW.get(method, {}).get(attack_type, f"{method} detection triggered")

        W   = 64
        sep = "=" * 66
        dash = "-" * 66

        def _col(label, value):
            s = label + str(value)
            return f"|  {s[:W]:<{W}}|"

        print(flush=True)
        print(Fore.RED + Style.BRIGHT + f"+{sep}+",                                       flush=True)
        print(Fore.RED + Style.BRIGHT + f"|{'  *** MITM ATTACK DETECTED ***':<66}|",      flush=True)
        print(Fore.RED + Style.BRIGHT + f"+{dash}+",                                      flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Attack Type : ", attack_type),              flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Method      : ", method),                   flush=True)
        print(Fore.RED + Style.BRIGHT + _col("How         : ", how),                      flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Time        : ", ts),                       flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Host IP     : ", ip),                       flush=True)
        print(Fore.RED + Style.BRIGHT + _col("MAC         : ", mac),                      flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Details     : ", detail),                   flush=True)
        if ml_score is not None:
            print(Fore.RED + Style.BRIGHT + _col("ML Score    : ", f"{ml_score:.4f}"),    flush=True)
        else:
            print(Fore.RED + Style.BRIGHT + _col("ML Score    : ", "N/A (rule-based)"),   flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Confidence  : ", f"{confidence:.2f}"),      flush=True)
        print(Fore.RED + Style.BRIGHT + _col("Action      : ",
              "IP + MAC blocked — DROP flows installed"),                                  flush=True)
        print(Fore.RED + Style.BRIGHT + f"+{sep}+",                                       flush=True)
        print(flush=True)

        self.detections.append({
            "time": ts, "type": attack_type, "method": method,
            "ip": ip, "mac": mac, "detail": detail,
            "ml_score": ml_score, "confidence": confidence,
        })
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)

        try:
            log_path = "/tmp/mitm_alerts.json"
            existing = []
            try:
                existing = json.loads(open(log_path).read())
            except Exception:
                pass
            existing.append({
                "timestamp": ts, "attack_type": attack_type,
                "method": method, "how": how,
                "ip": ip, "mac": mac, "detail": detail,
                "ml_score": ml_score, "confidence": confidence,
            })
            open(log_path, 'w').write(json.dumps(existing, indent=2))
        except Exception:
            pass

        parser = dp.ofproto_parser
        self._add_flow(dp, 100, parser.OFPMatch(eth_src=mac), [])
        self._add_flow(dp, 100, parser.OFPMatch(eth_type=0x0800, ipv4_src=ip), [])

    # ─────────────────────────────────────────────────────────────────────────
    # STATS LOOP
    # ─────────────────────────────────────────────────────────────────────────
    def _stats_loop(self):
        while True:
            hub.sleep(10)
            self._flush_old_arp_suspects()
            self._expire_old_dns_queries()
            self._print_stats()

    def _expire_old_dns_queries(self):
        cutoff  = time.time() - 5.0
        expired = [k for k, v in self.dns_query_times.items() if v < cutoff]
        for k in expired:
            del self.dns_query_times[k]
        if expired:
            self.logger.debug(f"Expired {len(expired)} stale DNS query records")

    def _flush_old_arp_suspects(self):
        now = time.time()
        for conflict_ip, s in list(self.arp_suspects.items()):
            if now - s['at'] < 20:
                continue
            self.arp_suspects.pop(conflict_ip, None)
            ts = datetime.datetime.now().strftime('%H:%M:%S')

            best_score, best_flow, flows_found = 0.0, None, 0

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
                print(
                    f"[{ts}] [ML   ] Final ARP scan: "
                    f"{flow.src_ip}->{flow.dst_ip} "
                    f"pkts={flow.total_packets} score={score:.4f}",
                    flush=True
                )
                if score > best_score:
                    best_score, best_flow = score, flow

            if best_flow and best_score >= ML_THRESHOLD:
                confidence = self._combined_confidence(best_score, rule_triggered=True)
                detail = (
                    f"score={best_score:.4f} | conf={confidence:.2f} | "
                    f"ARP conflict: {conflict_ip} "
                    f"known={s['known']} forged={s['forged']} | "
                    f"best flow: {best_flow.src_ip}->{best_flow.dst_ip} "
                    f"pkts={best_flow.total_packets}"
                )
                print(
                    f"[{ts}] [ML   ] ARP POISONING confirmed "
                    f"score={best_score:.4f} conf={confidence:.2f} >= {ML_THRESHOLD}",
                    flush=True
                )
                self._trigger_alert(
                    "ARP POISONING", s['attacker_ip'], s['mac'],
                    s['dp'], "ML MODEL (CNN+LSTM)", detail,
                    ml_score=best_score, confidence=confidence,
                )

            elif flows_found > 0:
                print(
                    f"[{ts}] [ARP  ] Conflict on {conflict_ip}: "
                    f"{flows_found} flow(s), best_score={best_score:.4f} "
                    f"< {ML_THRESHOLD} — insufficient ML evidence, not flagging",
                    flush=True
                )
            else:
                print(
                    f"[{ts}] [ARP  ] Conflict on {conflict_ip}: "
                    f"no scorable flows — rule-based fallback",
                    flush=True
                )
                alert_key = (s['attacker_ip'], s['mac'], "ARP POISONING")
                if alert_key not in self.triggered_alerts:
                    confidence = self._combined_confidence(None, rule_triggered=True)
                    self._trigger_alert(
                        "ARP POISONING", s['attacker_ip'], s['mac'],
                        s['dp'], "RULE-BASED",
                        f"ARP conflict: {conflict_ip} known={s['known']} "
                        f"forged={s['forged']} | no flows to score",
                        ml_score=None, confidence=confidence,
                    )

    # BUG FIX (v5.1): removed space from method name, fixed `retuurn` typo
    def _get_best_flow_score(self, ip):
        """Return the highest last_score seen across all flows touching this IP."""
        best = 0.0
        for flow in self.flows.values():
            if flow.src_ip == ip or flow.dst_ip == ip:
                if flow.last_score is not None:
                    best = max(best, flow.last_score)
        return best  # FIX: was `retuurn`

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(Fore.CYAN + f"\n{'='*62} [{ts}]", flush=True)
        print(
            Fore.CYAN +
            f"  Switches={len(self.datapaths)}  "
            f"Flows={len(self.flows)}  "
            f"ARP entries={len(self.arp_table)}  "
            f"IP bindings={len(self.ip_to_port)}  "
            f"DNS queries pending={len(self.dns_query_times)}",
            flush=True
        )
        if self.attack_counts:
            print(Fore.CYAN + "  Attack counts:", flush=True)
            for atype, cnt in sorted(self.attack_counts.items()):
                print(Fore.CYAN + f"    {atype:<30}: {cnt}", flush=True)

        if self.detections:
            print(Fore.CYAN + "  Recent detections:", flush=True)
            for d in self.detections[-6:]:
                conf_str = f" | conf={d['confidence']:.2f}" if d.get('confidence') else ""
                print(
                    Fore.RED +
                    f"    [{d['time']}] {d['type']:<28} "
                    f"| {d['method']:<30} | {d['ip']}{conf_str}",
                    flush=True
                )
        print(
            Fore.CYAN +
            f"  Blocked IPs : {', '.join(self.blocked_ips) or '(none)'}",
            flush=True
        )
        print(Fore.CYAN + f"{'='*62}\n", flush=True)


if __name__ == '__main__':
    pass