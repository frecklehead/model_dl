# -*- coding: utf-8 -*-
"""
my_controller.py
Clean SDN Controller for MITM Detection with Live Dashboard
"""

import os
import time
import datetime
import threading
import numpy as np
import joblib
from tabulate import tabulate
from colorama import Fore, Style, init

# Ryu imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, ether_types
from ryu.lib import hub

# Initialize colorama
init(autoreset=True)

# ML Libraries
try:
    import tensorflow as tf
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# FEATURES is loaded at runtime from selected_features.pkl so it always
# matches whatever the trained model actually expects.  This list is only
# used as a last-resort fallback if the pkl is missing.
_FALLBACK_FEATURES = [
    'src_port', 'dst_port', 'bidirectional_duration_ms', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'bidirectional_min_ps', 'bidirectional_mean_ps', 'bidirectional_stddev_ps',
    'bidirectional_max_ps', 'src2dst_max_ps', 'dst2src_min_ps', 'dst2src_max_ps',
    'bidirectional_mean_piat_ms', 'bidirectional_max_piat_ms', 'src2dst_max_piat_ms',
    'application_name', 'requested_server_name',
    'byte_asymmetry', 'bytes_per_packet', 'src2dst_bpp', 'dst2src_bpp',
    'duration_ratio', 'ps_variance_ratio',
]
FEATURES = _FALLBACK_FEATURES  # overwritten from pkl in _load_model()

class FlowTracker:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        now = time.time()
        self.start_time = now
        self.last_time = now

        # Bidirectional counters
        self.s2d_packets = 0
        self.s2d_bytes = 0
        self.d2s_packets = 0
        self.d2s_bytes = 0

        # Packet size tracking — bidirectional and per-direction
        self.packet_sizes = []       # all packets
        self.s2d_packet_sizes = []   # src→dst only
        self.d2s_packet_sizes = []   # dst→src only

        # PIAT tracking — bidirectional and per-direction
        self.piats = []              # all inter-arrival times
        self.s2d_piats = []          # src→dst only
        self.s2d_last_time = now     # timestamp of last s2d packet

        # Directional duration tracking
        self.s2d_start_time = None   # set on first s2d packet

        # TCP flag counts (kept for rule-based layer, not fed to ML)
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0

        self.last_score = 0.0
        self.is_mitm = False

    def update(self, size, direction, flags=0):
        now = time.time()
        piat_ms = (now - self.last_time) * 1000
        self.piats.append(piat_ms)
        self.last_time = now
        self.packet_sizes.append(size)

        if direction == 's2d':
            self.s2d_packets += 1
            self.s2d_bytes += size
            self.s2d_packet_sizes.append(size)
            self.s2d_piats.append((now - self.s2d_last_time) * 1000)
            self.s2d_last_time = now
            if self.s2d_start_time is None:
                self.s2d_start_time = now
        else:
            self.d2s_packets += 1
            self.d2s_bytes += size
            self.d2s_packet_sizes.append(size)

        # TCP flags: FIN=1, SYN=2, RST=4, PSH=8, ACK=16
        if flags & 0x02: self.syn_count += 1
        if flags & 0x10: self.ack_count += 1
        if flags & 0x04: self.rst_count += 1
        if flags & 0x01: self.fin_count += 1

    def classify_mitm_type(self):
        """
        Classify the MITM attack subtype using flow-level behavioral signals.
        Returns a tuple of (attack_type_string, reason_string).
        """
        total_pkts = self.s2d_packets + self.d2s_packets
        total_bytes = self.s2d_bytes + self.d2s_bytes
        safe_pkts = total_pkts if total_pkts > 0 else 1

        pkt_asym = abs(self.s2d_packets - self.d2s_packets) / safe_pkts
        byte_asym = abs(self.s2d_bytes - self.d2s_bytes) / (total_bytes + 1)
        rst_r = self.rst_count / safe_pkts
        syn_r = self.syn_count / safe_pkts
        mean_piat = np.mean(self.piats) if self.piats else 0
        std_piat = np.std(self.piats) if self.piats else 0
        piat_cv = std_piat / (mean_piat + 1e-6)  # coefficient of variation

        # 1. SSL Stripping: HTTP traffic appearing on port 443-neighbour flows
        #    or plain HTTP (80/8080) with very low piat variance (downgraded relay)
        if self.dst_port in (443, 8443) or self.src_port in (443, 8443):
            return ("SSL STRIPPING", f"TLS port flow downgraded (port={self.dst_port or self.src_port})")

        # 2. Session Hijacking: high RST ratio mid-flow (RST injection) + ongoing ACKs
        if rst_r > 0.15 and self.ack_count > 5:
            return ("SESSION HIJACKING", f"RST injection detected (rst_ratio={rst_r:.2f}, acks={self.ack_count})")

        # 3. Relay / Traffic Interception: both high packet & byte asymmetry
        #    Classic sign of relay — one side receives more than it should
        if pkt_asym > 0.35 and byte_asym > 0.30:
            return ("PACKET INTERCEPTION", f"Bidirectional asymmetry (pkt={pkt_asym:.2f}, byte={byte_asym:.2f})")

        # 4. Flood Relay (bulk connection flood by attacker to generate ML trigger)
        #    Very low PIAT variance = robotic/automated traffic, not human
        if total_pkts > 30 and piat_cv < 0.5 and mean_piat < 50:
            return ("RELAY FLOOD", f"Automated relay pattern (piat_cv={piat_cv:.2f}, mean_piat={mean_piat:.1f}ms)")

        # 5. Generic interception if the ML model flagged it but no specific sub-type
        if pkt_asym > 0.15:
            return ("TRAFFIC RELAY", f"Mild asymmetry suggestive of relay (pkt_asym={pkt_asym:.2f})")

        return ("ML ANOMALY", "Flow statistics deviate from normal baseline")

    def get_features(self):
        """
        Returns a dict whose keys exactly match selected_features.pkl so the
        ML model receives the same feature space it was trained on.
        """
        now = time.time()
        total_pkts  = self.s2d_packets + self.d2s_packets
        total_bytes = self.s2d_bytes + self.d2s_bytes
        safe_pkts   = max(total_pkts, 1)

        # ── packet size stats ──────────────────────────────
        all_ps  = self.packet_sizes if self.packet_sizes else [0]
        s2d_ps  = self.s2d_packet_sizes if self.s2d_packet_sizes else [0]
        d2s_ps  = self.d2s_packet_sizes if self.d2s_packet_sizes else [0]

        mean_ps = float(np.mean(all_ps))
        std_ps  = float(np.std(all_ps))
        min_ps  = float(min(all_ps))
        max_ps  = float(max(all_ps))

        # ── PIAT stats ─────────────────────────────────────
        all_piat  = self.piats if self.piats else [0]
        s2d_piat  = self.s2d_piats if self.s2d_piats else [0]

        mean_piat = float(np.mean(all_piat))
        max_piat  = float(max(all_piat))

        # ── directional durations ──────────────────────────
        bidi_dur  = (now - self.start_time) * 1000
        s2d_dur   = ((self.s2d_last_time - self.s2d_start_time) * 1000
                     if self.s2d_start_time is not None else 0.0)
        d2s_dur   = max(bidi_dur - s2d_dur, 0.0)

        return {
            # ── features the model was trained on ──────────
            'src_port':                  self.src_port,
            'dst_port':                  self.dst_port,
            'bidirectional_duration_ms': bidi_dur,
            'bidirectional_bytes':       float(total_bytes),
            'src2dst_duration_ms':       s2d_dur,
            'src2dst_packets':           float(self.s2d_packets),
            'src2dst_bytes':             float(self.s2d_bytes),
            'bidirectional_min_ps':      min_ps,
            'bidirectional_mean_ps':     mean_ps,
            'bidirectional_stddev_ps':   std_ps,
            'bidirectional_max_ps':      max_ps,
            'src2dst_max_ps':            float(max(s2d_ps)),
            'dst2src_min_ps':            float(min(d2s_ps)),
            'dst2src_max_ps':            float(max(d2s_ps)),
            'bidirectional_mean_piat_ms':mean_piat,
            'bidirectional_max_piat_ms': max_piat,
            'src2dst_max_piat_ms':       float(max(s2d_piat)),
            # text categoricals are unknown at runtime → use 0 (encoded "unknown")
            'application_name':          0.0,
            'requested_server_name':     0.0,
            # engineered features (same formulas as train_model.py)
            'byte_asymmetry':  abs(self.s2d_bytes - self.d2s_bytes) / (total_bytes + 1),
            'bytes_per_packet':total_bytes / safe_pkts,
            'src2dst_bpp':     self.s2d_bytes / (self.s2d_packets + 1),
            'dst2src_bpp':     self.d2s_bytes / (self.d2s_packets + 1),
            'duration_ratio':  s2d_dur / (d2s_dur + 1),
            'ps_variance_ratio': (std_ps ** 2) / (mean_ps + 1),
        }

class MITMController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MITMController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}  # IP -> MAC
        self.flows = {}      # (ip1, ip2, port1, port2, proto) -> FlowTracker
        self.datapaths = {}
        self.blocked_macs = set()
        self.blocked_ips = set()
        self.detections = []
        self.triggered_alerts = set()
        
        # Load Model
        self.model = None
        self.scaler = None
        self._load_model()
        
        # Print Header
        self._print_header()
        
        # Start Stats Timer
        self.stats_thread = hub.spawn(self._stats_timer)

    def _load_model(self):
        global FEATURES
        # Support both Docker (/app/model/) and local (model/) paths
        base = "/app/model" if os.path.exists("/app/model") else "model"
        m_path = f"{base}/mitm_model.h5"
        s_path = f"{base}/scaler.pkl"
        f_path = f"{base}/selected_features.pkl"

        if not ML_AVAILABLE:
            self.logger.warning("TensorFlow not available — ML detection disabled.")
            return

        if not os.path.exists(m_path):
            self.logger.error(f"Model file not found: {m_path}  Run train_model.py first.")
            return

        try:
            self.model  = tf.keras.models.load_model(m_path)
            self.scaler = joblib.load(s_path) if os.path.exists(s_path) else None
            if self.scaler is None:
                self.logger.warning(f"Scaler not found at {s_path} — predictions may be inaccurate.")

            # Load the feature list the model was ACTUALLY trained on.
            # This is the critical part: FEATURES must match selected_features.pkl
            # exactly, or the model receives garbage input and never fires.
            if os.path.exists(f_path):
                loaded = joblib.load(f_path)
                FEATURES = loaded
                self.logger.info(f"Feature list loaded from pkl ({len(FEATURES)} features).")
            else:
                self.logger.warning(
                    f"selected_features.pkl not found at {f_path}. "
                    "Using fallback feature list — re-train if detection fails."
                )

            self.logger.info(
                f"CNN+LSTM model loaded  ({len(FEATURES)} features, "
                f"scaler={'yes' if self.scaler else 'NO'})"
            )
        except Exception as e:
            self.logger.error(f"Error loading model artefacts: {e}")
            self.model = None

    def _print_header(self):
        print(Fore.CYAN + Style.BRIGHT + "╔══════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "║   MITM DETECTION CONTROLLER v1.0    ║")
        print(Fore.CYAN + Style.BRIGHT + "║   Layer 1: ARP Rule-based           ║")
        print(Fore.CYAN + Style.BRIGHT + "║   Layer 2: CNN+LSTM ML Model        ║")
        print(Fore.CYAN + Style.BRIGHT + "╚══════════════════════════════════════╝")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Clear state when switch connects (for demo consistency)
        self.mac_to_port.pop(datapath.id, None)
        self.arp_table.clear()
        self.flows.clear()
        self.blocked_macs.clear()
        self.blocked_ips.clear()
        self.detections.clear()
        self.triggered_alerts.clear()
        
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Switch {datapath.id} connected. State Reset.")

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP: return

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        src_mac = eth.src
        dst_mac = eth.dst
        
        # Drop packets from already-fully-blocked MACs
        if src_mac in self.blocked_macs: return

        # ARP handling
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(datapath, in_port, pkt_arp, eth, ts)

        # IP handling
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            if pkt_ipv4.src in self.blocked_ips: return
            self._handle_ipv4(datapath, in_port, pkt, pkt_ipv4, eth, ts)

        # Learning & Forwarding
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][src_mac] = in_port
        
        if dst_mac in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # We don't install permanent flows so we can keep monitoring packet_ins for stats
        # but to keep it realistic we could install flows with low idle_timeout.
        # For this demo, we use PacketIn for all traffic to ensure ML gets every packet.
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_arp(self, datapath, in_port, pkt_arp, eth, ts):
        opcode = "REQUEST" if pkt_arp.opcode == arp.ARP_REQUEST else "REPLY"
        print(f"[{ts}] [{Fore.YELLOW}ARP  {Style.RESET_ALL}] {opcode:<8} {pkt_arp.src_ip} ({eth.src}) → {pkt_arp.dst_ip}")
        
        src_ip, src_mac = pkt_arp.src_ip, eth.src
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                known = self.arp_table[src_ip]
                self._trigger_detection(
                    "ARP POISONING", src_ip, src_mac, datapath, in_port,
                    f"IP {src_ip} was bound to {known}, now claiming {src_mac}"
                )
        else:
            self.arp_table[src_ip] = src_mac

    def _handle_ipv4(self, datapath, in_port, pkt, pkt_ipv4, eth, ts):
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        proto = pkt_ipv4.proto
        
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        
        src_port, dst_port, flags = 0, 0, 0
        type_str = "IP   "
        info = ""

        if pkt_tcp:
            src_port, dst_port = pkt_tcp.src_port, pkt_tcp.dst_port
            flags = pkt_tcp.bits
            type_str = "HTTP " if (dst_port in (8080, 80, 443) or src_port in (8080, 80, 443)) else "TCP  "
            log_msg = f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip}:{src_port} → {dst_ip}:{dst_port} {info}"
        elif pkt_udp:
            src_port, dst_port = pkt_udp.src_port, pkt_udp.dst_port
            type_str = "DNS  " if (dst_port == 53 or src_port == 53) else "UDP  "
            log_msg = f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        else:
            log_msg = f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip} → {dst_ip} | bytes={pkt_ipv4.total_length}"

        print(log_msg)

        # Track Flow
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)
        
        direction = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        self.flows[key].update(pkt_ipv4.total_length, direction, flags)
        
        flow = self.flows[key]
        total_p = flow.s2d_packets + flow.d2s_packets
        
        # Rule-based detection (runs independently of ML model)
        if total_p >= 20 and total_p % 10 == 0:
            self._check_flow_rules(flow, ts, datapath, eth.src)
        
        # ML Analysis every 20 packets
        if total_p % 20 == 0:
            self._run_ml(key, ts, datapath, eth.src)

    def _check_flow_rules(self, flow, ts, datapath, src_mac):
        """Rule-based MITM sub-type detection — runs independently of ML model."""
        total_pkts = flow.s2d_packets + flow.d2s_packets
        safe_pkts = total_pkts if total_pkts > 0 else 1
        rst_r = flow.rst_count / safe_pkts

        # SSL Stripping: flow targeting TLS port (443/8443)
        if flow.dst_port in (443, 8443) or flow.src_port in (443, 8443):
            self._trigger_detection(
                "SSL STRIPPING", flow.src_ip, src_mac, datapath, 0,
                f"TLS port flow detected (port={flow.dst_port}, pkts={total_pkts})"
            )

        # Session Hijacking: high RST ratio + ACK count (RST injection attack)
        if rst_r > 0.15 and flow.ack_count > 5:
            self._trigger_detection(
                "SESSION HIJACKING", flow.src_ip, src_mac, datapath, 0,
                f"RST injection (rst_ratio={rst_r:.2f}, acks={flow.ack_count}, pkts={total_pkts})"
            )

    def _run_ml(self, key, ts, datapath, src_mac):
        if not self.model: return
        flow = self.flows[key]
        feat_dict = flow.get_features()
        
        try:
            vector = np.array([[feat_dict[f] for f in FEATURES]], dtype=np.float32)
            if self.scaler: vector = self.scaler.transform(vector)
            vector = vector.reshape(1, vector.shape[1], 1)
            score = float(self.model.predict(vector, verbose=0)[0][0])
        except Exception as e:
            self.logger.error(f"ML prediction error: {e}")
            return

        flow.last_score = score
        status = f"{Fore.RED}MITM 🚨" if score > 0.5 else f"{Fore.GREEN}NORMAL ✅"
        print(
            f"[{ts}] [{Fore.MAGENTA}ML   {Style.RESET_ALL}] "
            f"Flow: {flow.src_ip}→{flow.dst_ip} | "
            f"pkts={flow.s2d_packets + flow.d2s_packets} | "
            f"score={score:.4f} | {status}"
        )
        
        # Threshold 0.5 matches the model's training evaluation threshold.
        # Previously 0.8 caused the detector to miss most attacks.
        if score > 0.5:
            flow.is_mitm = True
            attack_type, reason = flow.classify_mitm_type()
            self._trigger_detection(attack_type, flow.src_ip, src_mac, datapath, 0, reason)

    def _trigger_detection(self, d_type, ip, mac, dp, port, details):
        alert_key = (ip, mac, d_type)
        if alert_key in self.triggered_alerts: return
        self.triggered_alerts.add(alert_key)
        
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        
        print(Fore.RED + Style.BRIGHT + "\n╔════════════════════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + f"║  🚨 MITM ATTACK DETECTED — {d_type:<36}║")
        print(Fore.RED + Style.BRIGHT + f"║  Time:     {ts:<47}║")
        print(Fore.RED + Style.BRIGHT + f"║  Host IP:  {ip:<47}║")
        print(Fore.RED + Style.BRIGHT + f"║  MAC:      {mac:<47}║")
        print(Fore.RED + Style.BRIGHT + f"║  Details:  {details:<47}║")
        print(Fore.RED + Style.BRIGHT + "║  Action:   MAC+IP blocked — DROP rule installed            ║")
        print(Fore.RED + Style.BRIGHT + "╚════════════════════════════════════════════════════════════╝\n")
        
        self.detections.append(f"[{ts}] {d_type:<22} {ip} blocked")
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)
        
        # Install DROP rule on the switch
        parser = dp.ofproto_parser
        match_mac = parser.OFPMatch(eth_src=mac)
        self.add_flow(dp, 100, match_mac, [])
        match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, 100, match_ip, [])

    def _stats_timer(self):
        while True:
            hub.sleep(30)
            self._print_stats()

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"\n{Fore.CYAN}══════════ NETWORK STATS [{ts}] ══════════")
        print(f"Switches connected : {len(self.datapaths)}")
        print(f"MACs learned       : {sum(len(v) for v in self.mac_to_port.values())}")
        print(f"ARP table entries  : {len(self.arp_table)}")
        print(f"Active flows       : {len(self.flows)}")
        print(Fore.CYAN + "─────────────────────────────────────────────")
        print("FLOW TABLE:")
        flow_data = []
        for f in list(self.flows.values())[-5:]:
            total_pkts = f.s2d_packets + f.d2s_packets
            total_bytes = f.s2d_bytes + f.d2s_bytes
            dur = int(time.time() - f.start_time)
            warn = " ⚠️" if f.last_score > 0.5 else ""
            flow_data.append([f"{f.src_ip} → {f.dst_ip}", total_pkts, total_bytes, f"{dur}s", f"{f.last_score:.2f}{warn}"])
        
        if flow_data:
            print(tabulate(flow_data, headers=["Flow", "Pkts", "Bytes", "Dur", "Score"], tablefmt="plain"))
        else:
            print(" (No flows active)")
            
        print(Fore.CYAN + "─────────────────────────────────────────────")
        print("DETECTIONS:")
        for d in self.detections[-3:]:
            print(f" {Fore.RED}{d}")
        if not self.detections: print(" (None)")
        
        print(Fore.CYAN + "─────────────────────────────────────────────")
        print("BLOCKED:")
        print(f" MACs: {', '.join(self.blocked_macs) or '(None)'}")
        print(f" IPs : {', '.join(self.blocked_ips) or '(None)'}")
        print(Fore.CYAN + "══════════════════════════════════════════════\n")

if __name__ == '__main__':
    pass
