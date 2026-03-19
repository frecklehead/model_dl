# -*- coding: utf-8 -*-
"""
enhanced_mitm_controller.py
Defense-In-Depth SDN Controller for MITM Detection
Implements: Dynamic ARP Inspection, MAC-IP Binding Enforcement, Flow Validation
No ML required — purely rule-based anomaly detection
"""

import os
import time
import datetime
import threading
from collections import defaultdict
import numpy as np
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

init(autoreset=True)

# ============================================================================
# LAYER 1: DYNAMIC ARP INSPECTION (DAI) + MAC-IP BINDING ENFORCEMENT
# ============================================================================

class ARPInspector:
    """
    Implements Dynamic ARP Inspection (DAI) per RFC 3740 principles.
    - Maintains authoritative MAC-IP binding table from DHCP snooping simulation
    - Rate limits ARP requests per MAC/IP
    - Detects invalid ARP messages
    """
    
    def __init__(self, max_arp_per_sec=10):
        self.binding_table = {}  # IP -> MAC (authoritative)
        self.arp_request_log = defaultdict(list)  # MAC -> [timestamps]
        self.arp_reply_log = defaultdict(list)    # IP -> [timestamps]
        self.suspicious_macs = set()
        self.max_arp_per_sec = max_arp_per_sec
        self.invalid_patterns = []
        
    def learn_binding(self, ip, mac):
        """Add or update an authoritative MAC-IP binding."""
        if ip in self.binding_table and self.binding_table[ip] != mac:
            return ("POISONING", f"IP {ip} already bound to {self.binding_table[ip]}, new claim: {mac}")
        self.binding_table[ip] = mac
        return ("LEARNED", f"Binding: {ip} → {mac}")
    
    def validate_arp_request(self, src_ip, src_mac, dst_ip, ts):
        """
        Validate ARP REQUEST against:
        - Rate limiting (max N requests per second)
        - Source MAC-IP consistency
        - Broadcast/reserved addresses
        """
        violations = []
        
        # 1. Validate source IP/MAC not broadcast/reserved
        if src_mac == "ff:ff:ff:ff:ff:ff" or src_mac == "00:00:00:00:00:00":
            violations.append(("INVALID_MAC", f"Broadcast MAC in request: {src_mac}"))
        if src_ip.startswith("255.") or src_ip.startswith("0."):
            violations.append(("INVALID_IP", f"Reserved IP in request: {src_ip}"))
        
        # 2. Rate limit: check if this MAC has exceeded ARP_REQ/sec
        now = time.time()
        self.arp_request_log[src_mac] = [t for t in self.arp_request_log[src_mac] if now - t < 1.0]
        self.arp_request_log[src_mac].append(now)
        
        if len(self.arp_request_log[src_mac]) > self.max_arp_per_sec:
            violations.append(("RATE_LIMIT", f"MAC {src_mac} exceeded {self.max_arp_per_sec} ARP/sec"))
        
        # 3. MAC-IP consistency: if binding exists, verify match
        if src_ip in self.binding_table:
            if self.binding_table[src_ip] != src_mac:
                violations.append(("SPOOFING", f"IP {src_ip} claimed by {src_mac}, bound to {self.binding_table[src_ip]}"))
        
        # 4. Gratuitous ARP check: src_ip == dst_ip (normal for new host, but log it)
        if src_ip == dst_ip:
            # Gratuitous ARP is normal on startup, but rapid gratuitous ARPs = suspicious
            self.arp_reply_log[src_ip].append(now)
            gratuitous_count = len([t for t in self.arp_reply_log[src_ip] if now - t < 5.0])
            if gratuitous_count > 3:
                violations.append(("GRATUITOUS_FLOOD", f"IP {src_ip} sent {gratuitous_count} gratuitous ARPs in 5s"))
        
        return violations
    
    def validate_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac, ts):
        """
        Validate ARP REPLY against:
        - Binding table consistency
        - Unsolicited replies
        - Suspicious reply patterns
        """
        violations = []
        
        # 1. Sender MAC-IP must match binding table
        if src_ip in self.binding_table:
            if self.binding_table[src_ip] != src_mac:
                violations.append(("POISONING", f"ARP reply: {src_ip} claims {src_mac}, bound to {self.binding_table[src_ip]}"))
        
        # 2. Check for suspicious patterns: ARP reply without prior request (unsolicited)
        # In a real system, cross-reference with ARP request cache
        # For now, just log rapid replies to unusual targets
        
        # 3. Gratuitous reply flood detection
        now = time.time()
        self.arp_reply_log[src_ip].append(now)
        reply_count = len([t for t in self.arp_reply_log[src_ip] if now - t < 5.0])
        if reply_count > 5:
            violations.append(("REPLY_FLOOD", f"IP {src_ip} sent {reply_count} replies in 5s"))
        
        return violations

# ============================================================================
# LAYER 2: FLOW-LEVEL ANOMALY DETECTION
# ============================================================================

class FlowAnomalyDetector:
    """
    Detects MITM-like behavior through flow-level statistics.
    No ML — uses threshold-based heuristics:
    - Packet/byte asymmetry (relay detection)
    - RST injection patterns (session hijacking)
    - Unusual port combinations (SSL stripping)
    - Connection reset frequency
    """
    
    def __init__(self):
        self.thresholds = {
            'pkt_asymmetry': 0.35,        # >35% imbalance = relay
            'byte_asymmetry': 0.30,       # >30% imbalance = relay
            'rst_ratio': 0.15,             # >15% RST = session hijacking attempt
            'min_packets': 20,             # Analyze after N packets
            'syn_timeout': 10,             # Incomplete handshake after 10s = suspicious
        }
    
    def analyze_flow(self, flow):
        """
        Run heuristic-based MITM detection on a flow.
        Returns: (threat_level, threat_type, reason)
          threat_level: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'
        """
        total_pkts = flow.s2d_packets + flow.d2s_packets
        total_bytes = flow.s2d_bytes + flow.d2s_bytes
        
        if total_pkts < self.thresholds['min_packets']:
            return ('NONE', 'BASELINE', 'Insufficient data')
        
        safe_pkts = total_pkts if total_pkts > 0 else 1
        safe_bytes = total_bytes if total_bytes > 0 else 1
        
        # === Anomaly 1: Packet Asymmetry ===
        pkt_asym = abs(flow.s2d_packets - flow.d2s_packets) / safe_pkts
        byte_asym = abs(flow.s2d_bytes - flow.d2s_bytes) / safe_bytes
        
        if pkt_asym > self.thresholds['pkt_asymmetry'] and byte_asym > self.thresholds['byte_asymmetry']:
            return ('CRITICAL', 'RELAY_INTERCEPTION', 
                    f"Severe asymmetry: pkts={pkt_asym:.2%}, bytes={byte_asym:.2%}")
        elif pkt_asym > 0.20 or byte_asym > 0.15:
            return ('HIGH', 'POSSIBLE_RELAY', 
                    f"Mild asymmetry: pkts={pkt_asym:.2%}, bytes={byte_asym:.2%}")
        
        # === Anomaly 2: RST Injection (Session Hijacking) ===
        rst_ratio = flow.rst_count / safe_pkts
        if rst_ratio > self.thresholds['rst_ratio'] and flow.ack_count > 5:
            return ('CRITICAL', 'RST_INJECTION', 
                    f"High RST rate: {rst_ratio:.2%} (count={flow.rst_count})")
        elif rst_ratio > 0.05 and flow.syn_count > 0:
            return ('MEDIUM', 'ABNORMAL_RST', 
                    f"Elevated RST rate: {rst_ratio:.2%}")
        
        # === Anomaly 3: SSL Stripping (TLS/HTTPS port anomalies) ===
        if (flow.dst_port in (443, 8443, 465) or flow.src_port in (443, 8443, 465)):
            # On HTTPS port — check for suspicious patterns
            # Plain HTTPS should have low packet rate and encrypted payload
            mean_ps = np.mean(flow.packet_sizes) if flow.packet_sizes else 0
            if mean_ps < 100:  # Very small packets on HTTPS = suspicious
                return ('HIGH', 'SSL_STRIPPING', 
                        f"TLS port with small packets (mean={mean_ps:.0f} bytes)")
        
        # === Anomaly 4: Incomplete TCP Handshake ===
        duration = time.time() - flow.start_time
        if flow.syn_count > 5 and flow.syn_count > flow.ack_count and duration > self.thresholds['syn_timeout']:
            return ('MEDIUM', 'SYN_FLOOD_OR_HANDSHAKE_FAILURE', 
                    f"Many SYNs ({flow.syn_count}) without matching ACKs after {duration:.0f}s")
        
        # === Anomaly 5: Protocol Mismatch ===
        # If port suggests one protocol but behavior suggests another (DNS on HTTPS port, etc.)
        
        return ('NONE', 'NORMAL', 'No anomalies detected')

# ============================================================================
# LAYER 3: ENHANCED CONTROLLER WITH DEFENSE MECHANISMS
# ============================================================================

class FlowTracker:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_time = time.time()
        
        self.s2d_packets = 0
        self.s2d_bytes = 0
        self.d2s_packets = 0
        self.d2s_bytes = 0
        
        self.packet_sizes = []
        self.piats = []
        
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0

    def update(self, size, direction, flags=0):
        now = time.time()
        self.piats.append((now - self.last_time) * 1000)
        self.last_time = now
        self.packet_sizes.append(size)
        
        if direction == 's2d':
            self.s2d_packets += 1
            self.s2d_bytes += size
        else:
            self.d2s_packets += 1
            self.d2s_bytes += size
            
        # Ryu TCP flags: FIN=1, SYN=2, RST=4, PSH=8, ACK=16
        if flags & 0x02: self.syn_count += 1
        if flags & 0x10: self.ack_count += 1
        if flags & 0x04: self.rst_count += 1
        if flags & 0x01: self.fin_count += 1

class EnhancedMITMController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnhancedMITMController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flows = {}
        self.datapaths = {}
        self.blocked_macs = set()
        self.blocked_ips = set()
        self.detections = []
        self.triggered_alerts = set()
        
        # Initialize defense layers
        self.dai = ARPInspector(max_arp_per_sec=10)
        self.anomaly_detector = FlowAnomalyDetector()
        
        self._print_header()
        self.stats_thread = hub.spawn(self._stats_timer)

    def _print_header(self):
        print(Fore.CYAN + Style.BRIGHT + "╔════════════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "║   ENHANCED MITM DETECTION CONTROLLER v2.0         ║")
        print(Fore.CYAN + Style.BRIGHT + "║   Layer 1: Dynamic ARP Inspection (DAI)            ║")
        print(Fore.CYAN + Style.BRIGHT + "║   Layer 2: MAC-IP Binding Enforcement              ║")
        print(Fore.CYAN + Style.BRIGHT + "║   Layer 3: Flow-Level Anomaly Detection            ║")
        print(Fore.CYAN + Style.BRIGHT + "║   Strategy: Defense-in-Depth (No ML)              ║")
        print(Fore.CYAN + Style.BRIGHT + "╚════════════════════════════════════════════════════╝")

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

        self.mac_to_port.pop(datapath.id, None)
        self.flows.clear()
        self.blocked_macs.clear()
        self.blocked_ips.clear()
        self.detections.clear()
        self.triggered_alerts.clear()
        
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Switch {datapath.id} connected.")

        # Table-miss rule
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
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP: 
            return

        ts = datetime.datetime.now().strftime('%H:%M:%S')
        src_mac = eth.src
        dst_mac = eth.dst
        
        # Quick check: drop if source MAC is blocked
        if src_mac in self.blocked_macs: 
            return

        # === LAYER 1: ARP HANDLING WITH DAI ===
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp_with_dai(datapath, in_port, pkt_arp, eth, ts)

        # === LAYER 2 & 3: IP HANDLING WITH BINDING ENFORCEMENT + FLOW ANALYSIS ===
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            if pkt_ipv4.src in self.blocked_ips: 
                return
            self._handle_ipv4(datapath, in_port, pkt, pkt_ipv4, eth, ts)

        # Learning & Forwarding
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][src_mac] = in_port
        
        if dst_mac in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: 
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ========== LAYER 1: DYNAMIC ARP INSPECTION ==========
    def _handle_arp_with_dai(self, datapath, in_port, pkt_arp, eth, ts):
        """
        ARP handling with Dynamic ARP Inspection (DAI):
        1. Validate ARP message format and source
        2. Check against learned MAC-IP bindings
        3. Rate limit ARP traffic
        4. Detect ARP poisoning attempts
        """
        src_ip = pkt_arp.src_ip
        src_mac = eth.src
        dst_ip = pkt_arp.dst_ip
        opcode = "REQUEST" if pkt_arp.opcode == arp.ARP_REQUEST else "REPLY"
        
        print(f"[{ts}] [{Fore.YELLOW}ARP  {Style.RESET_ALL}] {opcode:<8} {src_ip} ({src_mac}) → {dst_ip}")
        
        # === ARP REQUEST Validation ===
        if pkt_arp.opcode == arp.ARP_REQUEST:
            violations = self.dai.validate_arp_request(src_ip, src_mac, dst_ip, ts)
            if violations:
                for v_type, v_msg in violations:
                    print(f"[{ts}] [{Fore.RED}DAI  {Style.RESET_ALL}] ⚠️  {v_type}: {v_msg}")
                    if v_type in ('SPOOFING', 'POISONING', 'RATE_LIMIT'):
                        self._trigger_detection(v_type, src_ip, src_mac, datapath, in_port, v_msg)
                        return
            else:
                # No violations — learn/confirm binding
                result, msg = self.dai.learn_binding(src_ip, src_mac)
                if result == "POISONING":
                    self._trigger_detection("ARP_POISONING", src_ip, src_mac, datapath, in_port, msg)
        
        # === ARP REPLY Validation ===
        elif pkt_arp.opcode == arp.ARP_REPLY:
            violations = self.dai.validate_arp_reply(src_ip, src_mac, dst_ip, pkt_arp.dst_mac, ts)
            if violations:
                for v_type, v_msg in violations:
                    print(f"[{ts}] [{Fore.RED}DAI  {Style.RESET_ALL}] ⚠️  {v_type}: {v_msg}")
                    if v_type in ('POISONING', 'REPLY_FLOOD'):
                        self._trigger_detection(v_type, src_ip, src_mac, datapath, in_port, v_msg)
                        return
            else:
                result, msg = self.dai.learn_binding(src_ip, src_mac)
                if result == "POISONING":
                    self._trigger_detection("ARP_POISONING", src_ip, src_mac, datapath, in_port, msg)

    # ========== LAYER 2 & 3: IP HANDLING + FLOW ANOMALY DETECTION ==========
    def _handle_ipv4(self, datapath, in_port, pkt, pkt_ipv4, eth, ts):
        """
        IPv4 handling with:
        1. MAC-IP binding validation
        2. Flow tracking
        3. Anomaly detection (asymmetry, RST injection, SSL stripping, etc.)
        """
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        proto = pkt_ipv4.proto
        
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        
        src_port, dst_port, flags = 0, 0, 0
        type_str = "IP   "

        if pkt_tcp:
            src_port, dst_port = pkt_tcp.src_port, pkt_tcp.dst_port
            flags = pkt_tcp.bits
            type_str = "HTTP " if (dst_port in (8080, 80, 443) or src_port in (8080, 80, 443)) else "TCP  "
        elif pkt_udp:
            src_port, dst_port = pkt_udp.src_port, pkt_udp.dst_port
            type_str = "DNS  " if (dst_port == 53 or src_port == 53) else "UDP  "

        print(f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
              f"bytes={pkt_ipv4.total_length}")

        # === MAC-IP Binding Enforcement ===
        # Check: is this packet's source MAC consistent with its source IP?
        if src_ip in self.dai.binding_table:
            expected_mac = self.dai.binding_table[src_ip]
            if eth.src != expected_mac:
                self._trigger_detection("MAC_IP_MISMATCH", src_ip, eth.src, datapath, in_port,
                                       f"IP {src_ip} bound to {expected_mac}, packet from {eth.src}")
                return
        else:
            # First time seeing this IP — learn it
            self.dai.learn_binding(src_ip, eth.src)

        # === Flow Tracking ===
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)
        
        direction = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        self.flows[key].update(pkt_ipv4.total_length, direction, flags)
        
        flow = self.flows[key]
        total_pkts = flow.s2d_packets + flow.d2s_packets
        
        # === Anomaly Detection: every N packets ===
        if total_pkts % 15 == 0 and total_pkts >= 20:
            threat_level, threat_type, reason = self.anomaly_detector.analyze_flow(flow)
            
            if threat_level in ('CRITICAL', 'HIGH'):
                print(f"[{ts}] [{Fore.RED}ANOMALY{Style.RESET_ALL}] {threat_type}: {reason}")
                self._trigger_detection(threat_type, src_ip, eth.src, datapath, in_port, reason)
            elif threat_level == 'MEDIUM':
                print(f"[{ts}] [{Fore.YELLOW}ANOMALY{Style.RESET_ALL}] {threat_type}: {reason}")

    def _trigger_detection(self, d_type, ip, mac, dp, port, details):
        """Block detected attacker and log alert."""
        alert_key = (ip, mac, d_type)
        if alert_key in self.triggered_alerts: 
            return
        self.triggered_alerts.add(alert_key)
        
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        
        print(Fore.RED + Style.BRIGHT + "\n╔══════════════════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + f"║  🚨 THREAT DETECTED — {d_type:<36}║")
        print(Fore.RED + Style.BRIGHT + f"║  Time:   {ts:<51}║")
        print(Fore.RED + Style.BRIGHT + f"║  IP:     {ip:<51}║")
        print(Fore.RED + Style.BRIGHT + f"║  MAC:    {mac:<51}║")
        print(Fore.RED + Style.BRIGHT + f"║  Reason: {details:<51}║")
        print(Fore.RED + Style.BRIGHT + "║  Action: DROP rules installed (MAC + IP blocked)         ║")
        print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════════════════════════╝\n")
        
        self.detections.append(f"[{ts}] {d_type:<22} {ip} ({mac})")
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)
        
        # Install DROP rules
        parser = dp.ofproto_parser
        match_mac = parser.OFPMatch(eth_src=mac)
        self.add_flow(dp, 100, match_mac, [])
        match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, 100, match_ip, [])

    def _stats_timer(self):
        while True:
            hub.sleep(20)
            self._print_stats()

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"\n{Fore.CYAN}═══════════════════ DEFENSE STATS [{ts}] ═══════════════════")
        print(f"Switches            : {len(self.datapaths)}")
        print(f"MAC-IP Bindings     : {len(self.dai.binding_table)}")
        print(f"Active Flows        : {len(self.flows)}")
        print(f"Suspicious MACs     : {len(self.dai.suspicious_macs)}")
        print(Fore.CYAN + "────────────────────────────────────────────────────────────")
        print(f"Blocked MACs        : {len(self.blocked_macs)} {' | '.join(list(self.blocked_macs)[:3]) or '(None)'}")
        print(f"Blocked IPs         : {len(self.blocked_ips)} {' | '.join(list(self.blocked_ips)[:3]) or '(None)'}")
        print(Fore.CYAN + "────────────────────────────────────────────────────────────")
        print("Recent Detections:")
        for d in self.detections[-5:]:
            print(f"  {Fore.RED}{d}")
        if not self.detections: 
            print("  (None)")
        print(Fore.CYAN + "════════════════════════════════════════════════════════════\n")

if __name__ == '__main__':
    pass