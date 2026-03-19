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

# Features requested by user (25 features)
FEATURES = [
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_packets', 'src2dst_bytes', 'dst2src_packets', 'dst2src_bytes',
    'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_mean_piat_ms',
    'bidirectional_stddev_piat_ms', 'bidirectional_syn_packets', 'bidirectional_ack_packets',
    'bidirectional_rst_packets', 'bidirectional_fin_packets', 'packet_asymmetry',
    'byte_asymmetry', 'bytes_per_packet', 'syn_ratio', 'rst_ratio',
    'piat_variance_ratio', 'protocol', 'src_port', 'dst_port', 'ps_variance_ratio'
]

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
        
        self.last_score = 0.0
        self.is_mitm = False

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

    def get_features(self):
        duration = (self.last_time - self.start_time) * 1000
        total_pkts = self.s2d_packets + self.d2s_packets
        total_bytes = self.s2d_bytes + self.d2s_bytes
        
        mean_ps = np.mean(self.packet_sizes) if self.packet_sizes else 0
        std_ps = np.std(self.packet_sizes) if self.packet_sizes else 0
        mean_piat = np.mean(self.piats) if self.piats else 0
        std_piat = np.std(self.piats) if self.piats else 0
        
        safe_pkts = total_pkts if total_pkts > 0 else 1
        
        return {
            'bidirectional_duration_ms': duration,
            'bidirectional_packets': total_pkts,
            'bidirectional_bytes': total_bytes,
            'src2dst_packets': self.s2d_packets,
            'src2dst_bytes': self.s2d_bytes,
            'dst2src_packets': self.d2s_packets,
            'dst2src_bytes': self.d2s_bytes,
            'bidirectional_mean_ps': mean_ps,
            'bidirectional_stddev_ps': std_ps,
            'bidirectional_mean_piat_ms': mean_piat,
            'bidirectional_stddev_piat_ms': std_piat,
            'bidirectional_syn_packets': self.syn_count,
            'bidirectional_ack_packets': self.ack_count,
            'bidirectional_rst_packets': self.rst_count,
            'bidirectional_fin_packets': self.fin_count,
            'packet_asymmetry': abs(self.s2d_packets - self.d2s_packets) / safe_pkts,
            'byte_asymmetry': abs(self.s2d_bytes - self.d2s_bytes) / (total_bytes + 1),
            'bytes_per_packet': total_bytes / safe_pkts,
            'syn_ratio': self.syn_count / safe_pkts,
            'rst_ratio': self.rst_count / safe_pkts,
            'piat_variance_ratio': (std_piat**2) / (mean_piat + 1),
            'protocol': self.protocol,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'ps_variance_ratio': (std_ps**2) / (mean_ps + 1)
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
        
        # Load Model
        self.model = None
        self.scaler = None
        self._load_model()
        
        # Print Header
        self._print_header()
        
        # Start Stats Timer
        self.stats_thread = hub.spawn(self._stats_timer)

    def _load_model(self):
        m_path = "random_forest_kaggle.pkl"
        s_path = "scaler_kaggle.pkl"
        if ML_AVAILABLE and os.path.exists(m_path):
            try:
                self.model = tf.keras.models.load_model(m_path)
                if os.path.exists(s_path):
                    self.scaler = joblib.load(s_path)
                self.logger.info("CNN+LSTM Model loaded successfully.")
            except Exception as e:
                self.logger.error(f"Error loading model: {e}")

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
        
        # Blocked check
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
        
        # Layer 1 Detection (ARP Spoofing)
        if pkt_arp.src_ip in self.arp_table:
            if self.arp_table[pkt_arp.src_ip] != eth.src:
                self._trigger_detection("ARP SPOOF", pkt_arp.src_ip, eth.src, datapath, in_port, "Impersonating known IP")
        else:
            self.arp_table[pkt_arp.src_ip] = eth.src

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
            type_str = "TCP  "
            if dst_port == 8080 or src_port == 8080:
                type_str = "HTTP "
                # Very basic HTTP detection from payload if possible
                payload = str(pkt.protocols[-1])
                if "GET" in payload: info = "| GET /"
                elif "POST" in payload: info = "| POST /login " + (Fore.RED + "⚠️" if "password" in payload.lower() else "")
            
            log_msg = f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip}:{src_port} → {dst_ip}:{dst_port} {info}"
        elif pkt_udp:
            src_port, dst_port = pkt_udp.src_port, pkt_udp.dst_port
            type_str = "UDP  "
            log_msg = f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        else:
            log_msg = f"[{ts}] [{Fore.BLUE}{type_str}{Style.RESET_ALL}] {src_ip} → {dst_ip} | pkts=1 bytes={pkt_ipv4.total_length}"

        print(log_msg)

        # Track Flow
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        if key not in self.flows:
            self.flows[key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, proto)
        
        dir = 's2d' if (src_ip, src_port) == key[0] else 'd2s'
        self.flows[key].update(pkt_ipv4.total_length, dir, flags)
        
        # ML Analysis every 20 packets
        total_p = self.flows[key].s2d_packets + self.flows[key].d2s_packets
        if total_p % 20 == 0:
            self._run_ml(key, ts, datapath, eth.src)

    def _run_ml(self, key, ts, datapath, src_mac):
        if not self.model: return
        flow = self.flows[key]
        feat_dict = flow.get_features()
        
        # Build vector
        vector = np.array([[feat_dict[f] for f in FEATURES]])
        if self.scaler: vector = self.scaler.transform(vector)
        
        # Reshape for CNN (TimeSteps=1 for live)
        vector = vector.reshape(1, vector.shape[1], 1)
        
        score = self.model.predict(vector, verbose=0)[0][0]
        flow.last_score = score
        
        status = f"{Fore.RED}MITM 🚨" if score > 0.5 else f"{Fore.GREEN}NORMAL ✅"
        print(f"[{ts}] [{Fore.MAGENTA}ML   {Style.RESET_ALL}] Flow: {flow.src_ip}→{flow.dst_ip} | pkts={flow.s2d_packets+flow.d2s_packets} | score={score:.4f} | {status}")
        
        if score > 0.8:
            flow.is_mitm = True
            self._trigger_detection("ML DETECT", flow.src_ip, src_mac, datapath, 0, f"Score: {score:.4f}")

    def _trigger_detection(self, d_type, ip, mac, dp, port, details):
        if mac in self.blocked_macs: return
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        
        print(Fore.RED + Style.BRIGHT + "\n╔══════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + f"║  🚨 MITM ATTACK DETECTED — {d_type:<18}║")
        print(Fore.RED + Style.BRIGHT + f"║  Time:      {ts:<33}║")
        print(Fore.RED + Style.BRIGHT + f"║  Attacker:  {ip:<10} ({mac})  ║")
        print(Fore.RED + Style.BRIGHT + "║  Switch:    s%d  Port: %-23d║" % (dp.id, port))
        print(Fore.RED + Style.BRIGHT + "║  ACTION:    MAC+IP blocked — DROP rule installed║")
        print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════════════╝\n")
        
        self.detections.append(f"[{ts}] {d_type}  {ip} blocked")
        self.blocked_macs.add(mac)
        self.blocked_ips.add(ip)
        
        # Install Block Rule
        parser = dp.ofproto_parser
        match_mac = parser.OFPMatch(eth_src=mac)
        self.add_flow(dp, 100, match_mac, []) # Drop
        match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, 100, match_ip, []) # Drop

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
