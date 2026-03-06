# -*- coding: utf-8 -*-
"""
my_controller.py
MITM Detection Ryu Controller with Live Dashboard
"""

import sys
import os
import time
import datetime
import threading
import numpy as np
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp, ether_types
from ryu.lib import hub

# Terminal Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# ML Libraries
try:
    import joblib
    import tensorflow as tf
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class MITMController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MITMController, self).__init__(*args, **kwargs)
        
        self.mac_to_port = {}
        self.arp_table = {}
        self.flow_stats = {}
        self.blocked_hosts = set() # Set of blocked (IP, MAC) tuples
        self.detections = [] # List of detection events for history
        
        # Load Model
        self.model = None
        self.scaler = None
        self.features_list = None
        self._load_model()
        
        # Start Dashboard Thread
        self.monitor_thread = hub.spawn(self._monitor)
        
        self._print_header()

    def _print_header(self):
        print(f"{BOLD}{CYAN}╔══════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║   MITM DETECTION CONTROLLER v1.0    ║{RESET}")
        print(f"{BOLD}{CYAN}║   Layer 1: ARP Rule-based           ║{RESET}")
        print(f"{BOLD}{CYAN}║   Layer 2: CNN+LSTM ML Model        ║{RESET}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════╝{RESET}")
        if ML_AVAILABLE and self.model:
            print(f"{GREEN}✅ ML Model Loaded Successfully{RESET}")
        else:
            print(f"{YELLOW}⚠️  ML Model NOT Loaded (Rule-based only){RESET}")

    def _load_model(self):
        if not ML_AVAILABLE:
            return

        model_path = "model/mitm_model.h5"
        scaler_path = "model/scaler.pkl"
        features_path = "model/selected_features.pkl"
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = tf.keras.models.load_model(model_path)
                self.scaler = joblib.load(scaler_path)
                if os.path.exists(features_path):
                    self.features_list = joblib.load(features_path)
            except Exception as e:
                print(f"{RED}❌ Error loading model: {e}{RESET}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
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
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # 1. LOGGING & DETECTION
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        
        # Check if source MAC is blocked
        if src in self.blocked_hosts:
            # Drop silently
            return

        # Handle ARP
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(datapath, in_port, pkt_arp, src, dst, ts)

        # Handle IP/TCP/UDP & ML
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            self._handle_ipv4(datapath, in_port, pkt, pkt_ipv4, src, dst, ts)

        # 2. FORWARDING LOGIC
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid PacketIn next time (unless we want to monitor stats)
        # Note: For this project, we might want to keep sending to controller to collect stats 
        # OR use OpenFlow stats requests. 
        # To keep it simple and responsive for the demo, we will install flows but rely on 
        # stats polling or just sample PacketIns. 
        # Actually, for the ML features requested (stats), we should rely on the packet_in 
        # loop for calculation IF the volume isn't massive, OR use the monitor thread 
        # to query stats.
        # Given "Flow Level Monitoring", let's aggregate here for simplicity on small Mininet networks.
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Verify if flow already exists? No, just add/overwrite.
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_arp(self, datapath, in_port, pkt_arp, src_mac, dst_mac, ts):
        op = "REQUEST" if pkt_arp.opcode == arp.ARP_REQUEST else "REPLY"
        src_ip = pkt_arp.src_ip
        dst_ip = pkt_arp.dst_ip

        print(f"[{ts}] [{YELLOW}ARP  {RESET}] {op:<7} {src_ip} ({src_mac}) → {dst_ip}")

        # ARP Spoofing Detection (Rule-based)
        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                # SPOOF DETECTED!
                # For this demo, we use RULE-BASED to show immediate detection, 
                # but NOT BLOCK yet so ML can also analyze the traffic later.
                # If we want immediate blocking, uncomment line 208 below
                self._trigger_detection(
                    "ARP SPOOFING", src_ip, src_mac, datapath, in_port,
                    f"Claimed IP {src_ip} but MAC {src_mac} != {known_mac}",
                    block=False # 🔥 Changed to False to let ML see the attack later
                )
                return 

        self.arp_table[src_ip] = src_mac

    def _handle_ipv4(self, datapath, in_port, pkt, pkt_ipv4, src_mac, dst_mac, ts):
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        
        # Parse Protocol
        protocol = pkt_ipv4.proto
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        log_type = "IP   "
        info = ""

        l4_src = 0
        l4_dst = 0

        if pkt_tcp:
            log_type = "TCP  "
            l4_src = pkt_tcp.src_port
            l4_dst = pkt_tcp.dst_port

            # Identify HTTP
            if l4_dst == 8080 or l4_src == 8080 or l4_dst == 80 or l4_src == 80:
                log_type = "HTTP "

            info = f"{src_ip}:{l4_src} → {dst_ip}:{l4_dst}"
        elif pkt_udp:
            log_type = "UDP  "
            l4_src = pkt_udp.src_port
            l4_dst = pkt_udp.dst_port
            info = f"{src_ip}:{l4_src} → {dst_ip}:{l4_dst}"
        elif pkt_icmp:
            log_type = "ICMP "
            info = f"{src_ip} → {dst_ip}"
        else:
            info = f"{src_ip} → {dst_ip}"

        # Compact Log
        # Log HTTP, ICMP, and 20% of other packets to show activity
        if log_type in ["HTTP ", "ICMP "] or np.random.rand() < 0.2:
            print(f"[{ts}] [{BLUE}{log_type}{RESET}] {info} | sw={datapath.id} port={in_port} | len={pkt_ipv4.total_length}")
        # UPDATE FLOW STATS for ML
        self._update_flow_stats(
            src_ip, dst_ip, src_mac, dst_mac, 
            protocol, l4_src, l4_dst, 
            pkt_ipv4.total_length, pkt_tcp, datapath
        )

    def _update_flow_stats(self, src_ip, dst_ip, src_mac, dst_mac, proto, l4_src, l4_dst, length, tcp_seg, datapath):
        # Key: tuple sorted to represent bidirectional flow
        if src_ip < dst_ip:
            key = (src_ip, dst_ip, proto, l4_src, l4_dst)
            forward = True
        else:
            key = (dst_ip, src_ip, proto, l4_dst, l4_src)
            forward = False
        
        now = time.time()
        
        if key not in self.flow_stats:
            self.flow_stats[key] = {
                'start_time': now,
                'last_time': now,
                'pkts_fwd': 0, 'bytes_fwd': 0,
                'pkts_bwd': 0, 'bytes_bwd': 0,
                'syn': 0, 'ack': 0, 'rst': 0, 'fin': 0,
                'piats': [] 
            }
        
        f = self.flow_stats[key]
        
        # PIAT
        piat = (now - f['last_time']) * 1000
        f['piats'].append(piat)
        f['last_time'] = now
        
        # Counts
        if forward:
            f['pkts_fwd'] += 1
            f['bytes_fwd'] += length
        else:
            f['pkts_bwd'] += 1
            f['bytes_bwd'] += length
            
        # TCP Flags
        if tcp_seg:
            # scapy/ryu flags logic might differ. Ryu uses integer.
            # FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10
            flg = tcp_seg.bits
            if flg & 0x02: f['syn'] += 1
            if flg & 0x10: f['ack'] += 1
            if flg & 0x04: f['rst'] += 1
            if flg & 0x01: f['fin'] += 1

        # Trigger ML every 20 packets total
        total_pkts = f['pkts_fwd'] + f['pkts_bwd']
        if total_pkts > 0 and total_pkts % 20 == 0:
            self._run_ml_check(key, f, src_ip, src_mac, datapath)

    def _run_ml_check(self, key, f, src_ip, src_mac, datapath):
        if not self.model:
            return

        # EXTRACT FEATURES
        # Matches logic in Task 2 - I
        total_pkts = f['pkts_fwd'] + f['pkts_bwd']
        total_bytes = f['bytes_fwd'] + f['bytes_bwd']
        duration = (f['last_time'] - f['start_time']) * 1000
        
        # Avoid div by zero
        safe_pkts = total_pkts if total_pkts > 0 else 1
        
        mean_ps = total_bytes / safe_pkts
        # Simple approximation for stddev without storing all packet sizes
        std_ps = 0 # In a real system, we'd track variance online. 
        
        mean_piat = np.mean(f['piats']) if f['piats'] else 0
        std_piat = np.std(f['piats']) if f['piats'] else 0
        
        # Build Vector
        # Ensure this order matches your training columns EXACTLY
        # For this demo, we assume the list provided in the prompt is the target order
        
        features = {
            'bidirectional_duration_ms': duration,
            'bidirectional_packets': total_pkts,
            'bidirectional_bytes': total_bytes,
            'src2dst_packets': f['pkts_fwd'],
            'src2dst_bytes': f['bytes_fwd'],
            'dst2src_packets': f['pkts_bwd'],
            'dst2src_bytes': f['bytes_bwd'],
            'bidirectional_mean_ps': mean_ps,
            'bidirectional_stddev_ps': std_ps, # Approx
            'bidirectional_mean_piat_ms': mean_piat,
            'bidirectional_stddev_piat_ms': std_piat,
            'bidirectional_syn_packets': f['syn'],
            'bidirectional_ack_packets': f['ack'],
            'bidirectional_rst_packets': f['rst'],
            'bidirectional_fin_packets': f['fin'],
            'packet_asymmetry': abs(f['pkts_fwd'] - f['pkts_bwd']) / safe_pkts,
            'byte_asymmetry': abs(f['bytes_fwd'] - f['bytes_bwd']) / (total_bytes + 1),
            'bytes_per_packet': mean_ps,
            'syn_ratio': f['syn'] / safe_pkts,
            'rst_ratio': f['rst'] / safe_pkts,
            'piat_variance_ratio': std_piat / (mean_piat + 1),
            'protocol': key[2],
            'src_port': key[3],
            'dst_port': key[4],
            'ps_variance_ratio': 0, # Approx
            'src2dst_duration_ms': duration, # Approx mapped to total
            'dst2src_duration_ms': duration, # Approx mapped to total
            'duration_ratio': 1.0
        }
        
        # If we have the exact feature list from the pickle, filter/order by it
        if self.features_list:
             vector = np.array([[features.get(feat, 0) for feat in self.features_list]])
        else:
             # Fallback: create array from values in arbitrary consistent order (Risky!)
             # For the demo, we'll assume the prompt list is the order
             vector = np.array([[v for k,v in features.items()]])

        # Scale
        if self.scaler:
            try:
                # Some scalers might complain about shape if feature count mismatches
                # We catch exception just in case
                vector = self.scaler.transform(vector)
            except:
                pass

        # Reshape for CNN (Samples, Features, 1)
        vector = vector.reshape(1, vector.shape[1], 1)
        
        # Predict
        score = self.model.predict(vector, verbose=0)[0][0]
        
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        if score > 0.7: # 🔥 Threshold updated from 0.8 to 0.7 to match training
             print(f"[{ts}] [{MAGENTA}ML   {RESET}] Flow: {key[0]}→{key[1]} | pkts={total_pkts} | score={score:.4f} | {RED}MITM 🚨{RESET}")
             self._trigger_detection("ML ANOMALY", src_ip, src_mac, datapath, 0, f"Score: {score:.4f}", block=True)
        else:
             print(f"[{ts}] [{MAGENTA}ML   {RESET}] Flow: {key[0]}→{key[1]} | pkts={total_pkts} | score={score:.4f} | {GREEN}NORMAL ✅{RESET}")

    def _trigger_detection(self, det_type, ip, mac, datapath, port, details, block=True):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        
        # Banner
        action_text = "BLOCKING MAC ADDRESS" if block else "DETECTION ONLY (ML WAITING)"
        print(f"\n{RED if block else YELLOW}╔══════════════════════════════════════════════╗{RESET}")
        print(f"{RED if block else YELLOW}║  🚨 MITM ATTACK DETECTED — {det_type:<14}║{RESET}")
        print(f"{RED if block else YELLOW}║  Time:      {ts:<33}║{RESET}")
        print(f"{RED if block else YELLOW}║  Attacker:  {mac:<33}║{RESET}")
        print(f"{RED if block else YELLOW}║  Claimed IP: {ip:<32}║{RESET}")
        print(f"{RED if block else YELLOW}║  ACTION:    {action_text:<33}║{RESET}")
        print(f"{RED if block else YELLOW}╚══════════════════════════════════════════════╝{RESET}\n")
        
        self.detections.append(f"[{ts}] {det_type} -> MAC: {mac}")
        
        if block:
            self.blocked_hosts.add(mac) # Store MAC only
            
            # Block MAC (This effectively stops the attacker)
            # We use a high priority to ensure this rule hits first
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=mac)
            self.add_flow(datapath, 100, match, []) # Drop
        
        # DO NOT block the 'ip' here, because 'ip' is the victim/server 
        # that the attacker is trying to impersonate!

    def _monitor(self):
        while True:
            hub.sleep(30)
            self._print_stats()

    def _print_stats(self):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"\n{BOLD}{CYAN}══════════ NETWORK STATS [{ts}] ══════════{RESET}")
        print(f" MACs learned       : {sum(len(v) for v in self.mac_to_port.values())}")
        print(f" ARP table entries  : {len(self.arp_table)}")
        print(f" Active flows       : {len(self.flow_stats)}")
        print(f"{CYAN}─────────────────────────────────────────────{RESET}")
        print(f" RECENT DETECTIONS:")
        if not self.detections:
            print(" (None)")
        else:
            for d in self.detections[-5:]:
                print(f" {RED}{d}{RESET}")
        print(f"{CYAN}─────────────────────────────────────────────{RESET}")
        print(f" BLOCKED HOSTS (MAC):")
        for mac in self.blocked_hosts:
            print(f" {RED}[{mac}]{RESET}")
        print(f"{CYAN}══════════════════════════════════════════════{RESET}\n")

if __name__ == '__main__':
    # This script is run by ryu-manager, so this block is usually not entered directly
    pass
