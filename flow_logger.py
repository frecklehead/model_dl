"""
Flow Logger - Full Feature Collection
=======================================
Collects all 60 features matching the Kaggle dataset schema.
Reads /tmp/mitm_label for labeling (0=normal, 1=attack).

Use this for BOTH normal and attack collection:
  - For normal data:  make sure /tmp/mitm_label contains 0
  - For attack data:  run alongside topo_attack.py which sets the label

Run:
  ryu-manager flow_logger_full.py

Output: full_collection.csv
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
from ryu.lib import hub

import csv
import os
import time
import threading
import collections
import numpy as np

OUTPUT_FILE    = 'full_collection.csv'
LABEL_FILE     = '/tmp/mitm_label'
FLUSH_INTERVAL = 10
FLOW_TIMEOUT   = 60

FIELDNAMES = [
    'src_port', 'dst_port', 'protocol', 'ip_version',
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
    'bidirectional_min_ps', 'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_max_ps',
    'src2dst_min_ps', 'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps',
    'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps', 'dst2src_max_ps',
    'bidirectional_min_piat_ms', 'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms', 'bidirectional_max_piat_ms',
    'src2dst_min_piat_ms', 'src2dst_mean_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms',
    'dst2src_min_piat_ms', 'dst2src_mean_piat_ms', 'dst2src_stddev_piat_ms', 'dst2src_max_piat_ms',
    'bidirectional_syn_packets', 'bidirectional_cwr_packets', 'bidirectional_ece_packets', 'bidirectional_urg_packets',
    'bidirectional_ack_packets', 'bidirectional_psh_packets', 'bidirectional_rst_packets', 'bidirectional_fin_packets',
    'src2dst_syn_packets', 'src2dst_cwr_packets', 'src2dst_ece_packets', 'src2dst_urg_packets',
    'src2dst_ack_packets', 'src2dst_psh_packets', 'src2dst_rst_packets', 'src2dst_fin_packets',
    'dst2src_syn_packets', 'dst2src_cwr_packets', 'dst2src_ece_packets', 'dst2src_urg_packets',
    'dst2src_ack_packets', 'dst2src_psh_packets', 'dst2src_rst_packets', 'dst2src_fin_packets',
    'label',
]


def read_label():
    try:
        with open(LABEL_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def arr_stats(arr):
    """Return min, mean, std, max. All 0 if empty."""
    if not arr:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(arr, dtype=float)
    return float(a.min()), float(a.mean()), float(a.std()), float(a.max())


class FlowRecord:
    """
    Tracks full bidirectional flow stats matching Kaggle schema.
    canonical key ensures both directions share one record.
    """

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_ms    = time.time() * 1000
        self.last_ms     = self.start_ms
        self.last_s2d_ms = None
        self.last_d2s_ms = None

        # Packet sizes
        self.s2d_sizes   = []
        self.d2s_sizes   = []

        # Inter-arrival times (ms)
        self.bidir_piats = []
        self.s2d_piats   = []
        self.d2s_piats   = []

        # Byte counts
        self.s2d_bytes = 0
        self.d2s_bytes = 0

        # TCP flags — Ryu: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32 ECE=64 CWR=128
        self.s2d_syn = self.s2d_cwr = self.s2d_ece = self.s2d_urg = 0
        self.s2d_ack = self.s2d_psh = self.s2d_rst = self.s2d_fin = 0
        self.d2s_syn = self.d2s_cwr = self.d2s_ece = self.d2s_urg = 0
        self.d2s_ack = self.d2s_psh = self.d2s_rst = self.d2s_fin = 0

    def update(self, pkt_size, direction, flags=0):
        now_ms = time.time() * 1000

        # Bidirectional inter-arrival time
        self.bidir_piats.append(now_ms - self.last_ms)
        self.last_ms = now_ms

        if direction == 's2d':
            self.s2d_sizes.append(pkt_size)
            self.s2d_bytes += pkt_size
            if self.last_s2d_ms is not None:
                self.s2d_piats.append(now_ms - self.last_s2d_ms)
            self.last_s2d_ms = now_ms
            if flags & 0x02: self.s2d_syn += 1
            if flags & 0x80: self.s2d_cwr += 1
            if flags & 0x40: self.s2d_ece += 1
            if flags & 0x20: self.s2d_urg += 1
            if flags & 0x10: self.s2d_ack += 1
            if flags & 0x08: self.s2d_psh += 1
            if flags & 0x04: self.s2d_rst += 1
            if flags & 0x01: self.s2d_fin += 1
        else:
            self.d2s_sizes.append(pkt_size)
            self.d2s_bytes += pkt_size
            if self.last_d2s_ms is not None:
                self.d2s_piats.append(now_ms - self.last_d2s_ms)
            self.last_d2s_ms = now_ms
            if flags & 0x02: self.d2s_syn += 1
            if flags & 0x80: self.d2s_cwr += 1
            if flags & 0x40: self.d2s_ece += 1
            if flags & 0x20: self.d2s_urg += 1
            if flags & 0x10: self.d2s_ack += 1
            if flags & 0x08: self.d2s_psh += 1
            if flags & 0x04: self.d2s_rst += 1
            if flags & 0x01: self.d2s_fin += 1

    def to_row(self, label):
        now_ms    = time.time() * 1000
        bidir_ms  = now_ms - self.start_ms
        s2d_pkts  = len(self.s2d_sizes)
        d2s_pkts  = len(self.d2s_sizes)
        all_sizes = self.s2d_sizes + self.d2s_sizes
        s2d_dur   = (self.last_s2d_ms - self.start_ms) if self.last_s2d_ms else 0
        d2s_dur   = (self.last_d2s_ms - self.start_ms) if self.last_d2s_ms else 0

        bi_min_ps,  bi_mean_ps,  bi_std_ps,  bi_max_ps  = arr_stats(all_sizes)
        s2d_min_ps, s2d_mean_ps, s2d_std_ps, s2d_max_ps = arr_stats(self.s2d_sizes)
        d2s_min_ps, d2s_mean_ps, d2s_std_ps, d2s_max_ps = arr_stats(self.d2s_sizes)
        bi_min_pi,  bi_mean_pi,  bi_std_pi,  bi_max_pi  = arr_stats(self.bidir_piats)
        s2d_min_pi, s2d_mean_pi, s2d_std_pi, s2d_max_pi = arr_stats(self.s2d_piats)
        d2s_min_pi, d2s_mean_pi, d2s_std_pi, d2s_max_pi = arr_stats(self.d2s_piats)

        return {
            'src_port':                     self.src_port,
            'dst_port':                     self.dst_port,
            'protocol':                     self.protocol,
            'ip_version':                   4,
            'bidirectional_duration_ms':    round(bidir_ms, 3),
            'bidirectional_packets':        s2d_pkts + d2s_pkts,
            'bidirectional_bytes':          self.s2d_bytes + self.d2s_bytes,
            'src2dst_duration_ms':          round(s2d_dur, 3),
            'src2dst_packets':              s2d_pkts,
            'src2dst_bytes':                self.s2d_bytes,
            'dst2src_duration_ms':          round(d2s_dur, 3),
            'dst2src_packets':              d2s_pkts,
            'dst2src_bytes':                self.d2s_bytes,
            'bidirectional_min_ps':         bi_min_ps,
            'bidirectional_mean_ps':        round(bi_mean_ps, 4),
            'bidirectional_stddev_ps':      round(bi_std_ps, 4),
            'bidirectional_max_ps':         bi_max_ps,
            'src2dst_min_ps':               s2d_min_ps,
            'src2dst_mean_ps':              round(s2d_mean_ps, 4),
            'src2dst_stddev_ps':            round(s2d_std_ps, 4),
            'src2dst_max_ps':               s2d_max_ps,
            'dst2src_min_ps':               d2s_min_ps,
            'dst2src_mean_ps':              round(d2s_mean_ps, 4),
            'dst2src_stddev_ps':            round(d2s_std_ps, 4),
            'dst2src_max_ps':               d2s_max_ps,
            'bidirectional_min_piat_ms':    round(bi_min_pi, 3),
            'bidirectional_mean_piat_ms':   round(bi_mean_pi, 3),
            'bidirectional_stddev_piat_ms': round(bi_std_pi, 3),
            'bidirectional_max_piat_ms':    round(bi_max_pi, 3),
            'src2dst_min_piat_ms':          round(s2d_min_pi, 3),
            'src2dst_mean_piat_ms':         round(s2d_mean_pi, 3),
            'src2dst_stddev_piat_ms':       round(s2d_std_pi, 3),
            'src2dst_max_piat_ms':          round(s2d_max_pi, 3),
            'dst2src_min_piat_ms':          round(d2s_min_pi, 3),
            'dst2src_mean_piat_ms':         round(d2s_mean_pi, 3),
            'dst2src_stddev_piat_ms':       round(d2s_std_pi, 3),
            'dst2src_max_piat_ms':           round(d2s_max_pi, 3),
            'bidirectional_syn_packets':    self.s2d_syn + self.d2s_syn,
            'bidirectional_cwr_packets':    self.s2d_cwr + self.d2s_cwr,
            'bidirectional_ece_packets':    self.s2d_ece + self.d2s_ece,
            'bidirectional_urg_packets':    self.s2d_urg + self.d2s_urg,
            'bidirectional_ack_packets':    self.s2d_ack + self.d2s_ack,
            'bidirectional_psh_packets':    self.s2d_psh + self.d2s_psh,
            'bidirectional_rst_packets':    self.s2d_rst + self.d2s_rst,
            'bidirectional_fin_packets':    self.s2d_fin + self.d2s_fin,
            'src2dst_syn_packets':          self.s2d_syn,
            'src2dst_cwr_packets':          self.s2d_cwr,
            'src2dst_ece_packets':          self.s2d_ece,
            'src2dst_urg_packets':          self.s2d_urg,
            'src2dst_ack_packets':          self.s2d_ack,
            'src2dst_psh_packets':          self.s2d_psh,
            'src2dst_rst_packets':          self.s2d_rst,
            'src2dst_fin_packets':          self.s2d_fin,
            'dst2src_syn_packets':          self.d2s_syn,
            'dst2src_cwr_packets':          self.d2s_cwr,
            'dst2src_ece_packets':          self.d2s_ece,
            'dst2src_urg_packets':          self.d2s_urg,
            'dst2src_ack_packets':          self.d2s_ack,
            'dst2src_psh_packets':          self.d2s_psh,
            'dst2src_rst_packets':          self.d2s_rst,
            'dst2src_fin_packets':          self.d2s_fin,
            'label':                        label,
        }

    @property
    def last_seen(self):
        return self.last_ms / 1000


class FlowLoggerFull(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.flows       = {}
        self.flows_lock  = threading.Lock()
        self.last_flush  = time.time()
        self.label_counts = {0: 0, 1: 0}

        self._setup_csv()
        hub.spawn(self._flush_loop)

        # Ensure label file starts at 0
        try:
            with open(LABEL_FILE, 'w') as f:
                f.write('0')
        except Exception:
            pass

    def _setup_csv(self):
        exists = os.path.exists(OUTPUT_FILE)
        self.csv_file   = open(OUTPUT_FILE, 'a', newline='')
        self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=FIELDNAMES)
        if not exists:
            self.csv_writer.writeheader()
            self.csv_file.flush()
        self.logger.info(f'[logger] Writing to {OUTPUT_FILE}')

    def _flush_loop(self):
        while True:
            hub.sleep(FLUSH_INTERVAL)
            self._flush()

    def _flush(self):
        now           = time.time()
        current_label = read_label()
        self.last_flush = now

        with self.flows_lock:
            active  = {k: v for k, v in self.flows.items()
                       if now - v.last_seen < FLOW_TIMEOUT}
            expired = {k: v for k, v in self.flows.items()
                       if now - v.last_seen >= FLOW_TIMEOUT}
            self.flows = active

        to_write = list(active.values()) + list(expired.values())
        if not to_write:
            status = 'ATTACK' if current_label == 1 else 'normal'
            self.logger.info(f'[flush] No flows | label={current_label} ({status})')
            return

        for rec in to_write:
            self.csv_writer.writerow(rec.to_row(current_label))
            self.label_counts[current_label] = \
                self.label_counts.get(current_label, 0) + 1

        self.csv_file.flush()
        status = '!! ATTACK !!' if current_label == 1 else 'normal'
        self.logger.info(
            f'[flush] {len(to_write)} rows | label={current_label} ({status}) | '
            f'normal={self.label_counts.get(0,0)} '
            f'attack={self.label_counts.get(1,0)}'
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        self.mac_to_port.setdefault(dp.id, {})
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_ADD,
            priority=0, match=match, instructions=inst
        ))
        self.logger.info(f'[switch] Connected: dpid={dp.id}')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser
        dpid    = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofp.OFPP_FLOOD)

        # Skip non-IPv4
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            self._forward(dp, ofp, parser, msg, in_port, out_port)
            return

        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)
        src_ip   = ip_pkt.src
        dst_ip   = ip_pkt.dst
        proto    = ip_pkt.proto
        src_port = (tcp_pkt.src_port if tcp_pkt else
                    udp_pkt.src_port if udp_pkt else 0)
        dst_port = (tcp_pkt.dst_port if tcp_pkt else
                    udp_pkt.dst_port if udp_pkt else 0)
        flags    = tcp_pkt.bits if tcp_pkt else 0
        pkt_size = ip_pkt.total_length

        # Canonical key — bidirectional flows share one record
        canonical  = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        direction  = 's2d' if (src_ip, src_port) == canonical[0] else 'd2s'
        canon_src  = canonical[0]
        canon_dst  = canonical[1]

        with self.flows_lock:
            if canonical not in self.flows:
                self.flows[canonical] = FlowRecord(
                    canon_src[0], canon_dst[0],
                    canon_src[1], canon_dst[1],
                    proto
                )
            self.flows[canonical].update(pkt_size, direction, flags)

        # Install specific flow rule to reduce packet-ins
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_type=0x0800,
                eth_src=src_mac, eth_dst=dst_mac,
                ipv4_src=src_ip, ipv4_dst=dst_ip,
            )
            actions_fwd = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_fwd)]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=1,
                idle_timeout=30, hard_timeout=120,
                match=match, instructions=inst,
            ))

        self._forward(dp, ofp, parser, msg, in_port, out_port)

    def _forward(self, dp, ofp, parser, msg, in_port, out_port):
        actions = [parser.OFPActionOutput(out_port)]
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        ))