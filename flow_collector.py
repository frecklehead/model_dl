# -*- coding: utf-8 -*-
"""
flow_collector.py
Advanced flow tracking and feature extraction for MITM detection.
"""

import time
import csv
import os
import numpy as np

# Column order MUST match the user's selected_features.pkl list + Label
SELECTED_FEATURES = [
    'src_port', 'dst_port', 'bidirectional_duration_ms', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'bidirectional_min_ps', 'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_max_ps',
    'src2dst_max_ps', 'dst2src_min_ps', 'dst2src_max_ps',
    'bidirectional_mean_piat_ms', 'bidirectional_max_piat_ms', 'src2dst_max_piat_ms',
    'application_name', 'requested_server_name', 'byte_asymmetry',
    'bytes_per_packet', 'src2dst_bpp', 'dst2src_bpp', 'duration_ratio', 'ps_variance_ratio',
    'Label'
]

class FlowRecord:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        now = time.time()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.first_seen = now
        self.last_seen = now
        self.s2d_first = now
        self.s2d_last = now
        self.d2s_first = None
        self.d2s_last = None
        
        self.bi_packets = 0
        self.bi_bytes = 0
        self.s2d_packets = 0
        self.s2d_bytes = 0
        self.d2s_packets = 0
        self.d2s_bytes = 0
        
        self.bi_sizes = []
        self.s2d_sizes = []
        self.d2s_sizes = []
        
        self.bi_piats = []
        self.s2d_piats = []
        self.d2s_piats = []
        
        self._last_bi_time = now
        self._last_s2d_time = now
        self._last_d2s_time = None

    def update(self, pkt_size, direction, now):
        # Bidirectional PIAT
        if self.bi_packets > 0:
            self.bi_piats.append((now - self._last_bi_time) * 1000)
        self._last_bi_time = now
        self.last_seen = now
        self.bi_packets += 1
        self.bi_bytes += pkt_size
        self.bi_sizes.append(pkt_size)

        if direction == 'src2dst':
            if self.s2d_packets > 0:
                self.s2d_piats.append((now - self._last_s2d_time) * 1000)
            self._last_s2d_time = now
            self.s2d_last = now
            self.s2d_packets += 1
            self.s2d_bytes += pkt_size
            self.s2d_sizes.append(pkt_size)
        else: # dst2src
            if self.d2s_first is None:
                self.d2s_first = now
                self._last_d2s_time = now
            else:
                self.d2s_piats.append((now - self._last_d2s_time) * 1000)
            self._last_d2s_time = now
            self.d2s_last = now
            self.d2s_packets += 1
            self.d2s_bytes += pkt_size
            self.d2s_sizes.append(pkt_size)

    @staticmethod
    def _stats(lst):
        if not lst: return 0.0, 0.0, 0.0, 0.0
        a = np.array(lst)
        return float(a.min()), float(a.mean()), float(a.std()), float(a.max())

    def to_dict(self, label=0):
        bi_dur = (self.last_seen - self.first_seen) * 1000
        s2d_dur = (self.s2d_last - self.s2d_first) * 1000
        d2s_dur = (self.d2s_last - self.d2s_first) * 1000 if self.d2s_first else 0.0
        
        bi_min_ps, bi_mean_ps, bi_std_ps, bi_max_ps = self._stats(self.bi_sizes)
        s2d_min_ps, s2d_mean_ps, s2d_std_ps, s2d_max_ps = self._stats(self.s2d_sizes)
        d2s_min_ps, d2s_mean_ps, d2s_std_ps, d2s_max_ps = self._stats(self.d2s_sizes)
        
        bi_min_pi, bi_mean_pi, bi_std_pi, bi_max_pi = self._stats(self.bi_piats)
        s2d_min_pi, s2d_mean_pi, s2d_std_pi, s2d_max_pi = self._stats(self.s2d_piats)
        d2s_min_pi, d2s_mean_pi, d2s_std_pi, d2s_max_pi = self._stats(self.d2s_piats)

        return {
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'bidirectional_duration_ms': bi_dur,
            'bidirectional_bytes': self.bi_bytes,
            'src2dst_duration_ms': s2d_dur,
            'src2dst_packets': self.s2d_packets,
            'src2dst_bytes': self.s2d_bytes,
            'bidirectional_min_ps': bi_min_ps,
            'bidirectional_mean_ps': bi_mean_ps,
            'bidirectional_stddev_ps': bi_std_ps,
            'bidirectional_max_ps': bi_max_ps,
            'src2dst_max_ps': s2d_max_ps,
            'dst2src_min_ps': d2s_min_ps,
            'dst2src_max_ps': d2s_max_ps,
            'bidirectional_mean_piat_ms': bi_mean_pi,
            'bidirectional_max_piat_ms': bi_max_pi,
            'src2dst_max_piat_ms': s2d_max_pi,
            'application_name': 0, # Placeholder
            'requested_server_name': 0, # Placeholder
            'byte_asymmetry': abs(self.s2d_bytes - self.d2s_bytes) / (self.bi_bytes + 1),
            'bytes_per_packet': self.bi_bytes / (self.bi_packets + 1),
            'src2dst_bpp': self.s2d_bytes / (self.s2d_packets + 1),
            'dst2src_bpp': self.d2s_bytes / (self.d2s_packets + 1),
            'duration_ratio': s2d_dur / (d2s_dur + 1),
            'ps_variance_ratio': bi_std_ps / (bi_mean_ps + 1),
            'Label': label
        }

class FlowCSVWriter:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.flows = {} # (c_src, c_dst, proto) -> FlowRecord
        
        if not os.path.exists(csv_path):
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=SELECTED_FEATURES)
                writer.writeheader()

    def _get_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        return tuple(sorted((a, b))) + (proto,)

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, proto, size):
        key = self._get_key(src_ip, dst_ip, src_port, dst_port, proto)
        now = time.time()
        
        if key not in self.flows:
            # Determine canonical src/dst
            a, b = (src_ip, src_port), (dst_ip, dst_port)
            if a < b: csrc, cdst = a, b
            else: csrc, cdst = b, a
            self.flows[key] = FlowRecord(csrc[0], cdst[0], csrc[1], cdst[1], proto)
        
        direction = 'src2dst' if (src_ip, src_port) == key[0] else 'dst2src'
        self.flows[key].update(size, direction, now)
        return self.flows[key]

    def write_flow(self, key, label=0):
        if key in self.flows:
            flow = self.flows.pop(key)
            row = flow.to_dict(label)
            with open(self.csv_path, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=SELECTED_FEATURES)
                writer.writerow(row)
