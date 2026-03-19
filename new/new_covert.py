#!/usr/bin/env python3
"""
covert_attack.py - Covert Flow-Pattern Anomaly Attack
Tests Layer 2 (Flow-Level Anomaly Detection) in enhanced controller.

This attack bypasses Layer 1 (DAI) by NOT sending ARP packets.
Instead, it generates suspicious flow patterns that mimic MITM relay behavior:
  - Packet/byte asymmetry (relay detection)
  - RST injection patterns (session hijacking)
  - Connection reset frequency

Usage:
  sudo python3 covert_attack.py \\
    --victim 10.0.2.1 \\
    --gateway 10.0.2.254 \\
    --duration 60 \\
    --interface h1-eth0 \\
    --attack_type relay

Attack Types:
  - relay: Generate asymmetric traffic (packet imbalance)
  - hijack: Inject RST packets to simulate session hijacking
  - ssl_strip: Send small packets on HTTPS port
  - flood: Generate high-volume relay-like traffic
"""

import argparse
import time
import sys
import random
from scapy.all import (
    IP, TCP, UDP, ICMP, send, Raw,
    get_if_hwaddr, RandIP, RandMAC,
    conf
)

# Suppress Scapy warnings
conf.verb = 0

class CovertAttackGenerator:
    def __init__(self, victim_ip, gateway_ip, iface, attack_type="relay"):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.attack_type = attack_type
        self.attacker_ip = self._get_interface_ip()
        self.packet_count = 0
    
    def _get_interface_ip(self):
        """Get source IP from interface"""
        try:
            from scapy.arch import get_if_addr
            return get_if_addr(self.iface)
        except:
            return "10.0.1.1"
    
    def _relay_attack(self, duration):
        """
        Generate asymmetric TCP traffic:
        - Send many packets from A→B
        - Send few packets from B→A
        Mimics relay where attacker forwards biased traffic
        """
        print("[*] Generating RELAY attack pattern")
        print("    Creating asymmetric traffic: A→B (100%), B→A (20%)")
        
        start = time.time()
        forward_pkts = 0
        backward_pkts = 0
        
        while time.time() - start < duration:
            # Forward direction: many packets
            for _ in range(10):
                pkt = IP(src=self.attacker_ip, dst=self.victim_ip) / \
                      TCP(sport=random.randint(10000, 65000), dport=80, flags="S")
                send(pkt, iface=self.iface, verbose=False)
                forward_pkts += 1
                self.packet_count += 1
            
            # Backward direction: few packets (simulating relay dropping)
            if random.random() < 0.2:
                pkt = IP(src=self.victim_ip, dst=self.attacker_ip) / \
                      TCP(sport=80, dport=random.randint(10000, 65000), flags="SA")
                send(pkt, iface=self.iface, verbose=False)
                backward_pkts += 1
                self.packet_count += 1
            
            elapsed = int(time.time() - start)
            asym_ratio = abs(forward_pkts - backward_pkts) / max(forward_pkts + backward_pkts, 1)
            print(f"[+] Fwd:{forward_pkts:3d} Bwd:{backward_pkts:3d} | "
                  f"Asymmetry:{asym_ratio:.1%} | Total:{self.packet_count:4d} | Elapsed:{elapsed:2d}s")
            
            time.sleep(0.5)
    
    def _hijack_attack(self, duration):
        """
        Generate RST injection pattern:
        - Send multiple legitimate TCP SYN packets
        - Follow with RST packets to tear down connection
        Mimics session hijacking
        """
        print("[*] Generating SESSION HIJACKING attack pattern")
        print("    Creating RST injection: SYN → establish → RST")
        
        start = time.time()
        syn_count = 0
        rst_count = 0
        ack_count = 0
        
        while time.time() - start < duration:
            # Send SYN (initiate connection)
            sport = random.randint(10000, 65000)
            pkt = IP(src=self.attacker_ip, dst=self.victim_ip) / \
                  TCP(sport=sport, dport=80, flags="S", seq=random.randint(1000, 100000))
            send(pkt, iface=self.iface, verbose=False)
            syn_count += 1
            self.packet_count += 1
            time.sleep(0.1)
            
            # Send ACK (as if connection established)
            pkt = IP(src=self.attacker_ip, dst=self.victim_ip) / \
                  TCP(sport=sport, dport=80, flags="A")
            send(pkt, iface=self.iface, verbose=False)
            ack_count += 1
            self.packet_count += 1
            time.sleep(0.1)
            
            # Send RST (tear down connection - hijack attempt)
            pkt = IP(src=self.attacker_ip, dst=self.victim_ip) / \
                  TCP(sport=sport, dport=80, flags="R")
            send(pkt, iface=self.iface, verbose=False)
            rst_count += 1
            self.packet_count += 1
            
            elapsed = int(time.time() - start)
            rst_ratio = rst_count / max(self.packet_count, 1)
            print(f"[+] SYN:{syn_count:3d} ACK:{ack_count:3d} RST:{rst_count:3d} | "
                  f"RST_ratio:{rst_ratio:.1%} | Total:{self.packet_count:4d} | Elapsed:{elapsed:2d}s")
            
            time.sleep(0.5)
    
    def _ssl_strip_attack(self, duration):
        """
        Generate SSL stripping pattern:
        - Send tiny packets on HTTPS port (443)
        - Mimics unencrypted HTTP relayed on HTTPS port
        """
        print("[*] Generating SSL STRIPPING attack pattern")
        print("    Creating small packets on port 443 (HTTPS)")
        
        start = time.time()
        packet_count = 0
        
        while time.time() - start < duration:
            # Send very small packets on HTTPS port
            for _ in range(5):
                pkt = IP(src=self.attacker_ip, dst=self.victim_ip) / \
                      TCP(sport=random.randint(10000, 65000), dport=443) / \
                      Raw(load=b"X" * random.randint(20, 50))  # Very small payload
                send(pkt, iface=self.iface, verbose=False)
                packet_count += 1
                self.packet_count += 1
            
            elapsed = int(time.time() - start)
            mean_payload = 35  # Average of 20-50 bytes
            print(f"[+] Packets sent: {self.packet_count:4d} | "
                  f"Avg payload: {mean_payload:3d} bytes | Total:{self.packet_count:4d} | Elapsed:{elapsed:2d}s")
            
            time.sleep(0.5)
    
    def _flood_attack(self, duration):
        """
        Generate high-volume relay flood:
        - Send many rapid packets with robotic timing
        - Mimics automated relay (not human traffic)
        """
        print("[*] Generating RELAY FLOOD attack pattern")
        print("    Creating high-volume automated relay traffic")
        
        start = time.time()
        
        while time.time() - start < duration:
            # Send rapid packets with consistent timing
            for _ in range(20):
                sport = random.randint(10000, 65000)
                pkt = IP(src=self.attacker_ip, dst=self.victim_ip) / \
                      TCP(sport=sport, dport=random.choice([80, 443, 8080]))
                send(pkt, iface=self.iface, verbose=False)
                self.packet_count += 1
            
            elapsed = int(time.time() - start)
            pps = self.packet_count / (elapsed + 1)
            print(f"[+] Total packets: {self.packet_count:4d} | "
                  f"Throughput: {pps:.1f} pkt/s | Elapsed:{elapsed:2d}s")
            
            time.sleep(0.2)  # Fast, robotic timing
    
    def run(self, duration):
        """Execute attack based on type"""
        attacks = {
            'relay': self._relay_attack,
            'hijack': self._hijack_attack,
            'ssl_strip': self._ssl_strip_attack,
            'flood': self._flood_attack
        }
        
        if self.attack_type not in attacks:
            print(f"[!] Unknown attack type: {self.attack_type}")
            print(f"    Available: {', '.join(attacks.keys())}")
            sys.exit(1)
        
        print(f"\n[*] Starting {self.attack_type.upper()} attack...")
        print("="*70)
        
        try:
            attacks[self.attack_type](duration)
        except KeyboardInterrupt:
            print("\n[*] Attack interrupted by user")
        finally:
            print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(
        description="Covert Flow-Pattern MITM Attack for Layer 2 Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  relay      - Asymmetric TCP traffic (packet imbalance)
  hijack     - RST injection pattern (session hijacking)
  ssl_strip  - Tiny packets on HTTPS port
  flood      - High-volume robotic relay traffic

Examples:
  # Test relay detection
  sudo python3 covert_attack.py \\
    --victim 10.0.2.1 \\
    --gateway 10.0.2.254 \\
    --duration 60 \\
    --interface h1-eth0 \\
    --attack_type relay

  # Test session hijacking detection
  sudo python3 covert_attack.py \\
    --victim 10.0.2.1 \\
    --gateway 10.0.2.254 \\
    --duration 60 \\
    --interface h1-eth0 \\
    --attack_type hijack
        """
    )
    parser.add_argument("--victim", required=True, help="Victim IP (e.g., 10.0.2.1)")
    parser.add_argument("--gateway", required=True, help="Gateway IP (e.g., 10.0.2.254)")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., h1-eth0)")
    parser.add_argument("--duration", type=int, required=True, help="Attack duration in seconds")
    parser.add_argument("--attack_type", choices=['relay', 'hijack', 'ssl_strip', 'flood'],
                       default='relay', help="Type of covert attack")
    
    args = parser.parse_args()
    
    print("[*] Covert Flow-Pattern Attack Initialization")
    print(f"    Victim:        {args.victim}")
    print(f"    Gateway:       {args.gateway}")
    print(f"    Interface:     {args.interface}")
    print(f"    Duration:      {args.duration}s")
    print(f"    Attack Type:   {args.attack_type.upper()}")
    print(f"\n[*] Note: This attack BYPASSES Layer 1 (DAI)")
    print("    It only generates suspicious FLOW PATTERNS")
    print("    Expected to trigger: Layer 2 (Flow Anomaly Detection)")
    
    attacker = CovertAttackGenerator(
        args.victim,
        args.gateway,
        args.interface,
        args.attack_type
    )
    
    attacker.run(args.duration)
    
    print(f"\n[*] Final Statistics:")
    print(f"    Total packets sent: {attacker.packet_count}")
    print(f"    Attack type:        {args.attack_type}")
    print("="*70)

if __name__ == "__main__":
    main()