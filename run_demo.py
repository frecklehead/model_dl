#!/usr/bin/env python3
"""
run_demo.py — Complete MITM Detection Demo
Starts everything automatically in Mininet.

Usage: sudo python3 run_demo.py

What it does:
  1. Creates topology
  2. Starts Ryu controller (assumes already running)
  3. Starts server (login page)
  4. Starts victim (sends credentials)
  5. Starts attacker (MITM)
  6. Watches Ryu detect and block the attack
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    # Single Switch for 100% reliable demo connectivity
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # All hosts on the same switch
    victim   = net.addHost('victim',   ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    server   = net.addHost('server',   ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    attacker = net.addHost('attacker', ip='10.0.0.100/24', mac='00:00:00:00:00:03')
    
    device1  = net.addHost('device1',  ip='10.0.0.11/24', mac='00:00:00:00:00:11')
    device2  = net.addHost('device2',  ip='10.0.0.12/24', mac='00:00:00:00:00:12')

    # Links
    net.addLink(victim,   s1)
    net.addLink(server,   s1)
    net.addLink(attacker, s1)
    net.addLink(device1,  s1)
    net.addLink(device2,  s1)

    return net

def run_demo():
    net = create_topology()
    net.start()

    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')
    device1  = net.get('device1')

    print("\n" + "="*60)
    print("🚀 MITM DETECTION DEMO STARTED")
    print("="*60)

    # ── Phase 1: Test connectivity ─────────────────────────
    print("\n📡 Phase 1: Testing network connectivity...")
    time.sleep(2) # Wait for Ryu to learn ports
    print("Pinging all hosts to warm up the controller...")
    net.pingAll()
    
    result = victim.cmd('ping -c 2 10.0.0.2')
    if "2 received" in result:
        print("✅ Victim can reach Server — network OK")
    else:
        print("⚠️  Connectivity issue — check Ryu controller logs")

    # ── Phase 2: Start server (login page) ────────────────
    print("\n🏦 Phase 2: Starting login server...")
    server.cmd('python3 /tmp/server_login.py &')
    time.sleep(2)
    print("✅ Login server running on 10.0.0.2:8080")

    # ── Phase 3: Generate normal traffic ──────────────────
    print("\n✅ Phase 3: Normal traffic (no attack)...")
    victim.cmd('curl -s http://10.0.0.2:8080/ > /dev/null &')
    victim.cmd('curl -s -X POST http://10.0.0.2:8080/login -d "username=alice&password=secret123" &')
    device1.cmd('ping -c 10 10.0.0.2 &')
    time.sleep(5)
    print("✅ Normal traffic generated — Ryu should show 'Normal' scores")

    # ── Phase 4: Launch MITM attack ────────────────────────
    print("\n🔴 Phase 4: Launching REAL MITM Attack...")
    print("   Step 1: Enabling IP forwarding on attacker...")
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1')

    print("   Step 2: ARP poisoning victim and server...")
    attacker.cmd('python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 &')
    time.sleep(3)
    print("✅ Attack launched! Traffic now flows through attacker")

    # ── Phase 5: Victim sends credentials (gets stolen!) ──
    print("\n💀 Phase 5: Victim sending credentials (being stolen!)...")
    victim.cmd('python3 /tmp/victim_traffic.py 10.0.0.2 &')
    time.sleep(5)

    # ── Phase 6: Check stolen credentials ─────────────────
    print("\n🔍 Phase 6: Checking attacker's stolen data...")
    stolen = attacker.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null || echo "No file yet"')
    if "username" in stolen or "password" in stolen:
        print("🚨 CREDENTIALS STOLEN BY ATTACKER:")
        print(stolen[:300])
    else:
        print("⏳ Attack in progress... check attacker terminal")

    # ── Phase 7: Verify detection ─────────────────────────
    print("\n🛡️  Phase 7: Verifying detection...")
    print("   → Check Ryu controller terminal for:")
    print("     🚨 [RULE] ARP SPOOF DETECTED!")
    print("     🚨 [ML]   MITM DETECTED!")
    print("     🔒 Blocked MAC/IP of attacker")

    print("\n" + "="*60)
    print("📊 DEMO COMPLETE — Opening interactive CLI")
    print("   Useful CLI commands:")
    print("   victim arp -n          → see poisoned ARP table")
    print("   attacker cat /tmp/mitm_stolen.txt  → stolen creds")
    print("   server  cat /tmp/server_log.txt    → server logs")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()
