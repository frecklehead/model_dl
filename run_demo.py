#!/usr/bin/env python3
"""
run_demo.py — Complete MITM Detection Demo
Usage: sudo python3 run_demo.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os
import shutil

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts')

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    net.addController('c0', ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    victim   = net.addHost('victim',   ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    server   = net.addHost('server',   ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    attacker = net.addHost('attacker', ip='10.0.0.100/24', mac='00:00:00:00:00:03')
    device1  = net.addHost('device1',  ip='10.0.0.11/24', mac='00:00:00:00:00:11')
    device2  = net.addHost('device2',  ip='10.0.0.12/24', mac='00:00:00:00:00:12')

    net.addLink(victim,   s1)
    net.addLink(server,   s1)
    net.addLink(attacker, s1)
    net.addLink(device1,  s1)
    net.addLink(device2,  s1)
    return net

def deploy_scripts(net):
    """Copy scripts into /tmp (Mininet hosts share root filesystem)."""
    print("\n📂 Deploying latest scripts to /tmp ...")
    files = ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py']
    for fname in files:
        src = os.path.join(SCRIPTS_DIR, fname)
        dst = f'/tmp/{fname}'
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except OSError:
                pass # Already removed or other error handled by copy2
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"  ✅ {dst}")
        else:
            print(f"  ❌ NOT FOUND: {src}  (expected alongside run_demo.py)")

def run_demo():
    net = create_topology()
    net.start()

    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')
    device1  = net.get('device1')

    # Deploy scripts BEFORE anything runs
    deploy_scripts(net)

    # Mininet interface name = <hostname>-eth0
    attacker_iface = 'attacker-eth0'

    print("\n" + "="*60)
    print("🚀 MITM DETECTION DEMO STARTED")
    print("="*60)

    # ── Phase 1: ARP warm-up (CRITICAL) ───────────────────
    print("\n📡 Phase 1: Warming ARP caches (attacker needs this to find MACs)...")
    time.sleep(3)

    victim.cmd('ping -c 3 -W 2 10.0.0.2   > /dev/null 2>&1')
    victim.cmd('ping -c 3 -W 2 10.0.0.100 > /dev/null 2>&1')
    server.cmd('ping -c 3 -W 2 10.0.0.1   > /dev/null 2>&1')
    server.cmd('ping -c 3 -W 2 10.0.0.100 > /dev/null 2>&1')
    attacker.cmd('ping -c 3 -W 2 10.0.0.1 > /dev/null 2>&1')
    attacker.cmd('ping -c 3 -W 2 10.0.0.2 > /dev/null 2>&1')
    time.sleep(2)

    print("Attacker ARP cache after warm-up:")
    print(attacker.cmd('arp -n'))

    result = victim.cmd('ping -c 2 -W 2 10.0.0.2')
    if '2 received' in result or '1 received' in result:
        print("✅ Victim ↔ Server connectivity: OK")
    else:
        print("⚠️  Connectivity issue — check Ryu controller logs")

    # ── Phase 2: Start server ──────────────────────────────
    print("\n🏦 Phase 2: Starting login server...")
    server.cmd('fuser -k 8080/tcp 2>/dev/null; sleep 1')
    server.cmd('python3 /tmp/server_login.py > /tmp/server_output.txt 2>&1 &')
    time.sleep(3)

    test = victim.cmd('curl -s --connect-timeout 3 http://10.0.0.2:8080/')
    if 'SecureBank' in test or 'Login' in test:
        print("✅ Login server verified reachable from victim")
    else:
        print(f"⚠️  Server check failed. Response: {test[:120]}")

    # ── Phase 3: Normal traffic ────────────────────────────
    print("\n✅ Phase 3: Normal traffic (no attack)...")
    victim.cmd('curl -s http://10.0.0.2:8080/ > /dev/null &')
    victim.cmd('curl -s -X POST http://10.0.0.2:8080/login '
               '-d "username=alice&password=secret123" > /dev/null &')
    device1.cmd('ping -c 10 10.0.0.2 &')
    time.sleep(5)
    print("✅ Normal traffic done")

    # ── Phase 4: Launch MITM attack ────────────────────────
    print(f"\n🔴 Phase 4: Launching MITM on interface {attacker_iface}...")
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    attacker.cmd('iptables -F; iptables -t nat -F; iptables -P FORWARD ACCEPT')

    # ✅ KEY FIX: 3rd argument = attacker-eth0
    attacker.cmd(
        f'python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 {attacker_iface} '
        f'> /tmp/attacker_output.txt 2>&1 &'
    )
    time.sleep(5)

    print("Victim ARP table (server IP should now map to attacker MAC):")
    print(victim.cmd('arp -n'))

    # ── Phase 5: Victim sends credentials ─────────────────
    print("\n💀 Phase 5: Victim sending credentials...")
    victim.cmd('python3 /tmp/victim_traffic.py 10.0.0.2 > /tmp/victim_output.txt 2>&1 &')
    time.sleep(6)

    # ── Phase 6: Check stolen credentials ─────────────────
    print("\n🔍 Phase 6: Stolen data check...")
    stolen = attacker.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null || echo "No stolen data yet"')
    if 'username' in stolen or 'password' in stolen:
        print("🚨 CREDENTIALS STOLEN:")
        print(stolen[:500])
    else:
        print("⏳ No creds yet. Attacker log tail:")
        print(attacker.cmd('tail -20 /tmp/attacker_output.txt 2>/dev/null'))

    print("\n🛡️  Phase 7: Check Ryu controller for detection messages")
    print("\n" + "="*60)
    print("📊 DEMO COMPLETE — Opening interactive CLI")
    print("   victim   arp -n                        → poisoned ARP table")
    print("   attacker cat /tmp/mitm_stolen.txt      → stolen credentials")
    print("   attacker cat /tmp/attacker_output.txt  → attacker debug log")
    print("   server   cat /tmp/server_log.txt       → server logs")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()