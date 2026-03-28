#!/usr/bin/env python3
"""
topology.py — MITM Detection Demo Topology
Creates the same network as run_demo.py but as a standalone Mininet topology.

Usage:
    sudo python3 topology.py

Requires Ryu to already be running:
    ryu-manager my_controller.py   (in a separate terminal)
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess, time, os, shutil

# ── Script paths ────────────────────────────────────────────────────────────
_HERE       = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(_HERE, 'scripts')

# ── Helpers ──────────────────────────────────────────────────────────────────
def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def wait_for_controller(timeout=30):
    print(f"\n[*] Waiting for Ryu controller on port 6633 (up to {timeout}s)...")
    for i in range(timeout):
        r = run("ovs-vsctl get controller s1 is_connected 2>/dev/null")
        if 'true' in r.stdout.lower():
            print(f"[+] Controller connected! ({i}s)")
            return True
        time.sleep(1)
        if i % 5 == 4:
            print(f"    ... {i+1}s elapsed")
    print("[-] Controller not connected. Is ryu-manager running?")
    return False

def wait_for_flows(timeout=15):
    print(f"[*] Waiting for Ryu to install flows (up to {timeout}s)...")
    for i in range(timeout):
        r = run("ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null")
        if r.stdout.count('cookie=') > 0:
            n = r.stdout.count('cookie=')
            print(f"[+] {n} flow(s) installed.")
            return True
        time.sleep(1)
    print("[!] No flows found after timeout.")
    return False

def deploy_scripts():
    print("\n[*] Deploying scripts to /tmp ...")
    scripts = [
        'attacker_mitm.py',
        'victim_traffic.py',
        'server_login.py',
        'ssl_strip.py',
        'session_hijack.py',
    ]
    for fname in scripts:
        src = os.path.join(SCRIPTS_DIR, fname)
        dst = f'/tmp/{fname}'
        if os.path.exists(src):
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            print(f"    [+] /tmp/{fname}")
        else:
            # Also check current directory
            alt = os.path.join(_HERE, fname)
            if os.path.exists(alt):
                shutil.copy2(alt, dst)
                os.chmod(dst, 0o755)
                print(f"    [+] /tmp/{fname}  (from project root)")
            else:
                print(f"    [-] NOT FOUND: {fname}")

def cleanup():
    print("[*] Cleaning up previous runs...")
    run("pkill -f attacker_mitm.py")
    run("pkill -f victim_traffic.py")
    run("pkill -f server_login.py")
    run("pkill -f ssl_strip.py")
    run("pkill -f session_hijack.py")
    run("ovs-ofctl -O OpenFlow13 del-flows s1 2>/dev/null")
    run("ovs-vsctl del-controller s1 2>/dev/null")

# ── Topology ──────────────────────────────────────────────────────────────────
def build_network():
    """
    Star topology: 1 switch, 5 hosts

    Hosts:
        victim   10.0.0.1   MAC 00:00:00:00:00:01   — legitimate user
        server   10.0.0.2   MAC 00:00:00:00:00:02   — bank web server
        attacker 10.0.0.100 MAC 00:00:00:00:00:03   — ARP MITM attacker
        device1  10.0.0.11  MAC 00:00:00:00:00:11   — SSL stripping device
        device2  10.0.0.12  MAC 00:00:00:00:00:12   — session hijacking device

    Switch:
        s1 — Open vSwitch, OpenFlow 1.3, RemoteController at 127.0.0.1:6633
    """
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    # Remote controller — Ryu must be running separately
    net.addController('c0', ip='127.0.0.1', port=6633)

    # Switch — OpenFlow 1.3
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Hosts with fixed IPs and MACs
    victim   = net.addHost('victim',   ip='10.0.0.1/24',   mac='00:00:00:00:00:01')
    server   = net.addHost('server',   ip='10.0.0.2/24',   mac='00:00:00:00:00:02')
    attacker = net.addHost('attacker', ip='10.0.0.100/24', mac='00:00:00:00:00:03')
    device1  = net.addHost('device1',  ip='10.0.0.11/24',  mac='00:00:00:00:00:11')
    device2  = net.addHost('device2',  ip='10.0.0.12/24',  mac='00:00:00:00:00:12')

    # All hosts connect to s1 (star topology)
    net.addLink(victim,   s1)   # victim-eth0   ↔ s1-eth1
    net.addLink(server,   s1)   # server-eth0   ↔ s1-eth2
    net.addLink(attacker, s1)   # attacker-eth0 ↔ s1-eth3
    net.addLink(device1,  s1)   # device1-eth0  ↔ s1-eth4
    net.addLink(device2,  s1)   # device2-eth0  ↔ s1-eth5

    return net

# ── Main ──────────────────────────────────────────────────────────────────────
def run_topology():
    setLogLevel('warning')   # suppress Mininet noise; keep our prints clean
    cleanup()

    print("\n" + "="*60)
    print("  MITM DETECTION DEMO — TOPOLOGY STARTING")
    print("="*60)
    print("\nTopology:")
    print("  victim   10.0.0.1   MAC 00:01")
    print("  server   10.0.0.2   MAC 00:02")
    print("  attacker 10.0.0.100 MAC 00:03")
    print("  device1  10.0.0.11  MAC 00:11")
    print("  device2  10.0.0.12  MAC 00:12")
    print("  switch   s1         OpenFlow 1.3 → Ryu @ 127.0.0.1:6633")
    print()

    net = build_network()
    net.start()

    # Give OVS a moment to register with Ryu
    run("ovs-vsctl set controller s1 max_backoff=1000")
    time.sleep(1)

    # Wait for Ryu to connect and install flows
    ctrl_ok = wait_for_controller(timeout=30)
    if ctrl_ok:
        wait_for_flows(timeout=15)
    else:
        print("\n[!] WARNING: No controller. Start ryu-manager in another terminal.")
        print("    Then type 'pingall' inside the Mininet CLI.\n")

    # Deploy attack scripts
    deploy_scripts()

    # ARP warm-up — populate controller's trusted ARP table
    print("\n[*] Warming ARP caches (pingall)...")
    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')

    pairs = [
        (victim,   '10.0.0.2'),
        (victim,   '10.0.0.100'),
        (server,   '10.0.0.1'),
        (server,   '10.0.0.100'),
        (attacker, '10.0.0.1'),
        (attacker, '10.0.0.2'),
    ]
    for host, dst in pairs:
        host.cmd(f'ping -c 1 -W 1 {dst} > /dev/null 2>&1')
    time.sleep(1)
    print("[+] ARP warm-up done. Controller has learned trusted IP→MAC bindings.")

    # Quick connectivity check
    r = victim.cmd('ping -c 1 -W 2 10.0.0.2')
    if '1 received' in r or '0% packet loss' in r:
        print("[+] victim → server: reachable ✓")
    else:
        print("[!] victim → server: UNREACHABLE — check Ryu is running")

    print("\n" + "="*60)
    print("  TOPOLOGY READY — Mininet CLI open")
    print("="*60)
    print()
    print("  Available hosts and their roles:")
    print("    victim    — runs victim_traffic.py (user browsing bank)")
    print("    server    — runs server_login.py   (bank web server)")
    print("    attacker  — runs attacker_mitm.py  (ARP poison + relay)")
    print("    device1   — runs ssl_strip.py      (SSL stripping)")
    print("    device2   — runs session_hijack.py (TCP session hijack)")
    print()
    print("  Scripts deployed to /tmp/ — use these commands in the CLI:")
    print()
    print("  1. server   python3 /tmp/server_login.py &")
    print("  2. victim   python3 /tmp/victim_traffic.py 10.0.0.2 &")
    print("  3. device1  python3 /tmp/ssl_strip.py 10.0.0.2 &")
    print("  4. device2  python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2 device2-eth0 &")
    print("  5. attacker python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0 &")
    print()
    print("  Verify detections:")
    print("  → Watch Terminal 1 (ryu-manager) for attack alerts")
    print("  → attacker cat /tmp/mitm_stolen.txt")
    print("  → (outside) ovs-ofctl -O OpenFlow13 dump-flows s1")
    print()

    CLI(net)
    net.stop()
    print("\n[*] Network stopped.")

if __name__ == '__main__':
    run_topology()