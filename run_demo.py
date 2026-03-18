#!/usr/bin/env python3
"""
run_demo.py — Complete MITM Detection Demo
Usage: sudo python3 run_demo.py

CRITICAL FIX: Waits for Ryu controller to connect AND install flows
before any traffic is sent. Without this, OVS silently drops everything.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time, os, shutil, subprocess

# Scripts live in a 'scripts/' subfolder next to this file
_HERE        = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR  = os.path.join(_HERE, 'scripts')

# ── Topology ───────────────────────────────────────────
def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    net.addController('c0', ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    victim   = net.addHost('victim',   ip='10.0.0.1/24',   mac='00:00:00:00:00:01')
    server   = net.addHost('server',   ip='10.0.0.2/24',   mac='00:00:00:00:00:02')
    attacker = net.addHost('attacker', ip='10.0.0.100/24', mac='00:00:00:00:00:03')
    device1  = net.addHost('device1',  ip='10.0.0.11/24',  mac='00:00:00:00:00:11')
    device2  = net.addHost('device2',  ip='10.0.0.12/24',  mac='00:00:00:00:00:12')

    for h in [victim, server, attacker, device1, device2]:
        net.addLink(h, s1)
    return net

# ── Script deployment ──────────────────────────────────
def deploy_scripts():
    """Copy scripts/ → /tmp/ (all Mininet hosts share the root filesystem)."""
    print("\n📂 Deploying scripts to /tmp ...")
    for fname in ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py',
                  'ssl_strip.py', 'session_hijack.py']:
        src = os.path.join(SCRIPTS_DIR, fname)
        dst = f'/tmp/{fname}'
        if os.path.exists(src):
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            print(f"  ✅ /tmp/{fname}")
        else:
            print(f"  ❌ NOT FOUND: {src}")

# ── Controller readiness helpers ───────────────────────
def _ovs_get(field, target='s1'):
    """Run an ovs-vsctl get and return stdout."""
    r = subprocess.run(
        ['ovs-vsctl', 'get', 'controller', target, field],
        capture_output=True, text=True
    )
    return r.stdout.strip().lower()

def wait_for_controller(timeout=45):
    """
    Block until Ryu reports is_connected=true on s1.
    This is the #1 cause of victim timeouts: if OVS has no flows it
    drops every packet, including the ARP warm-up pings.
    """
    print(f"\n⏳ Waiting for Ryu controller (up to {timeout}s) …")
    for i in range(timeout):
        try:
            if 'true' in _ovs_get('is_connected'):
                print(f"  ✅ Ryu connected! ({i}s elapsed)")
                return True
        except Exception:
            pass
        time.sleep(1)
        if i % 10 == 9:
            print(f"  … {i+1}s elapsed, still waiting …")

    print("  ❌ Ryu did NOT connect within the timeout.")
    print("     Make sure you ran:  ryu-manager my_controller.py")
    return False

def wait_for_flows(timeout=20):
    """Block until Ryu has installed at least the table-miss flow."""
    print(f"⏳ Waiting for Ryu to push flows (up to {timeout}s) …")
    for i in range(timeout):
        # Must specify OpenFlow13 version for ovs-ofctl to see flows on an OF13 switch
        r = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                           capture_output=True, text=True)
        # Ryu usually installs flows with a cookie (e.g. cookie=0x0)
        n = r.stdout.count('cookie=')
        if n > 0:
            print(f"  ✅ {n} flow(s) installed by Ryu")
            return True
        
        # Diagnostic: show error if ovs-ofctl failed
        if r.returncode != 0 and i == timeout - 1:
            print(f"  ❌ ovs-ofctl failed (code {r.returncode}): {r.stderr.strip()}")
            
        time.sleep(1)
    
    print("  ⚠️  No flows after timeout — forwarding may fail")
    # Last resort: dump what we found
    last_check = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                                capture_output=True, text=True)
    if last_check.stdout.strip():
        print(f"  DEBUG: Current Table:\n{last_check.stdout.strip()}")
    return False

# ── Connectivity check ─────────────────────────────────
def check_ping(src_host, dst_ip, label, retries=3):
    for attempt in range(retries):
        r = src_host.cmd(f'ping -c 2 -W 2 {dst_ip}')
        if '1 received' in r or '2 received' in r:
            print(f"  ✅ {label}: reachable")
            return True
        time.sleep(2)
    print(f"  ❌ {label}: UNREACHABLE after {retries} tries")
    return False

def cleanup_orphans():
    """Kill any leftover background processes from previous runs."""
    print("🧹 Cleaning up leftover processes ...")
    subprocess.run(['pkill', '-f', 'attacker_mitm.py'], capture_output=True)
    subprocess.run(['pkill', '-f', 'victim_traffic.py'], capture_output=True)
    subprocess.run(['pkill', '-f', 'server_login.py'], capture_output=True)
    # Also clear any OVS flows that might be hanging
    subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', 's1'], capture_output=True)

# ── Main demo ──────────────────────────────────────────
def run_demo():
    cleanup_orphans()
    net = create_topology()
    net.start()

    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')
    device1  = net.get('device1')
    attacker_iface = 'attacker-eth0'

    deploy_scripts()

    print("\n" + "="*60)
    print("🚀 MITM DETECTION DEMO STARTED")
    print("="*60)

    # ── GATE: wait for Ryu before any traffic ─────────────
    ctrl_ok = wait_for_controller(timeout=45)
    if ctrl_ok:
        wait_for_flows(timeout=20)
    else:
        print("\n⚠️  Continuing without confirmed controller — pings will likely fail.")
        print("   Start Ryu now in another terminal, then type 'pingall' in the CLI.\n")

    # ── Phase 1: ARP warm-up ───────────────────────────────
    print("\n📡 Phase 1: Warming ARP caches …")
    # All 6 directions so every host knows every other host's MAC
    pairs = [
        (victim,   '10.0.0.2'),
        (victim,   '10.0.0.100'),
        (server,   '10.0.0.1'),
        (server,   '10.0.0.100'),
        (attacker, '10.0.0.1'),
        (attacker, '10.0.0.2'),
    ]
    for host, dst in pairs:
        host.cmd(f'ping -c 2 -W 2 {dst} > /dev/null 2>&1')
    time.sleep(2)

    print("Attacker ARP cache:")
    print(attacker.cmd('arp -n'))

    # Hard stop if basic connectivity is broken
    if not check_ping(victim, '10.0.0.2', 'victim → server'):
        print("\n  Dumping OVS flows for diagnosis:")
        print(os.popen('ovs-ofctl dump-flows s1 2>/dev/null').read()[:800])
        print("\n  Opening CLI — run 'pingall' and check Ryu terminal.")
        CLI(net)
        net.stop()
        return

    # ── Phase 2: Start login server ────────────────────────
    print("\n🏦 Phase 2: Starting login server on server:8080 …")
    server.cmd('fuser -k 8080/tcp 2>/dev/null; sleep 1')
    server.cmd('python3 /tmp/server_login.py > /tmp/server_output.txt 2>&1 &')
    time.sleep(3)

    test = victim.cmd('curl -s --connect-timeout 5 http://10.0.0.2:8080/')
    if 'SecureBank' in test or 'Login' in test:
        print("✅ Login server verified from victim")
    else:
        print(f"⚠️  Unexpected response: {test[:200]}")
        print(f"   server port 8080: {server.cmd('ss -tlnp | grep 8080').strip() or 'NOT LISTENING'}")
        print(f"   server processes: {server.cmd('pgrep -a python3').strip()}")

    # ── Phase 3: Normal baseline traffic ──────────────────
    print("\n✅ Phase 3: Normal traffic (establishing baseline) …")
    victim.cmd('curl -s http://10.0.0.2:8080/ > /dev/null &')
    victim.cmd('curl -s -X POST http://10.0.0.2:8080/login '
               '-d "username=alice&password=secret123" > /dev/null &')
    device1.cmd('ping -c 10 10.0.0.2 &')
    time.sleep(5)
    print("✅ Baseline done — Ryu should show NORMAL ML scores")

    # ── Phase 4: SSL Stripping (device1) ─────────────────
    print("\n🔐 Phase 4: SSL Stripping Attack (device1 → server:443) ...")
    device1.cmd('python3 /tmp/ssl_strip.py 10.0.0.2 > /tmp/ssl_strip_output.txt 2>&1 &')
    print("   device1 generating port-443 TCP flows (SSL stripping signature)...")
    time.sleep(8)  # Give ML time to accumulate 20+ packets
    print(f"   Log: {device1.cmd('tail -5 /tmp/ssl_strip_output.txt 2>/dev/null').strip()}")

    # ── Phase 5: Session Hijacking (device2) ──────────────
    print("\n🔒 Phase 5: Session Hijacking via RST Injection (device2) ...")
    device2  = net.get('device2')
    device2.cmd('python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2 device2-eth0 > /tmp/session_hijack_output.txt 2>&1 &')
    print("   device2 injecting ACK+RST packets into victim-server flow...")
    time.sleep(10)  # RST injection takes ~8s for 30 packets
    print(f"   Log: {device2.cmd('tail -5 /tmp/session_hijack_output.txt 2>/dev/null').strip()}")

    # ── Phase 6: ARP Poisoning MITM (attacker) ───────────
    print(f"\n🔴 Phase 6: ARP Poisoning MITM (interface={attacker_iface}) ...")    
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    attacker.cmd('iptables -F; iptables -t nat -F; iptables -P FORWARD ACCEPT')
    # Pass: victim_ip  server_ip  interface_name
    attacker.cmd(
        f'python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 {attacker_iface} '
        f'> /tmp/attacker_output.txt 2>&1 &'
    )
    time.sleep(5)

    # Confirm poison took effect
    victim_arp = victim.cmd('arp -n')
    print("Victim ARP (10.0.0.2 should now show MAC 00:00:00:00:00:03):")
    print(victim_arp)
    print("Attacker startup log:")
    print(attacker.cmd('head -30 /tmp/attacker_output.txt 2>/dev/null'))

    # ── Phase 5: Victim sends credentials ─────────────────
    print("\n💀 Phase 5: Victim sending credentials (being stolen) …")
    # victim_traffic.py accepts SERVER_IP as optional first arg
    victim.cmd('python3 /tmp/victim_traffic.py 10.0.0.2 > /tmp/victim_output.txt 2>&1 &')
    time.sleep(6)

    # ── Phase 6: Confirm theft ─────────────────────────────
    print("\n🔍 Phase 6: Checking stolen credentials …")
    stolen = attacker.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null || echo "(empty)"')
    if 'username' in stolen or 'password' in stolen:
        print(f"🚨 CREDENTIALS STOLEN:\n{stolen[:500]}")
    else:
        print(f"⏳ Nothing yet. Attacker log tail:\n"
              f"{attacker.cmd('tail -20 /tmp/attacker_output.txt 2>/dev/null')}")

    # ── Phase 7: Detection summary ─────────────────────────
    print("\n🛡️  Phase 7: Check Ryu terminal for:")
    print("     [RULE] ARP SPOOFING detected")
    print("     [ML]   MITM ANOMALY score > 0.7  →  attacker MAC blocked")

    print("\n" + "="*60)
    print("📊 DEMO COMPLETE — Interactive CLI open")
    print()
    print("  victim   arp -n                         → poisoned ARP table")
    print("  victim   cat /tmp/victim_output.txt     → victim log")
    print("  attacker cat /tmp/mitm_stolen.txt       → stolen credentials")
    print("  attacker cat /tmp/attacker_output.txt   → attacker debug log")
    print("  server   cat /tmp/server_log.txt        → server log")
    print()
    print("  ovs-ofctl dump-flows s1                 → current OVS flows")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()