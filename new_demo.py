#!/usr/bin/env python3
"""
run_demo.py — Complete MITM Detection Demo
Usage: sudo python3 run_demo.py

Attack sequence:
  Phase 1 — ARP warm-up (all hosts learn each other's MACs)
  Phase 2 — Login server starts on server:8080
  Phase 3 — Normal baseline traffic (establishes ML baseline)
  Phase 4 — SSL Stripping attack from device1 → server:443
  Phase 5 — Session Hijacking via RST injection from device2
  Phase 6 — ARP Poisoning MITM from attacker (attacker_mitm.py)
             └── Internal modules: ARP poison, transparent L2 relay,
                 seq-tracking session hijack, real SSL strip proxy,
                 query-triggered DNS spoof, credential interception
             └── Waits 5s for ARP cache before starting relay modules
  Phase 7 — Victim sends credentials (attacker should already be poisoned)
  Phase 8 — Confirm credential theft and check Ryu detection log
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time, os, shutil, subprocess

_HERE       = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(_HERE, 'scripts')

# ── Topology ────────────────────────────────────────────
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

# ── Script deployment ───────────────────────────────────
def deploy_scripts():
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

# ── Controller readiness helpers ────────────────────────
def _ovs_get(field, target='s1'):
    r = subprocess.run(
        ['ovs-vsctl', 'get', 'controller', target, field],
        capture_output=True, text=True
    )
    return r.stdout.strip().lower()

def wait_for_controller(timeout=45):
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
    print(f"⏳ Waiting for Ryu to push flows (up to {timeout}s) …")
    for i in range(timeout):
        r = subprocess.run(
            ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
            capture_output=True, text=True
        )
        n = r.stdout.count('cookie=')
        if n > 0:
            print(f"  ✅ {n} flow(s) installed by Ryu")
            return True
        if r.returncode != 0 and i == timeout - 1:
            print(f"  ❌ ovs-ofctl failed (code {r.returncode}): {r.stderr.strip()}")
        time.sleep(1)
    print("  ⚠️  No flows after timeout — forwarding may fail")
    r2 = subprocess.run(
        ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
        capture_output=True, text=True
    )
    if r2.stdout.strip():
        print(f"  DEBUG flows:\n{r2.stdout.strip()}")
    return False

# ── Connectivity check ──────────────────────────────────
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
    """Kill leftover processes and flows from previous runs."""
    print("🧹 Cleaning up leftover processes ...")
    for script in ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py',
                   'ssl_strip.py', 'session_hijack.py']:
        subprocess.run(['pkill', '-f', script], capture_output=True)
    subprocess.run(
        ['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', 's1'],
        capture_output=True
    )

# ── ARP poison verification ─────────────────────────────
def verify_arp_poison(victim, attacker_mac='00:00:00:00:00:03', retries=6):
    """
    Confirm that victim's ARP cache shows server IP (10.0.0.2)
    pointing to the attacker's MAC.  Retries every 3s.
    """
    print(f"  Polling victim ARP cache for poison (attacker MAC={attacker_mac}) ...")
    for i in range(retries):
        arp_out = victim.cmd('arp -n')
        if attacker_mac in arp_out:
            print(f"  ✅ ARP poison confirmed on victim (attempt {i+1})")
            print(f"     {arp_out.strip()}")
            return True
        print(f"  … attempt {i+1}/{retries} — not poisoned yet, waiting 3s")
        time.sleep(3)
    print("  ⚠️  ARP poison not confirmed — attacker may not have MAC-resolved victim")
    print(f"     Current victim ARP table:\n{victim.cmd('arp -n').strip()}")
    return False

# ── Main demo ───────────────────────────────────────────
def run_demo():
    cleanup_orphans()
    net = create_topology()
    net.start()

    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')
    device1  = net.get('device1')
    device2  = net.get('device2')
    attacker_iface = 'attacker-eth0'

    deploy_scripts()

    print("\n" + "="*60)
    print("🚀 MITM DETECTION DEMO STARTED")
    print("="*60)

    # ── GATE: wait for Ryu before any traffic ──────────────
    ctrl_ok = wait_for_controller(timeout=45)
    if ctrl_ok:
        wait_for_flows(timeout=20)
    else:
        print("\n⚠️  Continuing without confirmed controller.")
        print("   Start Ryu now:  ryu-manager my_controller.py\n")

    # ── Phase 1: ARP warm-up ───────────────────────────────
    print("\n📡 Phase 1: ARP warm-up — all hosts learning MACs …")
    pairs = [
        (victim,   '10.0.0.2'),
        (victim,   '10.0.0.100'),
        (server,   '10.0.0.1'),
        (server,   '10.0.0.100'),
        (attacker, '10.0.0.1'),
        (attacker, '10.0.0.2'),
        (device1,  '10.0.0.1'),
        (device1,  '10.0.0.2'),
        (device2,  '10.0.0.1'),
        (device2,  '10.0.0.2'),
    ]
    for host, dst in pairs:
        host.cmd(f'ping -c 2 -W 2 {dst} > /dev/null 2>&1')
    time.sleep(2)

    print("  Attacker ARP cache (should know victim + server MACs):")
    print(f"  {attacker.cmd('arp -n').strip()}")

    # Hard stop if basic connectivity is broken before any attack
    if not check_ping(victim, '10.0.0.2', 'victim → server (pre-attack baseline)'):
        print("\n  Dumping OVS flows for diagnosis:")
        print(os.popen('ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null').read()[:800])
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
        print("  ✅ Login server verified from victim")
    else:
        print(f"  ⚠️  Unexpected response: {test[:200]}")
        print(f"     server port 8080: {server.cmd('ss -tlnp | grep 8080').strip() or 'NOT LISTENING'}")
        print(f"     server processes: {server.cmd('pgrep -a python3').strip()}")

    # ── Phase 3: Normal baseline traffic ──────────────────
    print("\n✅ Phase 3: Normal traffic — establishing ML baseline …")
    victim.cmd('curl -s http://10.0.0.2:8080/ > /dev/null &')
    victim.cmd(
        'curl -s -X POST http://10.0.0.2:8080/login '
        '-d "username=alice&password=secret123" > /dev/null &'
    )
    device1.cmd('ping -c 10 10.0.0.2 > /dev/null &')
    time.sleep(5)
    print("  ✅ Baseline done — Ryu should show NORMAL ML scores")

    # ── Phase 4: SSL Stripping (device1 → server:443) ─────
    print("\n🔐 Phase 4: SSL Stripping attack (device1 → server:443) …")
    device1.cmd(
        'python3 /tmp/ssl_strip.py 10.0.0.2 '
        '> /tmp/ssl_strip_output.txt 2>&1 &'
    )
    print("  device1 generating port-443 TCP flows with RST injection …")
    # attacker_mitm.py also runs SSL strip internally — wait long enough
    # for the ML model to accumulate 20+ packets from device1's flow
    time.sleep(10)
    print(f"  ssl_strip log: "
          f"{device1.cmd('tail -5 /tmp/ssl_strip_output.txt 2>/dev/null | strings').strip()}")

    # ── Phase 5: Session Hijacking (device2) ──────────────
    print("\n🔒 Phase 5: Session Hijacking via RST injection (device2) …")
    device2.cmd(
        'python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2 device2-eth0 '
        '> /tmp/session_hijack_output.txt 2>&1 &'
    )
    print("  device2 injecting ACK+RST packets into victim↔server flow …")
    # 30 RST packets at 0.3s spacing = ~9s; wait 12s for buffer
    time.sleep(12)
    print(f"  session_hijack log: "
          f"{device2.cmd('tail -5 /tmp/session_hijack_output.txt 2>/dev/null | strings').strip()}")

    # ── Phase 6: ARP Poisoning MITM (attacker_mitm.py) ────
    print(f"\n🔴 Phase 6: ARP Poisoning MITM attack (interface={attacker_iface}) …")

    # Pre-configure IP forwarding and iptables BEFORE the script starts
    # so relay traffic isn't dropped while the script is still initialising
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    attacker.cmd('sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1')
    attacker.cmd('iptables -F; iptables -t nat -F; iptables -P FORWARD ACCEPT')
    attacker.cmd(
        'iptables -t nat -A PREROUTING -p tcp --destination-port 443 '
        '-j REDIRECT --to-ports 10000 2>/dev/null'
    )

    # Launch attacker_mitm.py — it resolves MACs then waits 5s for ARP
    # to propagate before starting the transparent relay and other modules.
    # We wait 15s total: 5s (ARP propagation) + 5s (internal delay) + 5s buffer.
    attacker.cmd(
        f'python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 {attacker_iface} '
        f'> /tmp/attacker_output.txt 2>&1 &'
    )

    print("  ⏳ Waiting 15s for ARP poison to propagate and attack modules to start …")
    print("     (attacker_mitm.py waits 5s internally for ARP cache to update)")
    time.sleep(15)

    print("\n  Attacker startup log:")
    print(attacker.cmd('head -40 /tmp/attacker_output.txt 2>/dev/null | strings'))

    # Verify poison took effect before victim sends credentials
    # If this fails the demo still continues but flags the issue clearly
    poisoned = verify_arp_poison(victim, attacker_mac='00:00:00:00:00:03')

    if not poisoned:
        print("\n  ⚠️  Poison unconfirmed — giving 10 more seconds for ARP to settle …")
        time.sleep(10)
        verify_arp_poison(victim, attacker_mac='00:00:00:00:00:03')

    # ── Phase 7: Victim sends credentials ─────────────────
    print("\n💀 Phase 7: Victim sending credentials (should be intercepted) …")
    # victim_traffic.py sends login POST requests to server; since ARP is
    # poisoned the traffic routes through attacker first → credentials stolen
    victim.cmd(
        'python3 /tmp/victim_traffic.py 10.0.0.2 '
        '> /tmp/victim_output.txt 2>&1 &'
    )
    # Give victim_traffic.py time to complete its POST requests
    # and give attacker_mitm.py's sniffer time to intercept and write them
    print("  ⏳ Waiting 10s for victim traffic + interception …")
    time.sleep(10)

    # ── Phase 8: Confirm theft and detection ───────────────
    print("\n🔍 Phase 8: Checking stolen credentials …")
    stolen = attacker.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null || echo "(empty)"')

    if 'username' in stolen.lower() or 'password' in stolen.lower():
        print(f"🚨 CREDENTIALS STOLEN:\n{stolen[:600]}")
    else:
        print("⏳ No credentials captured yet.")
        print("   Possible reasons:")
        print("   • ARP poison not fully propagated (victim still routing directly)")
        print("   • victim_traffic.py did not POST before interception started")
        print("   • SSL/TLS active — see ssl_strip log")
        print(f"\n  Attacker log tail:\n"
              f"{attacker.cmd('tail -25 /tmp/attacker_output.txt 2>/dev/null | strings')}")
        print(f"\n  Victim log:\n"
              f"{victim.cmd('cat /tmp/victim_output.txt 2>/dev/null | strings')}")

    # ── Phase 8: Detection summary ─────────────────────────
    print("\n🛡️  Phase 8: Expected Ryu detection events:")
    print("     [RULE] ARP POISONING     — MAC/IP binding conflict: 10.0.0.2 claimed by 00:00:00:00:00:03")
    print("     [RULE] TRANSPARENT RELAY — ingress port anomaly: victim IP arriving on attacker's port")
    print("     [ML]   ARP/RELAY         — port_anomaly + mac_ip_mismatch features scored by model")
    print("     [RULE] DNS HIJACKING     — response timing < 2ms threshold (on-path spoof)")
    print("     [RULE] SSL STRIPPING     — port 443 + no TLS completion (device1 + attacker proxy)")
    print("     [RULE] SESSION HIJACKING — RST ratio > 0.15 + real seq injection (device2 + attacker)")

    print("\n" + "="*60)
    print("📊 DEMO COMPLETE — Interactive CLI open")
    print()
    print("  victim   arp -n                             → poisoned ARP table")
    print("  victim   cat /tmp/victim_output.txt         → victim traffic log")
    print("  attacker cat /tmp/mitm_stolen.txt           → stolen credentials")
    print("  attacker cat /tmp/attacker_output.txt       → full attacker log")
    print("  device1  cat /tmp/ssl_strip_output.txt      → SSL strip log")
    print("  device2  cat /tmp/session_hijack_output.txt → session hijack log")
    print("  server   cat /tmp/server_output.txt         → server log")
    print()
    print("  ovs-ofctl -O OpenFlow13 dump-flows s1       → current OVS flows")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()