#!/usr/bin/env python3
"""
enterprise_topology.py — Complete MITM Detection Demo
Usage: sudo python3 enterprise_topology.py

Attack sequence:
  Phase 1 — ARP warm-up (all hosts learn their gateway MACs)
  Phase 2 — Login server starts on server:8080 (10.0.1.10)
  Phase 3 — Normal baseline traffic (establishes ML baseline)
  Phase 4 — SSL Stripping attack from atk3 (insider) and atk4 (external) → server:443
  Phase 5 — Session Hijacking via RST injection from atk5 (insider) and atk6 (external)
  Phase 6 — ARP Poisoning MITM from atk1 (insider)
             └── Internal modules: ARP poison, relay flood, session hijack,
                 SSL strip RST, DNS hijack, credential interception
  Phase 7 — Victim sends credentials (atk1 should already be poisoned)
  Phase 8 — Confirm credential theft and check Ryu detection log
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.cli import CLI
from mininet.log import setLogLevel
import time, os, shutil, subprocess

_HERE       = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(_HERE, 'scripts')

class LinuxRouter(Node):
    """A Node with IP forwarding enabled, acting as a router."""
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1 > /dev/null 2>&1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0 > /dev/null 2>&1')
        super(LinuxRouter, self).terminate()

# ── Topology ────────────────────────────────────────────
def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    net.addController('c0', ip='127.0.0.1', port=6633)
    
    # r0 Router connecting all 5 subnets
    r0 = net.addHost('r0', cls=LinuxRouter)

    # 5 switches for the 5 subnets
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', protocols='OpenFlow13')

    # Connect switches to router
    net.addLink(s1, r0, intfName2='r0-eth1', params2={'ip': '10.0.1.1/24'})
    net.addLink(s2, r0, intfName2='r0-eth2', params2={'ip': '10.0.2.1/24'})
    net.addLink(s3, r0, intfName2='r0-eth3', params2={'ip': '10.0.3.1/24'})
    net.addLink(s4, r0, intfName2='r0-eth4', params2={'ip': '10.0.4.1/24'})
    net.addLink(s5, r0, intfName2='r0-eth5', params2={'ip': '10.0.5.1/24'})

    # Helper function to add hosts with their default routes
    def add_h(name, ip, mac, gw):
        return net.addHost(name, ip=ip, mac=mac, defaultRoute=f'via {gw}')

    # s1 – DMZ
    server = add_h('server', '10.0.1.10/24', '00:00:00:00:01:10', '10.0.1.1')
    web1   = add_h('web1',   '10.0.1.11/24', '00:00:00:00:01:11', '10.0.1.1')
    web2   = add_h('web2',   '10.0.1.12/24', '00:00:00:00:01:12', '10.0.1.1')
    dns    = add_h('dns',    '10.0.1.20/24', '00:00:00:00:01:20', '10.0.1.1')
    mail   = add_h('mail',   '10.0.1.25/24', '00:00:00:00:01:25', '10.0.1.1')
    api    = add_h('api',    '10.0.1.30/24', '00:00:00:00:01:30', '10.0.1.1')
    cache  = add_h('cache',  '10.0.1.40/24', '00:00:00:00:01:40', '10.0.1.1')
    for h in [server, web1, web2, dns, mail, api, cache]: net.addLink(h, s1)

    # s2 – Internal
    victim = add_h('victim', '10.0.2.50/24', '00:00:00:00:02:50', '10.0.2.1')
    atk1   = add_h('atk1',   '10.0.2.60/24', '00:00:00:00:02:60', '10.0.2.1')
    atk2   = add_h('atk2',   '10.0.2.61/24', '00:00:00:00:02:61', '10.0.2.1')
    atk3   = add_h('atk3',   '10.0.2.51/24', '00:00:00:00:02:51', '10.0.2.1')
    atk5   = add_h('atk5',   '10.0.2.52/24', '00:00:00:00:02:52', '10.0.2.1')
    ws2    = add_h('ws2',    '10.0.2.62/24', '00:00:00:00:02:62', '10.0.2.1')
    ws3    = add_h('ws3',    '10.0.2.63/24', '00:00:00:00:02:63', '10.0.2.1')
    ws4    = add_h('ws4',    '10.0.2.64/24', '00:00:00:00:02:64', '10.0.2.1')
    printer= add_h('printer','10.0.2.100/24','00:00:00:00:02:a0', '10.0.2.1')
    voip   = add_h('voip',   '10.0.2.101/24','00:00:00:00:02:a1', '10.0.2.1')
    for h in [victim, atk1, atk2, atk3, atk5, ws2, ws3, ws4, printer, voip]: net.addLink(h, s2)

    # s3 – Database
    db1    = add_h('db1',    '10.0.3.10/24', '00:00:00:00:03:10', '10.0.3.1')
    db2    = add_h('db2',    '10.0.3.11/24', '00:00:00:00:03:11', '10.0.3.1')
    db3    = add_h('db3',    '10.0.3.12/24', '00:00:00:00:03:12', '10.0.3.1')
    fs     = add_h('fs',     '10.0.3.20/24', '00:00:00:00:03:20', '10.0.3.1')
    for h in [db1, db2, db3, fs]: net.addLink(h, s3)

    # s4 – Management
    admin  = add_h('admin',  '10.0.4.10/24', '00:00:00:00:04:10', '10.0.4.1')
    monitor= add_h('monitor','10.0.4.20/24', '00:00:00:00:04:20', '10.0.4.1')
    siem   = add_h('siem',   '10.0.4.30/24', '00:00:00:00:04:30', '10.0.4.1')
    backup = add_h('backup', '10.0.4.40/24', '00:00:00:00:04:40', '10.0.4.1')
    for h in [admin, monitor, siem, backup]: net.addLink(h, s4)

    # s5 – Lab
    atk4   = add_h('atk4',   '10.0.5.100/24','00:00:00:00:05:a0', '10.0.5.1')
    atk6   = add_h('atk6',   '10.0.5.101/24','00:00:00:00:05:a1', '10.0.5.1')
    for h in [atk4, atk6]: net.addLink(h, s5)

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
        time.sleep(1)
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
    print("🧹 Cleaning up leftover processes ...")
    for script in ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py',
                   'ssl_strip.py', 'session_hijack.py']:
        subprocess.run(['pkill', '-f', script], capture_output=True)
    subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', 's1'], capture_output=True)
    subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', 's2'], capture_output=True)

# ── ARP poison verification ─────────────────────────────
def verify_arp_poison(victim, attacker_mac='00:00:00:00:02:60', retries=6):
    print(f"  Polling victim ARP cache for poison (attacker MAC={attacker_mac}) ...")
    for i in range(retries):
        arp_out = victim.cmd('arp -n')
        if attacker_mac in arp_out:
            print(f"  ✅ ARP poison confirmed on victim (attempt {i+1})")
            return True
        time.sleep(3)
    return False

# ── Main demo ───────────────────────────────────────────
def run_demo():
    cleanup_orphans()
    net = create_topology()
    net.start()

    victim = net.get('victim')
    server = net.get('server')
    r0     = net.get('r0')
    
    # Attackers
    atk1 = net.get('atk1') # ARP poisoning, insider
    atk3 = net.get('atk3') # SSL stripping, insider
    atk5 = net.get('atk5') # Session hijacking, insider
    atk4 = net.get('atk4') # SSL stripping, external
    atk6 = net.get('atk6') # Session hijacking, external

    atk1_iface = 'atk1-eth0'

    deploy_scripts()

    print("\n" + "="*60)
    print("🚀 ENTERPRISE MITM DETECTION DEMO STARTED")
    print("="*60)

    ctrl_ok = wait_for_controller(timeout=45)
    if ctrl_ok:
        wait_for_flows(timeout=20)

    # ── Phase 1: ARP warm-up ───────────────────────────────
    print("\n📡 Phase 1: Setting up routes & ARP warm-up …")
    
    # Essential cross-subnet pings to establish ARP for routers and hosts
    pairs = [
        (victim, '10.0.1.10'),
        (server, '10.0.2.50'),
        (atk1,   '10.0.1.10'),
        (atk3,   '10.0.1.10'),
        (atk5,   '10.0.1.10'),
        (atk4,   '10.0.1.10'),
        (atk6,   '10.0.1.10'),
    ]
    for host, dst in pairs:
        host.cmd(f'ping -c 2 -W 2 {dst} > /dev/null 2>&1')
    time.sleep(2)

    # Check baseline routing & connectivity
    if not check_ping(victim, '10.0.1.10', 'victim → server (pre-attack cross-subnet baseline)'):
        print("\n  Opening CLI — run 'pingall' and check Ryu terminal.")
        CLI(net)
        net.stop()
        return

    # ── Phase 2: Start login server ────────────────────────
    print("\n🏦 Phase 2: Starting login server on server:8080 (10.0.1.10) …")
    server.cmd('fuser -k 8080/tcp 2>/dev/null; sleep 1')
    server.cmd('python3 /tmp/server_login.py > /tmp/server_output.txt 2>&1 &')
    time.sleep(3)

    test = victim.cmd('curl -s --connect-timeout 5 http://10.0.1.10:8080/')
    if 'SecureBank' in test or 'Login' in test:
        print("  ✅ Login server verified from victim")

    # ── Phase 3: Normal baseline traffic ──────────────────
    print("\n✅ Phase 3: Normal traffic — establishing ML baseline …")
    victim.cmd('curl -s http://10.0.1.10:8080/ > /dev/null &')
    victim.cmd(
        'curl -s -X POST http://10.0.1.10:8080/login '
        '-d "username=alice&password=secret123" > /dev/null &'
    )
    atk3.cmd('ping -c 10 10.0.1.10 > /dev/null &')
    time.sleep(5)
    print("  ✅ Baseline done — Ryu should show NORMAL ML scores")

    # ── Phase 4: SSL Stripping (atk3 insider, atk4 external) ─
    print("\n🔐 Phase 4: SSL Stripping attack (atk3 insider & atk4 external → server:443) …")
    atk3.cmd('python3 /tmp/ssl_strip.py 10.0.1.10 > /tmp/ssl_strip_atk3.txt 2>&1 &')
    atk4.cmd('python3 /tmp/ssl_strip.py 10.0.1.10 > /tmp/ssl_strip_atk4.txt 2>&1 &')
    print("  Atk3 & Atk4 generating port-443 TCP flows with RST injection …")
    time.sleep(10)

    # ── Phase 5: Session Hijacking (atk5 insider, atk6 external) ─
    print("\n🔒 Phase 5: Session Hijacking via RST injection …")
    # For insider: injecting into victim (10.0.2.50) to server (10.0.1.10)
    atk5.cmd('python3 /tmp/session_hijack.py 10.0.2.50 10.0.1.10 atk5-eth0 > /tmp/session_hijack_atk5.txt 2>&1 &')
    # For external: might try injecting but from another subnet (Lab s5)
    atk6.cmd('python3 /tmp/session_hijack.py 10.0.2.50 10.0.1.10 atk6-eth0 > /tmp/session_hijack_atk6.txt 2>&1 &')
    print("  Atk5 & Atk6 injecting ACK+RST packets …")
    time.sleep(12)

    # ── Phase 6: ARP Poisoning MITM (atk1) ────────────────
    print(f"\n🔴 Phase 6: ARP Poisoning MITM attack (atk1, interface={atk1_iface}) …")
    atk1.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    atk1.cmd('sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1')
    atk1.cmd('iptables -F; iptables -t nat -F; iptables -P FORWARD ACCEPT')
    atk1.cmd(
        'iptables -t nat -A PREROUTING -p tcp --destination-port 443 '
        '-j REDIRECT --to-ports 10000 2>/dev/null'
    )

    # atk1 poisons victim (10.0.2.50) and server (10.0.1.10).
    # Since server is on another subnet, it realistically poisons the gateway interface, 
    # but the logic runs the same way passing victim and server IPs
    atk1.cmd(
        f'python3 /tmp/attacker_mitm.py 10.0.2.50 10.0.1.10 {atk1_iface} '
        f'> /tmp/attacker_output.txt 2>&1 &'
    )

    print("  ⏳ Waiting 15s for ARP poison and relay flood …")
    time.sleep(15)

    verify_arp_poison(victim, attacker_mac='00:00:00:00:02:60')

    # ── Phase 7: Victim sends credentials ─────────────────
    print("\n💀 Phase 7: Victim sending credentials to server (intercepted by atk1) …")
    victim.cmd(
        'python3 /tmp/victim_traffic.py 10.0.1.10 '
        '> /tmp/victim_output.txt 2>&1 &'
    )
    print("  ⏳ Waiting 10s for victim traffic + interception …")
    time.sleep(10)

    # ── Phase 8: Confirm theft and detection ───────────────
    print("\n🔍 Phase 8: Checking stolen credentials on atk1 …")
    stolen = atk1.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null || echo "(empty)"')

    if 'username' in stolen.lower() or 'password' in stolen.lower():
        print(f"🚨 CREDENTIALS STOLEN:\n{stolen[:600]}")
    else:
        print("⏳ No credentials captured.")

    print("\n" + "="*60)
    print("📊 DEMO COMPLETE — Interactive CLI open")
    print()
    print("  victim   arp -n                             → poisoned ARP table")
    print("  victim   cat /tmp/victim_output.txt         → victim traffic log")
    print("  atk1     cat /tmp/mitm_stolen.txt           → stolen credentials")
    print("  atk1     cat /tmp/attacker_output.txt       → full attacker log")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()