#!/usr/bin/env python3
"""
enterprise_run_demo.py — MITM Detection on Production Enterprise Network
5-tier topology with 25+ hosts (FIXED: shortened hostnames for interface limit)

Usage: sudo python3 enterprise_run_demo.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.cli import CLI
from mininet.log import setLogLevel
import time, os, shutil, subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(_HERE, 'scripts')

class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

def create_topology():
    """Production 5-tier enterprise topology"""
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    net.addController('c0', ip='127.0.0.1', port=6633)
    
    r0 = net.addHost('r0', cls=Router, ip='0.0.0.0')
    
    # Tier 1: DMZ (s1)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    net.addLink(r0, s1)
    
    server = net.addHost('server', ip='10.0.1.10/24', mac='00:00:00:00:01:10')
    web1 = net.addHost('web1', ip='10.0.1.11/24', mac='00:00:00:00:01:11')
    web2 = net.addHost('web2', ip='10.0.1.12/24', mac='00:00:00:00:01:12')
    dns = net.addHost('dns', ip='10.0.1.20/24', mac='00:00:00:00:01:20')
    mail = net.addHost('mail', ip='10.0.1.25/24', mac='00:00:00:00:01:25')
    api = net.addHost('api', ip='10.0.1.30/24', mac='00:00:00:00:01:30')
    cache = net.addHost('cache', ip='10.0.1.40/24', mac='00:00:00:00:01:40')
    
    for h in [server, web1, web2, dns, mail, api, cache]:
        net.addLink(h, s1)
    
    # Tier 2: Internal (s2)
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    net.addLink(r0, s2)
    
    victim = net.addHost('victim', ip='10.0.2.50/24', mac='00:00:00:00:02:50')
    device1 = net.addHost('device1', ip='10.0.2.51/24', mac='00:00:00:00:02:51')
    device2 = net.addHost('device2', ip='10.0.2.52/24', mac='00:00:00:00:02:52')
    ws1 = net.addHost('ws1', ip='10.0.2.60/24', mac='00:00:00:00:02:60')
    ws2 = net.addHost('ws2', ip='10.0.2.61/24', mac='00:00:00:00:02:61')
    ws3 = net.addHost('ws3', ip='10.0.2.62/24', mac='00:00:00:00:02:62')
    ws4 = net.addHost('ws4', ip='10.0.2.63/24', mac='00:00:00:00:02:63')
    ws5 = net.addHost('ws5', ip='10.0.2.64/24', mac='00:00:00:00:02:64')
    printer = net.addHost('printer', ip='10.0.2.100/24', mac='00:00:00:00:02:ff')
    voip = net.addHost('voip', ip='10.0.2.101/24', mac='00:00:00:00:02:fe')
    
    for h in [victim, device1, device2, ws1, ws2, ws3, ws4, ws5, printer, voip]:
        net.addLink(h, s2)
    
    # Tier 3: Database (s3) - SHORTENED NAMES
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    net.addLink(r0, s3)
    
    db1 = net.addHost('db1', ip='10.0.3.10/24', mac='00:00:00:00:03:10')
    db2 = net.addHost('db2', ip='10.0.3.11/24', mac='00:00:00:00:03:11')
    db3 = net.addHost('db3', ip='10.0.3.12/24', mac='00:00:00:00:03:12')
    fs = net.addHost('fs', ip='10.0.3.20/24', mac='00:00:00:00:03:20')
    
    for h in [db1, db2, db3, fs]:
        net.addLink(h, s3)
    
    # Tier 4: Management (s4) - SHORTENED NAMES
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    net.addLink(r0, s4)
    
    admin = net.addHost('admin', ip='10.0.4.10/24', mac='00:00:00:00:04:10')
    monitor = net.addHost('monitor', ip='10.0.4.20/24', mac='00:00:00:00:04:20')
    siem = net.addHost('siem', ip='10.0.4.30/24', mac='00:00:00:00:04:30')
    backup = net.addHost('backup', ip='10.0.4.40/24', mac='00:00:00:00:04:40')
    
    for h in [admin, monitor, siem, backup]:
        net.addLink(h, s4)
    
    # Tier 5: Lab/Attacker (s5)
    s5 = net.addSwitch('s5', protocols='OpenFlow13')
    net.addLink(r0, s5)
    
    attacker = net.addHost('attacker', ip='10.0.5.100/24', mac='00:00:00:00:05:64')
    attacker2 = net.addHost('attacker2', ip='10.0.5.101/24', mac='00:00:00:00:05:65')
    
    net.addLink(attacker, s5)
    net.addLink(attacker2, s5)
    
    return net, r0

def deploy_scripts():
    print("\n📂 Deploying attack scripts ...")
    for fname in ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py', 'ssl_strip.py', 'session_hijack.py']:
        src = os.path.join(SCRIPTS_DIR, fname)
        dst = f'/tmp/{fname}'
        if os.path.exists(src):
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            print(f"  ✅ {fname}")

def _ovs_get(field, target='s1'):
    r = subprocess.run(['ovs-vsctl', 'get', 'controller', target, field], capture_output=True, text=True)
    return r.stdout.strip().lower()

def wait_for_controller(timeout=45):
    print(f"\n⏳ Waiting for Ryu ({timeout}s) …")
    for i in range(timeout):
        try:
            if 'true' in _ovs_get('is_connected'):
                print(f"  ✅ Ryu connected! ({i}s)")
                return True
        except:
            pass
        time.sleep(1)
        if i % 10 == 9:
            print(f"  ... {i+1}s ...")
    print("  ❌ Start: ryu-manager <controller>.py")
    return False

def wait_for_flows(timeout=20):
    print(f"⏳ Waiting for flows ({timeout}s) …")
    for i in range(timeout):
        r = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'], capture_output=True, text=True)
        if r.stdout.count('cookie=') > 0:
            print(f"  ✅ Flows installed")
            return True
        time.sleep(1)
    return False

def check_ping(src_host, dst_ip, label, retries=3):
    for attempt in range(retries):
        r = src_host.cmd(f'ping -c 2 -W 2 {dst_ip}')
        if '1 received' in r or '2 received' in r:
            print(f"  ✅ {label}: reachable")
            return True
        time.sleep(2)
    print(f"  ❌ {label}: UNREACHABLE")
    return False

def cleanup_orphans():
    for proc in ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py']:
        subprocess.run(['pkill', '-f', proc], capture_output=True)

def run_demo():
    cleanup_orphans()
    net, r0 = create_topology()
    net.start()
    
    # Router interfaces
    r0.cmd('ip addr add 10.0.1.1/24 dev r0-eth0')
    r0.cmd('ip addr add 10.0.2.1/24 dev r0-eth1')
    r0.cmd('ip addr add 10.0.3.1/24 dev r0-eth2')
    r0.cmd('ip addr add 10.0.4.1/24 dev r0-eth3')
    r0.cmd('ip addr add 10.0.5.1/24 dev r0-eth4')
    
    # Default routes
    dmz = ['server', 'web1', 'web2', 'dns', 'mail', 'api', 'cache']
    internal = ['victim', 'device1', 'device2', 'ws1', 'ws2', 'ws3', 'ws4', 'ws5', 'printer', 'voip']
    db = ['db1', 'db2', 'db3', 'fs']
    mgmt = ['admin', 'monitor', 'siem', 'backup']
    lab = ['attacker', 'attacker2']
    
    for h in dmz:
        net.get(h).cmd('ip route add default via 10.0.1.1')
    for h in internal:
        net.get(h).cmd('ip route add default via 10.0.2.1')
    for h in db:
        net.get(h).cmd('ip route add default via 10.0.3.1')
    for h in mgmt:
        net.get(h).cmd('ip route add default via 10.0.4.1')
    for h in lab:
        net.get(h).cmd('ip route add default via 10.0.5.1')
    
    victim = net.get('victim')
    server = net.get('server')
    attacker = net.get('attacker')
    device1 = net.get('device1')
    device2 = net.get('device2')
    
    deploy_scripts()
    
    print("\n" + "="*70)
    print("🚀 ENTERPRISE MITM DETECTION - PRODUCTION TOPOLOGY")
    print("="*70)
    print("""
25+ Hosts across 5 Tiers:
  DMZ (s1):        7 servers (web, dns, mail, api, cache, etc)
  Internal (s2):  10 workstations (victim, ws1-5, devices, etc)
  Database (s3):   4 DB servers (db1, db2, db3, fileserver)
  Management (s4): 4 admin servers (admin, monitor, siem, backup)
  Lab (s5):        2 attackers (controlled environment)
""")
    
    wait_for_controller(45)
    wait_for_flows(20)
    
    print("\n📡 Phase 1: ARP warm-up across tiers")
    pairs = [(victim, '10.0.1.10'), (server, '10.0.2.50'), (attacker, '10.0.1.10')]
    for h, d in pairs:
        h.cmd(f'ping -c 2 {d} > /dev/null 2>&1')
    time.sleep(2)
    print("  ✅ Ready")
    
    if not check_ping(victim, '10.0.1.10', 'victim→server'):
        CLI(net)
        net.stop()
        return
    
    print("\n🏦 Phase 2: Login server (DMZ)")
    server.cmd('python3 /tmp/server_login.py > /tmp/server_output.txt 2>&1 &')
    time.sleep(3)
    
    print("\n✅ Phase 3: Baseline traffic")
    victim.cmd('curl -s http://10.0.1.10:8080/ > /dev/null &')
    device1.cmd('ping -c 10 10.0.1.10 &')
    time.sleep(5)
    
    print("\n🔐 Phase 4: SSL Stripping (device1)")
    device1.cmd('python3 /tmp/ssl_strip.py 10.0.1.10 &')
    time.sleep(8)
    
    print("\n🔒 Phase 5: RST Injection (device2)")
    device2.cmd('python3 /tmp/session_hijack.py 10.0.2.50 10.0.1.10 device2-eth0 &')
    time.sleep(10)
    
    print("\n🔴 Phase 6: ARP Poisoning (attacker)")
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1 >/dev/null')
    attacker.cmd('iptables -P FORWARD ACCEPT >/dev/null 2>&1')
    attacker.cmd('python3 /tmp/attacker_mitm.py 10.0.2.50 10.0.1.10 attacker-eth0 &')
    time.sleep(5)
    
    print("\n💀 Phase 7: Credential theft")
    victim.cmd('python3 /tmp/victim_traffic.py 10.0.1.10 &')
    time.sleep(6)
    
    print("\n" + "="*70)
    print("✅ DEMO COMPLETE — Production topology with all attacks")
    print("="*70 + "\n")
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_demo()