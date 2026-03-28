#!/usr/bin/env python3
"""
topology.py — Enterprise Capstone Topology
Five subnets, one central software router (r0), 27 hosts, 6 OVS switches.

Node map
─────────────────────────────────────────────────────────────────────
r0          Software router — IP forwarding, default gateway for all subnets
            Interfaces: r0-eth0..r0-eth4, one per switch

s1  DMZ          10.0.1.0/24    GW 10.0.1.1
    server       10.0.1.10      login/HTTP server (runs server_login.py)
    web1         10.0.1.11      web server
    web2         10.0.1.12      web server
    dns          10.0.1.20      DNS server
    mail         10.0.1.25      mail server
    api          10.0.1.30      API server
    cache        10.0.1.40      cache server

s2  Internal     10.0.2.0/24    GW 10.0.2.1
    victim       10.0.2.50      primary attack target
    atk1         10.0.2.60      ARP poisoning (insider, coordinated)
    atk2         10.0.2.61      ARP poisoning (insider, coordinated)
    atk3         10.0.2.51      SSL stripping (insider)
    atk5         10.0.2.52      session hijacking (insider)
    ws2          10.0.2.62      legitimate workstation
    ws3          10.0.2.63      legitimate workstation
    ws4          10.0.2.64      legitimate workstation
    printer      10.0.2.100     legitimate printer
    voip         10.0.2.101     VoIP device

s3  Database     10.0.3.0/24    GW 10.0.3.1
    db1          10.0.3.10
    db2          10.0.3.11
    db3          10.0.3.12
    fs           10.0.3.20      file server

s4  Management   10.0.4.0/24    GW 10.0.4.1
    admin        10.0.4.10
    monitor      10.0.4.20
    siem         10.0.4.30
    backup       10.0.4.40

s5  Lab          10.0.5.0/24    GW 10.0.5.1
    atk4         10.0.5.100     SSL stripping (external)
    atk6         10.0.5.101     session hijacking (external)

Usage
─────
  # Terminal 1: start Ryu controller
  ryu-manager my_controller.py

  # Terminal 2: start topology + demo
  sudo python3 run_demo.py

  # Or just the topology with CLI:
  sudo python3 topology.py
"""

import os
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel


# ─────────────────────────────────────────────────────────────────────────────
# LINUXROUTER — host with IP forwarding enabled
# ─────────────────────────────────────────────────────────────────────────────
class LinuxRouter(Node):
    """A host that acts as a software router by enabling IP forwarding."""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1')
        super().terminate()


# ─────────────────────────────────────────────────────────────────────────────
# TOPOLOGY
# ─────────────────────────────────────────────────────────────────────────────
class CapstoneTopology(Topo):
    """
    Single-controller SDN topology.
    r0 is a software router connecting all five access switches through
    dedicated links.  All switches connect back to r0 so inter-subnet
    traffic is always seen by the SDN controller.
    """

    def build(self):
        # ── Switches ────────────────────────────────────────────────────────
        s1 = self.addSwitch('s1', protocols='OpenFlow13')   # DMZ
        s2 = self.addSwitch('s2', protocols='OpenFlow13')   # Internal
        s3 = self.addSwitch('s3', protocols='OpenFlow13')   # Database
        s4 = self.addSwitch('s4', protocols='OpenFlow13')   # Management
        s5 = self.addSwitch('s5', protocols='OpenFlow13')   # Lab

        # ── Central router ──────────────────────────────────────────────────
        # r0's first interface (r0-eth0) connects to s1, r0-eth1 to s2, etc.
        # We give r0 a dummy default IP; real IPs are assigned after start().
        r0 = self.addHost('r0', cls=LinuxRouter, ip='10.0.1.1/24')
        self.addLink(r0, s1)   # r0-eth0  ↔  s1  (10.0.1.1/24)
        self.addLink(r0, s2)   # r0-eth1  ↔  s2  (10.0.2.1/24)
        self.addLink(r0, s3)   # r0-eth2  ↔  s3  (10.0.3.1/24)
        self.addLink(r0, s4)   # r0-eth3  ↔  s4  (10.0.4.1/24)
        self.addLink(r0, s5)   # r0-eth4  ↔  s5  (10.0.5.1/24)

        # ── s1  DMZ  10.0.1.x ───────────────────────────────────────────────
        gw1 = 'via 10.0.1.1'
        for name, ip, mac in [
            ('server', '10.0.1.10/24', '00:00:01:00:00:0a'),
            ('web1',   '10.0.1.11/24', '00:00:01:00:00:0b'),
            ('web2',   '10.0.1.12/24', '00:00:01:00:00:0c'),
            ('dns',    '10.0.1.20/24', '00:00:01:00:00:14'),
            ('mail',   '10.0.1.25/24', '00:00:01:00:00:19'),
            ('api',    '10.0.1.30/24', '00:00:01:00:00:1e'),
            ('cache',  '10.0.1.40/24', '00:00:01:00:00:28'),
        ]:
            h = self.addHost(name, ip=ip, mac=mac, defaultRoute=gw1)
            self.addLink(h, s1)

        # ── s2  Internal  10.0.2.x ──────────────────────────────────────────
        gw2 = 'via 10.0.2.1'
        for name, ip, mac in [
            ('victim',  '10.0.2.50/24',  '00:00:02:00:00:32'),  # target
            ('atk1',    '10.0.2.60/24',  '00:00:02:00:00:3c'),  # ARP poison
            ('atk2',    '10.0.2.61/24',  '00:00:02:00:00:3d'),  # ARP poison
            ('atk3',    '10.0.2.51/24',  '00:00:02:00:00:33'),  # SSL insider
            ('atk5',    '10.0.2.52/24',  '00:00:02:00:00:34'),  # hijack insider
            ('ws2',     '10.0.2.62/24',  '00:00:02:00:00:3e'),
            ('ws3',     '10.0.2.63/24',  '00:00:02:00:00:3f'),
            ('ws4',     '10.0.2.64/24',  '00:00:02:00:00:40'),
            ('printer', '10.0.2.100/24', '00:00:02:00:00:64'),
            ('voip',    '10.0.2.101/24', '00:00:02:00:00:65'),
        ]:
            h = self.addHost(name, ip=ip, mac=mac, defaultRoute=gw2)
            self.addLink(h, s2)

        # ── s3  Database  10.0.3.x ──────────────────────────────────────────
        gw3 = 'via 10.0.3.1'
        for name, ip, mac in [
            ('db1', '10.0.3.10/24', '00:00:03:00:00:0a'),
            ('db2', '10.0.3.11/24', '00:00:03:00:00:0b'),
            ('db3', '10.0.3.12/24', '00:00:03:00:00:0c'),
            ('fs',  '10.0.3.20/24', '00:00:03:00:00:14'),
        ]:
            h = self.addHost(name, ip=ip, mac=mac, defaultRoute=gw3)
            self.addLink(h, s3)

        # ── s4  Management  10.0.4.x ────────────────────────────────────────
        gw4 = 'via 10.0.4.1'
        for name, ip, mac in [
            ('admin',   '10.0.4.10/24', '00:00:04:00:00:0a'),
            ('monitor', '10.0.4.20/24', '00:00:04:00:00:14'),
            ('siem',    '10.0.4.30/24', '00:00:04:00:00:1e'),
            ('backup',  '10.0.4.40/24', '00:00:04:00:00:28'),
        ]:
            h = self.addHost(name, ip=ip, mac=mac, defaultRoute=gw4)
            self.addLink(h, s4)

        # ── s5  Lab  10.0.5.x ───────────────────────────────────────────────
        gw5 = 'via 10.0.5.1'
        for name, ip, mac in [
            ('atk4', '10.0.5.100/24', '00:00:05:00:00:64'),  # SSL external
            ('atk6', '10.0.5.101/24', '00:00:05:00:00:65'),  # hijack external
        ]:
            h = self.addHost(name, ip=ip, mac=mac, defaultRoute=gw5)
            self.addLink(h, s5)


# ─────────────────────────────────────────────────────────────────────────────
# ROUTER CONFIGURATION  (called after net.start())
# ─────────────────────────────────────────────────────────────────────────────
def configure_router(net):
    """
    Assign the correct IP to each of r0's interfaces and add inter-subnet
    routes so traffic between subnets is forwarded through r0.
    Mininet assigns interface names in link order: r0-eth0, r0-eth1, …
    Link order in the topology: s1, s2, s3, s4, s5.
    """
    r0 = net.get('r0')

    # Remove the placeholder IP Mininet assigned during build
    r0.cmd('ip addr flush dev r0-eth0')

    # Assign one gateway IP per subnet interface
    r0.cmd('ip addr add 10.0.1.1/24 dev r0-eth0')   # DMZ
    r0.cmd('ip addr add 10.0.2.1/24 dev r0-eth1')   # Internal
    r0.cmd('ip addr add 10.0.3.1/24 dev r0-eth2')   # Database
    r0.cmd('ip addr add 10.0.4.1/24 dev r0-eth3')   # Management
    r0.cmd('ip addr add 10.0.5.1/24 dev r0-eth4')   # Lab

    # Bring all interfaces up
    for iface in ('r0-eth0', 'r0-eth1', 'r0-eth2', 'r0-eth3', 'r0-eth4'):
        r0.cmd(f'ip link set {iface} up')

    # Confirm
    print('  r0 interfaces:')
    print(f"  {r0.cmd('ip addr show | grep inet | grep -v inet6').strip()}")


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE ENTRY POINT  (CLI only — no attacks)
# ─────────────────────────────────────────────────────────────────────────────
def run_topology():
    setLogLevel('info')
    net = Mininet(topo=CapstoneTopology(),
                  controller=RemoteController,
                  switch=OVSSwitch)
    net.addController('c0', ip='127.0.0.1', port=6633)
    net.start()
    configure_router(net)
    print('\nTopology started. Type "exit" to quit.')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    run_topology()