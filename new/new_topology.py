#!/usr/bin/env python3
"""
new_topology.py - Complete Three-Subnet Topology for MITM Detection Testing
Architecture:
  - 3 switches (s1, s2, s3)
  - 1 router (r0) with 3 interfaces
  - 6 hosts across 3 subnets
  - Supports ARP spoofing and DNS hijacking attacks

Topology:
         ┌─── Router (r0) ───┐
         │                   │
    s1 ──┘                   └── s2 ────── s3
    │                            │         │
  h1,h2                        h3,h4     h5,h6

Subnets:
  - 10.0.1.0/24: h1, h2 (Subnet 1)
  - 10.0.2.0/24: h3, h4 (Subnet 2)
  - 10.0.3.0/24: h5, h6 (Subnet 3)

Gateway: 10.0.X.254 (r0)
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, Node
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

class Router(Node):
    """A Node with IP forwarding enabled"""
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(Router, self).terminate()

class ThreeSubnetTopo(Topo):
    """Three-subnet topology with router and SDN switches"""
    
    def build(self):
        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Create router (node with 3 interfaces)
        r0 = self.addHost('r0', ip='0.0.0.0', cls=Router)
        
        # === Subnet 1: 10.0.1.0/24 ===
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='aa:bb:cc:dd:ee:01')
        h2 = self.addHost('h2', ip='10.0.1.2/24', mac='aa:bb:cc:dd:ee:02')
        
        # === Subnet 2: 10.0.2.0/24 ===
        h3 = self.addHost('h3', ip='10.0.2.1/24', mac='aa:bb:cc:dd:ee:03')
        h4 = self.addHost('h4', ip='10.0.2.2/24', mac='aa:bb:cc:dd:ee:04')
        
        # === Subnet 3: 10.0.3.0/24 ===
        h5 = self.addHost('h5', ip='10.0.3.1/24', mac='aa:bb:cc:dd:ee:05')
        h6 = self.addHost('h6', ip='10.0.3.2/24', mac='aa:bb:cc:dd:ee:06')
        
        # === Links: Hosts to Switches ===
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        
        # === Links: Router to Switches ===
        self.addLink(r0, s1)  # r0-eth0 → Subnet 1
        self.addLink(r0, s2)  # r0-eth1 → Subnet 2
        self.addLink(r0, s3)  # r0-eth2 → Subnet 3

def run_topology():
    """Start the Mininet topology with remote Ryu controller"""
    setLogLevel('info')
    
    topo = ThreeSubnetTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        link=TCLink,
        autoSetMacs=True
    )
    
    net.start()
    
    # === Configure Router Interfaces ===
    r0 = net.get('r0')
    r0.cmd('ifconfig r0-eth0 10.0.1.254/24')
    r0.cmd('ifconfig r0-eth1 10.0.2.254/24')
    r0.cmd('ifconfig r0-eth2 10.0.3.254/24')
    r0.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # === Configure Host Interfaces & Routes ===
    # Subnet 1
    net.get('h1').cmd('ifconfig h1-eth0 10.0.1.1/24')
    net.get('h1').cmd('ip route add default via 10.0.1.254')
    net.get('h2').cmd('ifconfig h2-eth0 10.0.1.2/24')
    net.get('h2').cmd('ip route add default via 10.0.1.254')
    
    # Subnet 2
    net.get('h3').cmd('ifconfig h3-eth0 10.0.2.1/24')
    net.get('h3').cmd('ip route add default via 10.0.2.254')
    net.get('h4').cmd('ifconfig h4-eth0 10.0.2.2/24')
    net.get('h4').cmd('ip route add default via 10.0.2.254')
    
    # Subnet 3
    net.get('h5').cmd('ifconfig h5-eth0 10.0.3.1/24')
    net.get('h5').cmd('ip route add default via 10.0.3.254')
    net.get('h6').cmd('ifconfig h6-eth0 10.0.3.2/24')
    net.get('h6').cmd('ip route add default via 10.0.3.254')
    
    # === Print Topology Info ===
    print("\n" + "="*70)
    print("  SDN MITM Detection Topology Started")
    print("="*70)
    print("\nTopology:")
    print("  Router: r0 (10.0.1.254, 10.0.2.254, 10.0.3.254)")
    print("  Subnet 1 (10.0.1.0/24):  h1, h2")
    print("  Subnet 2 (10.0.2.0/24):  h3, h4")
    print("  Subnet 3 (10.0.3.0/24):  h5, h6")
    print("\nController: Ryu (127.0.0.1:6653)")
    print("\nHost MACs:")
    print("  h1: aa:bb:cc:dd:ee:01")
    print("  h2: aa:bb:cc:dd:ee:02")
    print("  h3: aa:bb:cc:dd:ee:03")
    print("  h4: aa:bb:cc:dd:ee:04")
    print("  h5: aa:bb:cc:dd:ee:05")
    print("  h6: aa:bb:cc:dd:ee:06")
    print("\nUsage:")
    print("  mininet> h1 ping h3   (test cross-subnet connectivity)")
    print("  mininet> h1 tcpdump   (capture traffic)")
    print("\nAttack Scripts (from separate terminals):")
    print("  python3 new_arp.py --victim 10.0.2.1 --gateway 10.0.2.254 --duration 60 --interface h1-eth0")
    print("  python3 new_dns.py --victim 10.0.2.1 --attacker_dns 10.0.1.2 --duration 60 --interface h1-eth0")
    print("  python3 new_covert.py --victim 10.0.2.1 --gateway 10.0.2.254 --duration 60 --interface h1-eth0 --attack_type relay")
    print("="*70 + "\n")
    
    # Start CLI for interactive control
    CLI(net)
    
    net.stop()

if __name__ == '__main__':
    run_topology()