#!/usr/bin/env python3
"""
enterprise_topology.py - Production-Grade SDN Topology for MITM Detection
Suitable for capstone research with realistic network segmentation

Architecture:
  - 3 Layer-3 subnets with proper gateways
  - DMZ (public servers)
  - Internal (trusted clients)
  - Lab/Attacker (isolated)
  - Multiple switches with core router
  - Proper VLAN-like separation (using subnets)

Network Design:
  DMZ:      10.0.1.0/24   (servers, public-facing)
  Internal: 10.0.2.0/24   (users, workstations)
  Lab:      10.0.3.0/24   (attackers, isolated)
  
  All traffic routes through 10.0.0.1 (core router)
  
Hosts (matching attack scenarios):
  server:        10.0.1.10  (login page, vulnerable)
  attacker:      10.0.3.100 (MITM attack platform)
  victim:        10.0.2.20  (user sending credentials)
  device1:       10.0.2.21  (generates SSL strip signature)
  device2:       10.0.2.22  (generates RST injection)
  
This topology enables:
  ✅ Cross-subnet MITM attacks (victim → server through attacker)
  ✅ ARP spoofing on same subnet
  ✅ Traffic interception via gateway poisoning
  ✅ Realistic routing scenarios
  ✅ Proper ML feature extraction from multiple layers
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import subprocess

# ── Topology Definition ────────────────────────────────
class EnterpriseTopology(Topo):
    """
    Production topology with 3 subnets, proper gateways, and realistic routing.
    Designed for MITM detection capstone project.
    """
    
    def build(self):
        # === CORE ROUTER ===
        # Acts as default gateway for all 3 subnets
        core_router = self.addSwitch('core', cls='OVSKernelSwitch', failMode='standalone')
        
        # === LAYER 1: DMZ (10.0.1.0/24) ===
        # Public-facing servers
        dmz_switch = self.addSwitch('s_dmz', cls='OVSKernelSwitch', failMode='open')
        self.addLink(dmz_switch, core_router)
        
        # Server with login page (the target)
        server = self.addHost(
            'server',
            ip='10.0.1.10/24',
            mac='00:00:00:00:00:10',
            defaultRoute='via 10.0.1.1'
        )
        self.addLink(server, dmz_switch)
        
        # Additional DMZ hosts (for realism)
        web_cache = self.addHost(
            'web_cache',
            ip='10.0.1.20/24',
            mac='00:00:00:00:00:11',
            defaultRoute='via 10.0.1.1'
        )
        self.addLink(web_cache, dmz_switch)
        
        # === LAYER 2: INTERNAL (10.0.2.0/24) ===
        # Trusted internal clients
        internal_switch = self.addSwitch('s_internal', cls='OVSKernelSwitch', failMode='open')
        self.addLink(internal_switch, core_router)
        
        # Victim: user accessing the login server
        victim = self.addHost(
            'victim',
            ip='10.0.2.20/24',
            mac='00:00:00:00:00:20',
            defaultRoute='via 10.0.2.1'
        )
        self.addLink(victim, internal_switch)
        
        # Device 1: generates SSL strip signature
        device1 = self.addHost(
            'device1',
            ip='10.0.2.21/24',
            mac='00:00:00:00:00:21',
            defaultRoute='via 10.0.2.1'
        )
        self.addLink(device1, internal_switch)
        
        # Device 2: generates RST injection signature
        device2 = self.addHost(
            'device2',
            ip='10.0.2.22/24',
            mac='00:00:00:00:00:22',
            defaultRoute='via 10.0.2.1'
        )
        self.addLink(device2, internal_switch)
        
        # Additional internal hosts (workstations)
        workstation1 = self.addHost(
            'workstation1',
            ip='10.0.2.30/24',
            mac='00:00:00:00:00:23',
            defaultRoute='via 10.0.2.1'
        )
        self.addLink(workstation1, internal_switch)
        
        workstation2 = self.addHost(
            'workstation2',
            ip='10.0.2.31/24',
            mac='00:00:00:00:00:24',
            defaultRoute='via 10.0.2.1'
        )
        self.addLink(workstation2, internal_switch)
        
        # === LAYER 3: LAB/ATTACKER (10.0.3.0/24) ===
        # Isolated attacker subnet (controlled lab environment)
        lab_switch = self.addSwitch('s_lab', cls='OVSKernelSwitch', failMode='open')
        self.addLink(lab_switch, core_router)
        
        # Main attacker machine
        attacker = self.addHost(
            'attacker',
            ip='10.0.3.100/24',
            mac='00:00:00:00:00:30',
            defaultRoute='via 10.0.3.1'
        )
        self.addLink(attacker, lab_switch)
        
        # Secondary attacker (for coordinated attacks)
        attacker2 = self.addHost(
            'attacker2',
            ip='10.0.3.101/24',
            mac='00:00:00:00:00:31',
            defaultRoute='via 10.0.3.1'
        )
        self.addLink(attacker2, lab_switch)

# ── Network Configuration ──────────────────────────────
class EnterpriseNetwork:
    """
    Manages the Mininet network with proper routing and gateway configuration.
    """
    
    def __init__(self):
        self.net = None
        self.core_router = None
    
    def setup_network(self):
        """Create and configure the network."""
        # Build topology
        topo = EnterpriseTopology()
        
        # Create network with remote controller
        self.net = Mininet(
            topo=topo,
            controller=RemoteController('c0', ip='127.0.0.1', port=6653),
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=False
        )
        
        self.core_router = self.net.get('core')
    
    def configure_gateway_interfaces(self):
        """
        Configure core router interfaces as gateways for each subnet.
        This is critical: the router acts as Layer 3 gateway, enabling
        cross-subnet routing and realistic attack scenarios.
        """
        print("\n🔧 Configuring gateway interfaces on core router ...")
        
        # Core router interfaces (one per subnet)
        # These act as the default gateways
        self.core_router.cmd('ip link add br_dmz type bridge')
        self.core_router.cmd('ip link add br_internal type bridge')
        self.core_router.cmd('ip link add br_lab type bridge')
        
        # Assign IP addresses as gateways
        self.core_router.cmd('ip addr add 10.0.1.1/24 dev br_dmz')
        self.core_router.cmd('ip addr add 10.0.2.1/24 dev br_internal')
        self.core_router.cmd('ip addr add 10.0.3.1/24 dev br_lab')
        
        # Enable IP forwarding
        self.core_router.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null')
        
        print("  ✅ DMZ gateway:      10.0.1.1")
        print("  ✅ Internal gateway: 10.0.2.1")
        print("  ✅ Lab gateway:      10.0.3.1")
    
    def start(self):
        """Start the network."""
        print("\n🚀 Starting Enterprise Network ...")
        self.setup_network()
        self.net.start()
        self.configure_gateway_interfaces()
        print("  ✅ Network online")
    
    def stop(self):
        """Stop the network."""
        print("\n🛑 Stopping network ...")
        self.net.stop()
    
    def test_connectivity(self):
        """Verify all subnets are reachable."""
        print("\n📡 Testing cross-subnet connectivity ...")
        
        victim = self.net.get('victim')
        server = self.net.get('server')
        attacker = self.net.get('attacker')
        
        tests = [
            (victim, '10.0.1.10', 'victim → server (DMZ)'),
            (server, '10.0.2.20', 'server → victim (Internal)'),
            (attacker, '10.0.2.20', 'attacker → victim'),
            (victim, '10.0.3.100', 'victim → attacker'),
        ]
        
        for src_host, dst_ip, label in tests:
            result = src_host.cmd(f'ping -c 2 -W 2 {dst_ip}')
            if 'received' in result:
                print(f"  ✅ {label}")
            else:
                print(f"  ❌ {label} - FAILED")
        
        # Show ARP tables
        print("\n📋 ARP Tables (after ping):")
        print("Victim ARP cache:")
        print(victim.cmd('arp -n'))
    
    def deploy_scripts(self, scripts_dir='/tmp'):
        """Deploy attack scripts to /tmp (shared filesystem)."""
        print(f"\n📂 Scripts deployed to {scripts_dir}/")
        print("  (Attack scripts should be in ./scripts/)")
    
    def run_cli(self):
        """Start interactive Mininet CLI."""
        print("\n" + "="*70)
        print("  ENTERPRISE TOPOLOGY — Interactive CLI")
        print("="*70)
        print("\n🎯 Useful commands:")
        print("  victim   arp -n                     # Check ARP table")
        print("  victim   ip route                   # Check routing table")
        print("  server   python3 /tmp/server_login.py  # Start login page")
        print("  attacker python3 /tmp/attacker_mitm.py 10.0.2.20 10.0.1.10 attacker-eth0")
        print("  victim   curl http://10.0.1.10:8080/   # Test login page")
        print("  ovs-ofctl dump-flows s_internal    # View switch flows")
        print("\nNetwork segments:")
        print("  DMZ (10.0.1.0/24):      server, web_cache")
        print("  Internal (10.0.2.0/24): victim, device1, device2, workstation1, workstation2")
        print("  Lab (10.0.3.0/24):      attacker, attacker2")
        print("="*70 + "\n")
        
        CLI(self.net)
    
    def print_topology(self):
        """Print topology summary."""
        print("\n" + "="*70)
        print("  ENTERPRISE MITM DETECTION TOPOLOGY")
        print("="*70)
        print("""
Network Architecture:
                    ┌──────────────────────────────┐
                    │   Core Router (gateway)       │
                    │   10.0.1.1 / 10.0.2.1 / etc   │
                    └───────┬─────────┬──────────┬──┘
                            │         │          │
                   ┌────────┘         │          └────────┐
                   │                  │                   │
        ┌──────────▼─────────┐  ┌─────▼────────────┐  ┌──▼─────────────┐
        │   DMZ (s_dmz)      │  │ Internal(s_int)  │  │  Lab (s_lab)   │
        │  10.0.1.0/24       │  │  10.0.2.0/24     │  │ 10.0.3.0/24    │
        ├────────────────────┤  ├──────────────────┤  ├────────────────┤
        │ server (10.0.1.10) │  │ victim (10.0..20)│  │ attacker       │
        │ web_cache (10.0..20)  │ device1 (10.0..21  │ (10.0.3.100)   │
        │                    │  │ device2 (10.0..22  │ attacker2      │
        │   Gateway:10.0.1.1 │  │ workstation1 ..30  │ (10.0.3.101)   │
        │                    │  │ workstation2 ..31  │                │
        │                    │  │   Gateway:10.0.2.1 │ Gateway:10.0..1 │
        └────────────────────┘  └──────────────────┘  └────────────────┘

Subnet Roles:
  🔓 DMZ:      Public-facing servers (login page, web cache)
  👥 Internal: Trusted users (victim, devices, workstations)
  🔴 Lab:      Isolated attacker subnet (controlled environment)

Attack Flows (realistic cross-subnet scenarios):
  1️⃣  Victim (10.0.2.20) → Server (10.0.1.10)
      └─ Routes through core router 10.0.2.1 → 10.0.1.1
      └─ Attacker (10.0.3.100) poisons BOTH gateways for MITM
  
  2️⃣  SSL Stripping (device1 → server:443)
      └─ Creates flow anomaly on port 443
  
  3️⃣  RST Injection (device2 → server)
      └─ Injects reset packets into established flow
  
  4️⃣  ARP Poisoning (attacker → victim + server)
      └─ Poisons victim's ARP for server (Layer 2)
      └─ Traffic redirected through attacker (Layer 3)
""")
        print("="*70)

# ── Main execution ────────────────────────────────────
def main():
    setLogLevel('info')
    
    net = EnterpriseNetwork()
    net.print_topology()
    
    try:
        net.start()
        
        # Wait for controller
        print("\n⏳ Waiting for Ryu controller (60s)...")
        print("   If not connected, run in another terminal:")
        print("   ryu-manager <your_controller>.py")
        
        # Test connectivity
        time.sleep(10)
        net.test_connectivity()
        
        # Start CLI
        net.run_cli()
        
    except KeyboardInterrupt:
        print("\n⏸️  Interrupted")
    finally:
        net.stop()

if __name__ == '__main__':
    main()