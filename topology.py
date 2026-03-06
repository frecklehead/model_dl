from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def create_topology():
    # Use standard 10.0.0.x IPs to match victim_traffic.py
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    print("🌐 Adding Remote Controller (127.0.0.1:6633)...")
    net.addController('c0', ip='127.0.0.1', port=6633)
    
    print("🌐 Adding Switches...")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    print("🌐 Adding Hosts...")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')  # Victim
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')  # Server
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # Attacker
    
    print("🌐 Linking Hosts to Switch...")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    
    print("🚀 Starting Network...")
    net.start()
    
    print("\n" + "="*40)
    print("✅ TOPOLOGY READY")
    print("h1 (Victim)   : 10.0.0.1")
    print("h2 (Server)   : 10.0.0.2")
    print("h3 (Attacker) : 10.0.0.3")
    print("="*40 + "\n")
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
