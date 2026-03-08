from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    print("🌐 Connecting to Remote Controller at 127.0.0.1:6633...")
    c0 = net.addController('c0', ip='127.0.0.1', port=6633)
    
    print("🌐 Adding 2 Switches (s1, s2)...")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    
    print("🌐 Adding 3 Hosts (h1-Victim, h2-Server, h3-Attacker)...")
    # h1 (Victim) on Switch 1
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    # h2 (Server) on Switch 2
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    # h3 (Attacker) on Switch 1
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    
    print("🌐 Connecting Hosts to Switches...")
    net.addLink(h1, s1)
    net.addLink(h3, s1)
    net.addLink(h2, s2)
    
    print("🌐 Connecting Switch 1 to Switch 2...")
    net.addLink(s1, s2)
    
    print("🚀 Starting Network...")
    net.start()
    
    print("\n" + "="*45)
    print("✅ MITM TOPOLOGY READY")
    print(" h1 (Victim)   : 10.0.0.1  (connected to s1)")
    print(" h2 (Server)   : 10.0.0.2  (connected to s2)")
    print(" h3 (Attacker) : 10.0.0.3  (connected to s1)")
    print("="*45 + "\n")
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
