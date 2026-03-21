import subprocess
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

CONTROLLER_IP   = '127.0.0.1'
CONTROLLER_PORT = 6633

def _force_ovs_connect(switches):
    """
    Explicitly configure every OVS bridge to use OpenFlow13 and point it at
    the Ryu controller.  This bypasses Mininet's Python-API layer and writes
    directly into the OVS database, which is the only reliable way to make
    OVS reconnect after stale state from previous runs.
    """
    target = f'tcp:{CONTROLLER_IP}:{CONTROLLER_PORT}'
    for sw in switches:
        name = sw.name
        # Force OpenFlow 1.3 — without this OVS may negotiate OF10 and Ryu
        # (which only accepts OF13) will silently drop the connection.
        subprocess.call(['ovs-vsctl', 'set', 'bridge', name,
                         'protocols=OpenFlow13'], stderr=subprocess.DEVNULL)
        # Secure fail-mode: switch waits for controller instead of going
        # standalone (standalone mode means packets are forwarded without
        # hitting Ryu, so detection never fires).
        subprocess.call(['ovs-vsctl', 'set-fail-mode', name, 'secure'],
                        stderr=subprocess.DEVNULL)
        # Explicitly set the controller address — overwrites any stale entry.
        subprocess.call(['ovs-vsctl', 'set-controller', name, target],
                        stderr=subprocess.DEVNULL)
        print(f'  [OVS] {name}: controller={target}  proto=OpenFlow13  fail-mode=secure')

def _wait_for_controller(timeout=10):
    """
    Block until Ryu is actually listening on port 6633 (up to `timeout` secs).
    Avoids the race where OVS tries to connect before Ryu is ready.
    """
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT), timeout=1)
            s.close()
            print(f'  [OK] Ryu controller reachable at {CONTROLLER_IP}:{CONTROLLER_PORT}')
            return True
        except OSError:
            time.sleep(0.5)
    print(f'  [WARN] Ryu not reachable at {CONTROLLER_IP}:{CONTROLLER_PORT} after {timeout}s — continuing anyway.')
    return False

def create_topology():
    # ── Wait for Ryu before building the network ──────────────────────────
    print('Waiting for Ryu controller ...')
    _wait_for_controller(timeout=15)

    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    print('Connecting to Remote Controller at 127.0.0.1:6633...')
    c0 = net.addController('c0', ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    print('Adding 2 Switches (s1, s2)...')
    s1 = net.addSwitch('s1', protocols='OpenFlow13', failMode='secure')
    s2 = net.addSwitch('s2', protocols='OpenFlow13', failMode='secure')

    print('Adding 3 Hosts (h1-Victim, h2-Server, h3-Attacker)...')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

    print('Connecting Hosts to Switches...')
    net.addLink(h1, s1)
    net.addLink(h3, s1)
    net.addLink(h2, s2)

    print('Connecting Switch 1 to Switch 2...')
    net.addLink(s1, s2)

    print('Starting Network...')
    net.start()

    # ── Force OVS to connect using correct protocol ────────────────────────
    # This is the permanent fix: Mininet's Python API does not always write
    # these settings into the live OVS database, especially after dirty
    # shutdowns.  Calling ovs-vsctl directly guarantees the connection.
    print('Forcing OVS switch controller registration...')
    _force_ovs_connect([s1, s2])

    # Give OVS a moment to establish the TCP connection to Ryu
    time.sleep(2)

    print('\n' + '='*45)
    print('MITM TOPOLOGY READY')
    print(' h1 (Victim)   : 10.0.0.1  (connected to s1)')
    print(' h2 (Server)   : 10.0.0.2  (connected to s2)')
    print(' h3 (Attacker) : 10.0.0.3  (connected to s1)')
    print('='*45 + '\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
