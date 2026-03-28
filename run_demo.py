#!/usr/bin/env python3
"""
run_demo.py  —  MITM Detection Demo  (interactive attack menu)
Usage: sudo python3 run_demo.py

Run ryu-manager my_controller.py in a separate terminal first.
Each attack is triggered individually so Ryu output stays readable.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time, os, shutil, subprocess, socket

_HERE       = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(_HERE, 'scripts')

# ── ANSI colours ──────────────────────────────────────────────────────────────
RD = '\033[91m'   # red
GR = '\033[92m'   # green
YL = '\033[93m'   # yellow
CY = '\033[96m'   # cyan
BD = '\033[1m'    # bold
DM = '\033[2m'    # dim
RS = '\033[0m'    # reset

W  = 66           # display width

# ── Print helpers ─────────────────────────────────────────────────────────────
def _ok(msg):     print(f'  {GR}{BD}[ OK ]{RS}  {msg}')
def _fail(msg):   print(f'  {RD}{BD}[FAIL]{RS}  {msg}')
def _warn(msg):   print(f'  {YL}{BD}[WARN]{RS}  {msg}')
def _info(msg):   print(f'  {CY}[....]{RS}  {msg}')
def _step(n, t, msg): print(f'\n  {CY}{BD}[{n}/{t}]{RS}  {msg}')

def _hline(ch='─'):
    print(ch * W)

def _banner(title, color=CY):
    print()
    print(color + BD + '═' * W + RS)
    pad = (W - len(title) - 2) // 2
    print(color + BD + ' ' * pad + '  ' + title + RS)
    print(color + BD + '═' * W + RS)

def _section(title, color=CY):
    print()
    print(color + '┌' + '─' * (W - 2) + '┐' + RS)
    print(color + '│' + RS + f'  {BD}{title}{RS}' +
          ' ' * (W - 4 - len(title)) + color + '│' + RS)
    print(color + '└' + '─' * (W - 2) + '┘' + RS)

def _result_header():
    print()
    print(GR + BD + '┌' + '─' * (W - 2) + '┐' + RS)
    print(GR + BD + '│' + '  DETECTION RESULTS' +
          ' ' * (W - 21) + '│' + RS)
    print(GR + BD + '└' + '─' * (W - 2) + '┘' + RS)

def _row(label, value, vcolor=RS):
    print(f'  {CY}{label:<22}{RS}{vcolor}{value}{RS}')

def _tail(host, path, lines=8):
    """Read last N lines from a log file safely (strips binary via `strings`)."""
    out = host.cmd(
        f'tail -{lines} {path} 2>/dev/null | strings || echo "(no output yet)"'
    )
    for line in out.strip().splitlines():
        print(f'    {DM}│{RS}  {line}')

def _countdown(seconds, label, color=YL):
    """Animated single-line progress bar during the attack window."""
    bw = 24
    for i in range(seconds, 0, -1):
        filled = int(bw * (seconds - i) / seconds)
        bar  = GR + '█' * filled + RS + DM + '░' * (bw - filled) + RS
        pct  = int(100 * (seconds - i) / seconds)
        line = (f'  {color}[{bar}{color}]  '
                f'{BD}{i:2d}s{RS}  {label}  '
                f'{DM}→ watch Ryu for [ALERT]{RS}')
        print(line, end='\r', flush=True)
        time.sleep(1)
    print(' ' * W, end='\r')   # clear line

# ── Topology ──────────────────────────────────────────────────────────────────
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

# ── Setup helpers ─────────────────────────────────────────────────────────────
def deploy_scripts():
    _info('Deploying attack scripts to /tmp ...')
    for fname in ['attacker_mitm.py', 'victim_traffic.py', 'server_login.py',
                  'ssl_strip.py', 'session_hijack.py']:
        src = os.path.join(SCRIPTS_DIR, fname)
        dst = f'/tmp/{fname}'
        if os.path.exists(src):
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            print(f'         {GR}✔{RS}  {fname}')
        else:
            print(f'         {RD}✘{RS}  MISSING: {src}')

def wait_for_ryu_port(port=6633, timeout=30):
    _info(f'Checking Ryu is listening on port {port} ...')
    for i in range(timeout):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                _ok(f'Ryu controller is up on port {port}')
                return True
        except OSError:
            if i == 0:
                _warn(f'Ryu not ready — waiting up to {timeout}s ...')
            if i % 5 == 4:
                print(f'         {DM}... {i+1}s  (ryu-manager my_controller.py?){RS}')
        time.sleep(1)
    _fail(f'Ryu not found on :{port} after {timeout}s')
    return False

def _ovs_get(field, target='s1'):
    r = subprocess.run(['ovs-vsctl', 'get', 'controller', target, field],
                       capture_output=True, text=True)
    return r.stdout.strip().lower()

def wait_for_controller(timeout=15):
    _info(f'Waiting for switch → Ryu connection (up to {timeout}s) ...')
    for i in range(timeout):
        try:
            if 'true' in _ovs_get('is_connected'):
                _ok(f'Switch s1 connected to Ryu  ({i}s elapsed)')
                return True
        except Exception:
            pass
        time.sleep(1)
    _fail('Switch did not connect within timeout')
    return False

def wait_for_flows(timeout=20):
    _info(f'Waiting for Ryu to push OpenFlow rules (up to {timeout}s) ...')
    for i in range(timeout):
        r = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                           capture_output=True, text=True)
        n = r.stdout.count('cookie=')
        if n > 0:
            _ok(f'{n} flow rule(s) installed by Ryu')
            return True
        time.sleep(1)
    _warn('No flows after timeout — forwarding may fail')
    return False

def check_ping(src_host, dst_ip, label, retries=3):
    for _ in range(retries):
        r = src_host.cmd(f'ping -c 2 -W 2 {dst_ip}')
        if '1 received' in r or '2 received' in r:
            _ok(f'{label}: reachable')
            return True
        time.sleep(2)
    _fail(f'{label}: UNREACHABLE after {retries} attempts')
    return False

def cleanup_orphans():
    _info('Cleaning up leftover processes from previous runs ...')
    for name in ['attacker_mitm', 'ssl_strip', 'session_hijack',
                 'victim_traffic', 'server_login']:
        subprocess.run(['pkill', '-f', f'{name}.py'], capture_output=True)
    subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', 's1'],
                   capture_output=True)
    subprocess.run(['ovs-vsctl', 'del-controller', 's1'], capture_output=True)

# ── Attack utilities ──────────────────────────────────────────────────────────
def _stop_attacks():
    for name in ['attacker_mitm', 'ssl_strip', 'session_hijack', 'victim_traffic']:
        subprocess.run(['pkill', '-f', f'{name}.py'], capture_output=True)
    time.sleep(1)

def _reset_arp(victim, server, attacker, device1, device2):
    _info('Flushing poisoned ARP caches ...')
    for h in [victim, server, attacker, device1, device2]:
        h.cmd('ip neigh flush all 2>/dev/null')
    for host, dst in [(victim, '10.0.0.2'), (victim, '10.0.0.100'),
                      (server, '10.0.0.1'), (attacker, '10.0.0.1'),
                      (attacker, '10.0.0.2')]:
        host.cmd(f'ping -c 1 -W 1 {dst} > /dev/null 2>&1')
    time.sleep(1)
    _ok('ARP tables reset and re-warmed')

def _attack_header(num, title, lines, host_label, alert_label):
    """Print a coloured attack banner."""
    print()
    print(RD + BD + '╔' + '═' * (W - 2) + '╗' + RS)
    atk = f'  ATTACK {num}  ──  {title}'
    print(RD + BD + '║' + atk + ' ' * (W - 2 - len(atk)) + '║' + RS)
    print(RD + BD + '╠' + '═' * (W - 2) + '╣' + RS)
    for line in lines:
        l = f'  {line}'
        print(RD + '║' + RS + l + ' ' * (W - 2 - len(l)) + RD + '║' + RS)
    # blank row
    print(RD + '║' + ' ' * (W - 2) + '║' + RS)
    host_line = f'  Attacker host  :  {host_label}'
    print(RD + '║' + RS + host_line + ' ' * (W - 2 - len(host_line)) + RD + '║' + RS)
    alert_line = f'  Watch Ryu for  :  [ALERT] {alert_label}'
    print(RD + '║' + RS + YL + BD + alert_line + RS + ' ' * (W - 2 - len(alert_line)) + RD + '║' + RS)
    print(RD + BD + '╚' + '═' * (W - 2) + '╝' + RS)

# ── ATTACK 1 — ARP Poisoning MITM ────────────────────────────────────────────
def attack_arp(victim, server, attacker, device1, device2):
    _attack_header(
        1, 'ARP Poisoning MITM',
        [
            'Attacker broadcasts forged ARP replies to victim:',
            '  "The server (10.0.0.2) is at MY MAC address"',
            'Victim updates its ARP table and routes ALL traffic through attacker.',
            'Attacker relays packets to real server while intercepting credentials.',
        ],
        'attacker  10.0.0.100',
        'ARP POISONING  (ML model,  score >= 0.5)'
    )

    _stop_attacks()
    _reset_arp(victim, server, attacker, device1, device2)

    _step(1, 3, 'Generating victim traffic (credentials flowing to server) ...')
    # Three parallel streams so the ML has rich multi-flow data to score
    for i in range(3):
        victim.cmd(f'python3 /tmp/victim_traffic.py 10.0.0.2 '
                   f'> /tmp/victim_output{i}.txt 2>&1 &')
    time.sleep(3)

    _step(2, 3, 'Enabling IP forwarding on attacker and launching ARP poison ...')
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    attacker.cmd('iptables -F; iptables -t nat -F; iptables -P FORWARD ACCEPT')
    attacker.cmd('python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0 '
                 '> /tmp/attacker_output.txt 2>&1 &')
    # Script waits 5s internally before relay_flood starts; wait 7s so the
    # victim ARP table is already poisoned when we print it.
    time.sleep(7)

    arp_out = victim.cmd('arp -n')
    poisoned = '00:00:00:00:00:03' in arp_out
    print()
    _row('Victim 10.0.0.2 entry:', '00:00:00:00:00:03 (ATTACKER)' if poisoned
         else 'still original MAC', GR + BD if poisoned else RD)
    for line in arp_out.strip().splitlines():
        print(f'    {DM}{line}{RS}')

    _step(3, 3, 'Detection window active — 40 seconds ...')
    print(f'  {DM}  relay_flood + RST injection + SSL RST all running inside attacker_mitm{RS}')
    _countdown(40, 'ARP Poisoning', RD)

    # ── Results ───────────────────────────────────────────────────────────────
    _result_header()
    arp_final = victim.cmd('arp -n')
    confirmed = '00:00:00:00:00:03' in arp_final
    _row('ARP poisoning:', 'CONFIRMED' if confirmed else 'not visible', GR + BD if confirmed else YL)

    print()
    print(f'  {CY}Victim ARP table:{RS}')
    for line in arp_final.strip().splitlines():
        print(f'    {line}')

    stolen = attacker.cmd('cat /tmp/mitm_stolen.txt 2>/dev/null | strings')
    if 'username' in stolen or 'password' in stolen:
        print()
        print(f'  {RD}{BD}CREDENTIALS INTERCEPTED:{RS}')
        for line in stolen[:500].splitlines():
            print(f'    {YL}{line}{RS}')
    else:
        print()
        print(f'  {CY}Attacker relay log (last 8 lines):{RS}')
        _tail(attacker, '/tmp/attacker_output.txt')

    print()
    print(f'  {YL}→ Check the Ryu terminal for the full [ALERT] and ML score.{RS}')

    _stop_attacks()
    print()
    input(f'  {DM}Press Enter to return to menu ...{RS}')

# ── ATTACK 2 — SSL Stripping ──────────────────────────────────────────────────
def attack_ssl(victim, server, attacker, device1, device2):
    _attack_header(
        2, 'SSL Stripping',
        [
            'device1 injects TCP RST packets into the victim\'s TLS handshake',
            '  on port 443, forcing the connection to terminate.',
            'Then relays the session over plain HTTP (port 80) — unencrypted.',
            'Controller sees: TCP dst_port=443 with RST ratio > 0.15.',
        ],
        'device1   10.0.0.11',
        'SSL STRIPPING  (ML + rule-based fallback)'
    )

    _stop_attacks()

    _step(1, 2, 'Sending victim HTTPS traffic toward server:443 ...')
    victim.cmd('curl -sk https://10.0.0.2:443/ > /dev/null 2>&1 &')
    time.sleep(1)

    _step(2, 2, 'Launching SSL strip attack from device1 ...')
    device1.cmd('python3 /tmp/ssl_strip.py 10.0.0.2 '
                '> /tmp/ssl_strip_output.txt 2>&1 &')

    print()
    _countdown(22, 'SSL Stripping', RD)

    _result_header()
    print(f'  {CY}device1 activity log:{RS}')
    _tail(device1, '/tmp/ssl_strip_output.txt')
    print()
    print(f'  {YL}→ Check the Ryu terminal for [ALERT] SSL STRIPPING.{RS}')

    _stop_attacks()
    print()
    input(f'  {DM}Press Enter to return to menu ...{RS}')

# ── ATTACK 3 — Session Hijacking ──────────────────────────────────────────────
def attack_session_hijack(victim, server, attacker, device1, device2):
    _attack_header(
        3, 'Session Hijacking (RST Injection)',
        [
            'device2 injects spoofed RST+ACK packets into the live TCP',
            '  session between victim and server.',
            'Victim\'s connection is torn down; device2 takes over the session.',
            'Controller sees: RST ratio > 0.15  AND  ACK count > 5.',
        ],
        'device2   10.0.0.12',
        'SESSION HIJACKING  (ML + rule-based fallback)'
    )

    _stop_attacks()

    _step(1, 2, 'Starting victim traffic — creates the live session to hijack ...')
    victim.cmd('python3 /tmp/victim_traffic.py 10.0.0.2 '
               '> /tmp/victim_output.txt 2>&1 &')
    time.sleep(3)

    _step(2, 2, 'Launching RST injection from device2 ...')
    device2.cmd('python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2 device2-eth0 '
                '> /tmp/session_hijack_output.txt 2>&1 &')

    print()
    _countdown(22, 'Session Hijacking', RD)

    _result_header()
    print(f'  {CY}device2 injection log:{RS}')
    _tail(device2, '/tmp/session_hijack_output.txt')
    print()
    print(f'  {YL}→ Check the Ryu terminal for [ALERT] SESSION HIJACKING.{RS}')

    _stop_attacks()
    print()
    input(f'  {DM}Press Enter to return to menu ...{RS}')

# ── ATTACK 4 — DNS Hijacking ──────────────────────────────────────────────────
def attack_dns(victim, server, attacker, device1, device2):
    _attack_header(
        4, 'DNS Hijacking',
        [
            'Attacker sends two spoofed DNS responses for  "test.local":',
            '   Response A  →  10.0.0.2  (real server)',
            '   Response B  →  10.0.0.99 (fake/attacker-controlled host)',
            'Controller detects same domain resolving to two different IPs.',
        ],
        'attacker  10.0.0.100',
        'DNS HIJACKING  (rule-based detection)'
    )

    _stop_attacks()

    _step(1, 1, 'Launching DNS spoofing from attacker ...')
    attacker.cmd('python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0 '
                 '> /tmp/attacker_output.txt 2>&1 &')
    # dns_hijack_loop prints a status line every ~22s; give it 30s to log at least once
    print(f'  {DM}  (DNS spoof loop fires every 2s; status line printed every ~22s){RS}')

    print()
    _countdown(30, 'DNS Hijacking', RD)

    _result_header()
    print(f'  {CY}Attacker activity log (last 10 lines):{RS}')
    _tail(attacker, '/tmp/attacker_output.txt', lines=10)
    print()
    print(f'  {CY}Packets sent per loop:{RS}')
    print(f'    Response A  test.local → {GR}10.0.0.2{RS}  (real server)')
    print(f'    Response B  test.local → {RD}10.0.0.99{RS} (fake host — triggers alert)')
    print()
    print(f'  {YL}→ Check the Ryu terminal for [ALERT] DNS HIJACKING.{RS}')

    _stop_attacks()
    print()
    input(f'  {DM}Press Enter to return to menu ...{RS}')

# ── Attack registry ───────────────────────────────────────────────────────────
ATTACKS = [
    ('1', 'ARP Poisoning MITM',        attack_arp),
    ('2', 'SSL Stripping',              attack_ssl),
    ('3', 'Session Hijacking',          attack_session_hijack),
    ('4', 'DNS Hijacking',              attack_dns),
]

# ── Interactive menu ──────────────────────────────────────────────────────────
def attack_menu(net, victim, server, attacker, device1, device2):
    hosts = (victim, server, attacker, device1, device2)

    while True:
        print()
        print(CY + BD + '╔' + '═' * (W - 2) + '╗' + RS)
        title = 'MITM ATTACK DETECTION SYSTEM  —  LIVE DEMONSTRATION'
        pad = (W - 2 - len(title)) // 2
        print(CY + BD + '║' + ' ' * pad + title + ' ' * (W - 2 - pad - len(title)) + '║' + RS)
        sub = 'SDN + OpenFlow13  |  ML Model (CNN+LSTM)  |  Rule-Based Fallback'
        pad2 = (W - 2 - len(sub)) // 2
        print(CY + '║' + ' ' * pad2 + sub + ' ' * (W - 2 - pad2 - len(sub)) + '║' + RS)
        print(CY + BD + '╠' + '═' * (W - 2) + '╣' + RS)

        def mrow(label, value):
            l = f'  {label:<12}{value}'
            print(CY + '║' + RS + l + ' ' * (W - 2 - len(l)) + CY + '║' + RS)

        mrow('victim',   '10.0.0.1    →  target host sending credentials')
        mrow('server',   '10.0.0.2    →  SecureBank login server  (:8080)')
        mrow('attacker', '10.0.0.100  →  malicious host  (ARP + DNS)')
        mrow('device1',  '10.0.0.11   →  SSL stripping attacker')
        mrow('device2',  '10.0.0.12   →  session hijacking attacker')
        print(CY + BD + '╠' + '═' * (W - 2) + '╣' + RS)

        attacks_display = [
            ('1', 'ARP Poisoning MITM',      'intercepts all victim ↔ server traffic'),
            ('2', 'SSL Stripping',            'downgrades HTTPS to unencrypted HTTP'),
            ('3', 'Session Hijacking',        'RST injection seizes live TCP session'),
            ('4', 'DNS Hijacking',            'spoofs domain → fake IP resolution'),
        ]
        def arow(key, name, desc):
            l = f'  [{key}]  {name:<26}{DM}{desc}{RS}'
            llen = 6 + len(name) + 26 + len(desc) - len(name) + 2
            # just print it; width calculation gets messy with escape codes
            print(CY + '║' + RS + f'  {YL}{BD}[{key}]{RS}  {BD}{name:<26}{RS}{DM}{desc}{RS}')

        for k, n, d in attacks_display:
            arow(k, n, d)
        print(CY + '║' + RS)
        print(CY + '║' + RS + f'  {DM}[a]  Run all 4 attacks sequentially{RS}')
        print(CY + '║' + RS + f'  {DM}[r]  Reset state  (flush ARP + stop attacks){RS}')
        print(CY + '║' + RS + f'  {DM}[c]  Open Mininet CLI{RS}')
        print(CY + '║' + RS + f'  {DM}[x]  Exit demo{RS}')
        print(CY + BD + '╚' + '═' * (W - 2) + '╝' + RS)
        print()

        choice = input(f'  {BD}Select attack {CY}[1/2/3/4/a/r/c/x]{RS}  > ').strip().lower()

        if choice in ('1', '2', '3', '4'):
            _, _, fn = next(e for e in ATTACKS if e[0] == choice)
            fn(*hosts)

        elif choice == 'a':
            print(f'\n  {YL}Running all 4 attacks sequentially.{RS}')
            for _, name, fn in ATTACKS:
                fn(*hosts)
            print(f'\n  {GR}{BD}All 4 attacks complete.{RS}')

        elif choice == 'r':
            print()
            _stop_attacks()
            _reset_arp(*hosts)
            _ok('State reset — ready for next attack')

        elif choice == 'c':
            print(f'  {DM}Opening Mininet CLI — type "exit" to return to menu.{RS}\n')
            CLI(net)

        elif choice == 'x':
            print(f'\n  {DM}Stopping all attacks and shutting down ...{RS}')
            _stop_attacks()
            break

        else:
            print(f'  {YL}Unknown choice — enter 1, 2, 3, 4, a, r, c, or x.{RS}')

# ── Main ──────────────────────────────────────────────────────────────────────
def run_demo():
    _banner('MITM DETECTION SYSTEM  —  INITIALISING')

    cleanup_orphans()

    ryu_up = wait_for_ryu_port(port=6633, timeout=30)
    if not ryu_up:
        _fail('Aborting — start ryu-manager my_controller.py first, then re-run.')
        return

    _info('Building Mininet topology ...')
    net = create_topology()
    net.start()
    subprocess.run(['ovs-vsctl', 'set', 'controller', 's1', 'max_backoff=1000'],
                   capture_output=True)

    victim   = net.get('victim')
    server   = net.get('server')
    attacker = net.get('attacker')
    device1  = net.get('device1')
    device2  = net.get('device2')

    deploy_scripts()

    ctrl_ok = wait_for_controller(timeout=15)
    if ctrl_ok:
        wait_for_flows(timeout=20)
    else:
        _warn('Continuing without confirmed controller — attacks may fail.')

    # ARP warm-up
    _info('Warming ARP caches across all hosts ...')
    for host, dst in [(victim,   '10.0.0.2'),  (victim,   '10.0.0.100'),
                      (server,   '10.0.0.1'),  (server,   '10.0.0.100'),
                      (attacker, '10.0.0.1'),  (attacker, '10.0.0.2')]:
        host.cmd(f'ping -c 2 -W 2 {dst} > /dev/null 2>&1')
    time.sleep(2)

    if not check_ping(victim, '10.0.0.2', 'victim → server'):
        _fail('Connectivity broken — opening Mininet CLI for diagnosis.')
        print(os.popen('ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null').read()[:800])
        CLI(net)
        net.stop()
        return

    # Login server
    _info('Starting SecureBank login server on server:8080 ...')
    server.cmd('fuser -k 8080/tcp 2>/dev/null; sleep 1')
    server.cmd('python3 /tmp/server_login.py > /tmp/server_output.txt 2>&1 &')
    time.sleep(3)
    test = victim.cmd('curl -s --connect-timeout 5 http://10.0.0.2:8080/')
    if 'SecureBank' in test or 'Login' in test:
        _ok('SecureBank login server reachable from victim')
    else:
        _warn(f'Unexpected server response: {test[:80]}')

    # Baseline
    _info('Sending 5s of normal baseline traffic (establishes Ryu flow baselines) ...')
    victim.cmd('curl -s http://10.0.0.2:8080/ > /dev/null &')
    victim.cmd('curl -s -X POST http://10.0.0.2:8080/login '
               '-d "username=alice&password=secret123" > /dev/null &')
    device1.cmd('ping -c 10 10.0.0.2 > /dev/null &')
    time.sleep(5)
    _ok('Baseline traffic done — Ryu ML model has normal-traffic context')

    print()
    print(f'  {GR}{BD}Setup complete!{RS}  Launching attack menu ...')
    time.sleep(1)

    attack_menu(net, victim, server, attacker, device1, device2)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_demo()
