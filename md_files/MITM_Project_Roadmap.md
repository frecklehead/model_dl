# 🛡️ MITM Attack Detection with Flow Level Monitoring
## Complete Project Roadmap & Workflow Guide
### *A Teacher's Guide for Students*

---

> **Project Title:** Detection of Man-in-the-Middle (MITM) Attacks with Flow Level Monitoring  
> **Stack:** Garuda Linux · Mininet · Ryu Controller (Docker) · Python · CNN+LSTM Model  
> **Author:** Student Reference Document

---

## 📚 Table of Contents

1. [Big Picture — How Everything Connects](#1-big-picture)
2. [Your Project Folder Structure](#2-folder-structure)
3. [Python Files You Need](#3-python-files)
4. [Every-Session Setup Guide](#4-every-session-setup)
5. [Mininet Commands Reference](#5-mininet-commands)
6. [The Complete Workflow Explained](#6-complete-workflow)
7. [The Attack & Detection Story](#7-attack-and-detection-story)
8. [Building the ML Model](#8-building-the-ml-model)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Big Picture — How Everything Connects

Before touching any terminal, understand this diagram. This is the soul of your project.

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR LAPTOP                               │
│                                                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    MININET (Virtual Network)             │   │
│   │                                                          │   │
│   │   [h1 Victim]──┐                  ┌──[h2 Server]        │   │
│   │   10.0.0.1     │                  │  10.0.0.2           │   │
│   │                ▼                  ▼                      │   │
│   │              [s1]────────────[s2]                        │   │
│   │                ▲                                         │   │
│   │   [h3 Attacker]│                                         │   │
│   │   10.0.0.3     │                                         │   │
│   └────────────────┼─────────────────────────────────────────┘  │
│                    │ OpenFlow Protocol                            │
│                    ▼                                              │
│   ┌────────────────────────────────────┐                         │
│   │   RYU CONTROLLER (Docker)          │                         │
│   │   - Controls all switches          │                         │
│   │   - Monitors every packet          │                         │
│   │   - Detects ARP spoofing           │                         │
│   │   - Runs ML model (CNN+LSTM)       │──► 🚨 ALERT + BLOCK    │
│   └────────────────────────────────────┘                         │
│                    │                                              │
│                    ▼                                              │
│   ┌────────────────────────────────────┐                         │
│   │   ML MODEL (mitm_model.h5)         │                         │
│   │   Trained on MITM dataset          │                         │
│   │   CNN + LSTM architecture          │                         │
│   │   Input: flow statistics           │                         │
│   │   Output: MITM (1) or Normal (0)   │                         │
│   └────────────────────────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

### What Each Component Does

| Component | Tool | Job |
|-----------|------|-----|
| Virtual Network | Mininet | Simulates hosts, switches, links |
| SDN Brain | Ryu Controller | Controls switches via OpenFlow |
| Attacker | h3 host | Performs ARP poisoning MITM |
| Victim | h1 host | Sends login credentials |
| Server | h2 host | Runs login web page |
| Detection | Ryu + ML Model | Detects and blocks MITM |

---

## 2. Folder Structure

Set up your project exactly like this. Every file has a specific place.

```
~/Desktop/Mitm_detection/
│
├── 📄 my_controller.py          ← Ryu SDN controller (MITM detection brain)
├── 📄 topology.py               ← Mininet network topology
├── 📄 train_model.py            ← Train the CNN+LSTM ML model
├── 📄 test_model.py             ← Verify model works correctly
├── 📄 Dockerfile                ← Builds Ryu Docker image
│
├── 📁 scripts/                  ← Scripts that run ON Mininet hosts
│   ├── server_login.py          ← HTTP login server (runs on h2)
│   ├── victim_traffic.py        ← Victim sending credentials (runs on h1)
│   └── attacker_mitm.py         ← MITM attack script (runs on h3)
│
├── 📁 dataset/
│   └── mitm_dataset.csv         ← Your MITM dataset goes here
│
└── 📁 model/                    ← Created automatically after training
    ├── mitm_model.h5            ← Trained CNN+LSTM model
    ├── scaler.pkl               ← Feature scaler
    └── selected_features.pkl    ← Selected feature names
```

Create the folders:
```bash
cd ~/Desktop/Mitm_detection
mkdir -p scripts dataset model
```

---

## 3. Python Files You Need

Here is every Python file, what it does, and where it runs.

---

### 📄 `topology.py` — The Virtual Network

**What it does:** Creates the virtual network in Mininet with hosts, switches, and links.

**Where it runs:** Normal terminal (outside Mininet), with `sudo`.

```python
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    # Controller (Ryu running in Docker)
    c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    # Switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    # Hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')   # Victim
    h2 = net.addHost('h2', ip='10.0.0.2/24')   # Server
    h3 = net.addHost('h3', ip='10.0.0.3/24')   # Attacker

    # Links (who connects to what)
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(s1, s2)

    net.start()
    print("✅ Network started!")
    print("Hosts: h1=10.0.0.1 (victim)  h2=10.0.0.2 (server)  h3=10.0.0.3 (attacker)")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
```

---

### 📄 `my_controller.py` — The Ryu SDN Controller

**What it does:** Controls all switches. Monitors every packet. Detects ARP spoofing. Runs ML model to detect MITM.

**Where it runs:** Inside Docker container.

Key sections:
- `switch_features_handler` — called when a switch connects, installs default rules
- `_packet_in_handler` — called for EVERY packet, this is where detection happens
- `handle_arp` — checks if ARP is spoofed (IP→MAC mismatch)
- `handle_ip` — logs HTTP traffic and flow statistics
- `block_mac` — installs a DROP rule to block attacker

---

### 📄 `scripts/server_login.py` — The Login Server

**What it does:** Runs a fake bank login website on h2. Accepts username and password via HTTP POST. Logs all login attempts.

**Where it runs:** On h2 inside Mininet.

```python
# Quick version — save as /tmp/loginserver.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
        <html><body>
        <h2>SecureBank Login</h2>
        <form method='POST' action='/login'>
        Username: <input name='username'><br>
        Password: <input name='password' type='password'><br>
        <input type='submit' value='Login'>
        </form></body></html>""")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length).decode()
        params = parse_qs(body)
        user   = params.get('username', [''])[0]
        pwd    = params.get('password', [''])[0]
        print(f"[SERVER] LOGIN: user={user} pass={pwd} from={self.client_address[0]}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html><body><h2>Welcome!</h2></body></html>")

    def log_message(self, format, *args):
        pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
```

---

### 📄 `scripts/attacker_mitm.py` — The MITM Attacker

**What it does:** Performs a complete real MITM attack:
1. Enables IP forwarding (makes attack invisible)
2. ARP poisons victim — tells victim "I am the server"
3. ARP poisons server — tells server "I am the victim"
4. Sniffs all traffic flowing through
5. Steals and prints credentials

**Where it runs:** On h3 inside Mininet.

---

### 📄 `train_model.py` — ML Model Training

**What it does:** Loads your dataset, selects features using RF-RFE, balances data with SMOTE, trains CNN+LSTM model, saves model files.

**Where it runs:** Normal terminal (once, before demo).

---

## 4. Every-Session Setup Guide

**Every single time you sit down to work on this project, follow these steps IN ORDER.**

---

### 🔴 Step 0: Go to project folder

```bash
cd ~/Desktop/Mitm_detection
```

---

### 🔴 Step 1: Start Open vSwitch (OVS)

OVS is the virtual switch software that Mininet uses. Must be running before anything else.

```bash
sudo systemctl start ovsdb-server
sudo systemctl start ovs-vswitchd

# Verify it's running
sudo ovs-vsctl show
```

✅ You should see bridge information (s1, s2 etc.) or an empty database.

---

### 🔴 Step 2: Clean up old Mininet state

**ALWAYS do this before starting Mininet.** Old runs leave behind broken network interfaces that cause errors.

```bash
sudo mn -c
```

✅ You should see:
```
*** Removing excess controllers/daemons/namespaces
*** Cleanup complete
```

---

### 🔴 Step 3: Start Ryu Controller (Docker) — Terminal 1

Open a dedicated terminal for Ryu. Keep it open — this is your detection terminal.

```bash
cd ~/Desktop/Mitm_detection

sudo docker run -it --name ryu-container \
  --network host \
  -v $(pwd):/app \
  osrg/ryu \
  ryu-manager /app/my_controller.py
```

✅ You should see:
```
🛡️  MITM Detection Controller Started!
   ✅ ARP Spoof Detection: ON
   ✅ Flow Monitoring:     ON
```

⚠️ If container name conflict error:
```bash
sudo docker stop ryu-container
sudo docker rm ryu-container
# Then run docker run again
```

---

### 🔴 Step 4: Start Mininet — Terminal 2

Open a new terminal for Mininet.

```bash
cd ~/Desktop/Mitm_detection
sudo mn -c          # clean first always!
sudo python3 topology.py
```

✅ You should see in **Ryu terminal (Terminal 1)**:
```
✅ Switch connected: id=1
✅ Switch connected: id=2
```

And in **Mininet terminal (Terminal 2)**:
```
mininet>
```

---

### 🔴 Step 5: Verify everything works

```bash
# Inside Mininet CLI
mininet> nodes          # see all hosts and switches
mininet> dump           # see IPs of all hosts
mininet> pingall        # test all hosts can reach each other
```

✅ pingall should show **0% dropped**. If not, check Ryu is running.

---

### 🔴 Step 6: Copy scripts to /tmp

Mininet hosts access files from /tmp on your real system.

```bash
# In a normal terminal (outside Mininet)
cp ~/Desktop/Mitm_detection/scripts/server_login.py /tmp/
cp ~/Desktop/Mitm_detection/scripts/attacker_mitm.py /tmp/
cp ~/Desktop/Mitm_detection/scripts/victim_traffic.py /tmp/
```

---

## 5. Mininet Commands Reference

### 📌 Basic Commands

| Command | What it Does |
|---------|-------------|
| `nodes` | List all nodes (hosts + switches + controller) |
| `dump` | Show all nodes with their IP addresses |
| `pingall` | Test connectivity between ALL hosts |
| `links` | Show all network links |
| `net` | Show network connections |
| `exit` | Exit Mininet (stops network) |
| `quit` | Same as exit |
| `help` | Show all available commands |

---

### 📌 Host Commands

Every command on a host follows this pattern:
```
mininet> <hostname> <linux command>
```

| Command | What it Does |
|---------|-------------|
| `h1 ifconfig` | Show h1's network interfaces and IPs |
| `h1 ping h2` | Ping from h1 to h2 |
| `h1 ping 10.0.0.2 -c 4` | Ping with 4 packets only |
| `h1 arp -n` | Show h1's ARP table (IP to MAC mapping) |
| `h2 python3 /tmp/server.py &` | Start server on h2 in background |
| `h1 curl http://10.0.0.2:8080/` | h1 sends HTTP GET to h2 |
| `h1 curl -X POST http://10.0.0.2:8080/login -d "username=alice&password=secret"` | h1 sends login credentials |
| `h3 sysctl -w net.ipv4.ip_forward=1` | Enable IP forwarding on h3 |
| `h3 arpspoof -i h3-eth0 -t 10.0.0.1 10.0.0.2 &` | ARP poison h1 from h3 |
| `h3 tcpdump -i h3-eth0 -A port 8080` | Sniff HTTP traffic on h3 |
| `h1 ps aux` | Show running processes on h1 |
| `h2 kill %1` | Kill background job on h2 |

---

### 📌 The & Symbol

When you see `&` at the end of a command it means **run in background**. This lets you run multiple things at once:

```bash
mininet> h2 python3 /tmp/loginserver.py &   # starts server, returns to prompt
mininet> h1 ping h2 &                        # starts ping, returns to prompt
mininet> h3 arpspoof -i h3-eth0 -t 10.0.0.1 10.0.0.2 &  # starts attack, returns to prompt
```

---

### 📌 xterm — Open a Separate Window for a Host

This is very useful for demo — each host gets its own terminal window!

```bash
mininet> xterm h1 h2 h3
```

This opens 3 separate terminal windows, one for each host. You can then type commands directly in each window.

---

## 6. Complete Workflow Explained

### 🔵 Phase 1: Normal Traffic (Before Attack)

```
h1 (Victim)                    h2 (Server)
    │                               │
    │──── GET http://10.0.0.2 ─────►│
    │◄─── HTML login page ──────────│
    │                               │
    │──── POST username=alice ──────►│
    │     password=secret123        │
    │◄─── Welcome! ─────────────────│
    │                               │
    
Ryu sees: Normal ARP, normal flows, no anomalies
ML Model: Score < 0.5 → NORMAL ✅
```

---

### 🔴 Phase 2: MITM Attack Launched

```
BEFORE ATTACK:
h1 ARP table: 10.0.0.2 → aa:bb:cc (h2's real MAC) ✅

ATTACKER (h3) sends fake ARP packets:
→ Tells h1: "10.0.0.2 is at MY MAC (h3's MAC)"
→ Tells h2: "10.0.0.1 is at MY MAC (h3's MAC)"

AFTER ATTACK:
h1 ARP table: 10.0.0.2 → dd:ee:ff (h3's MAC!) ❌ POISONED
h2 ARP table: 10.0.0.1 → dd:ee:ff (h3's MAC!) ❌ POISONED
```

---

### 🔴 Phase 3: Traffic Interception

```
WITHOUT IP FORWARDING (bad attack — victim notices):
h1 ──► h3 (attacker)   [DEAD END — victim loses connection]

WITH IP FORWARDING (real invisible MITM):
h1 ──► h3 ──► h2       [h3 reads everything and forwards]
h2 ──► h3 ──► h1       [victim thinks connection is normal!]

h3 can now READ, MODIFY, or STEAL any data!
```

---

### 🟢 Phase 4: Detection by Ryu

```
Ryu Controller sees:
- ARP REPLY from h3 saying: "I am 10.0.0.2"
- BUT Ryu remembers: 10.0.0.2 was aa:bb:cc (h2's MAC)
- NOW h3 claims: 10.0.0.2 is dd:ee:ff
- MISMATCH DETECTED! → 🚨 ARP SPOOFING ALERT

Ryu installs a DROP rule:
- Any packet from dd:ee:ff (attacker MAC) → DROP
- Attacker is now BLOCKED from the network
```

---

### 🟢 Phase 5: ML Model Detection

```
Ryu collects flow statistics:
- Unusual flow asymmetry (3-way traffic instead of 2-way)
- Doubled packet inter-arrival times (extra hop through attacker)
- Abnormal byte/packet ratios

Sends to CNN+LSTM model:
- Model outputs score: 0.94 (above threshold 0.7)
- MITM DETECTED! → 🚨 ML ALERT
- Attacker IP blocked
```

---

## 7. The Attack & Detection Story

Here is the complete story of what happens during your demo, step by step.

---

### 🎬 Act 1: Setup (Before any attack)

**What you do:**
```bash
# Start server on h2
mininet> h2 python3 /tmp/loginserver.py &

# Victim browses normally
mininet> h1 curl http://10.0.0.2:8080/
```

**What Ryu terminal shows:**
```
[ARP] REQUEST | 10.0.0.1 → 10.0.0.2 | switch=1
[ARP] REPLY   | 10.0.0.2 (aa:bb:cc) → 10.0.0.1
✅ Normal traffic
```

**What this means:** Everything is normal. h1 knows h2's real MAC address. Communication is direct and private.

---

### 🎬 Act 2: Victim Logs In (Normal)

**What you do:**
```bash
mininet> h1 curl -X POST http://10.0.0.2:8080/login \
  -d "username=alice&password=secret123"
```

**What server (h2) shows:**
```
[SERVER] LOGIN: user=alice pass=secret123 from=10.0.0.1
```

**What Ryu shows:**
```
[HTTP] 10.0.0.1:54321 → 10.0.0.2:8080 | switch=1
✅ Normal flow
```

**What this means:** Login works. Server received credentials directly from victim. No interception.

---

### 🎬 Act 3: Attacker Launches MITM

**What you do:**
```bash
# Enable IP forwarding — makes attack INVISIBLE
mininet> h3 sysctl -w net.ipv4.ip_forward=1

# Poison h1: "I am h2"
mininet> h3 arpspoof -i h3-eth0 -t 10.0.0.1 10.0.0.2 &

# Poison h2: "I am h1"
mininet> h3 arpspoof -i h3-eth0 -t 10.0.0.2 10.0.0.1 &
```

**What Ryu terminal immediately shows:**
```
[ARP] REPLY | 10.0.0.2 (dd:ee:ff) → 10.0.0.1  ← SUSPICIOUS!

==================================================
🚨 ARP SPOOFING DETECTED! — MITM ATTACK IN PROGRESS!
   IP Address : 10.0.0.2
   Known MAC  : aa:bb:cc  ✅ (legitimate h2)
   Fake MAC   : dd:ee:ff  ❌ (ATTACKER h3!)
   Switch     : 1  Port: 3
   ACTION     : Blocking attacker MAC!
==================================================

🔒 BLOCKED MAC: dd:ee:ff — attacker traffic dropped!
```

**What this means:** Ryu caught the ARP spoofing instantly by comparing the new MAC with the one it remembered. The attacker is blocked.

---

### 🎬 Act 4: Verify the Attack and Detection

**Check victim's poisoned ARP table:**
```bash
mininet> h1 arp -n
```

You'll see:
```
Address     HWtype  HWaddress         Flags
10.0.0.2    ether   dd:ee:ff:xx:xx:xx  C    ← h3's MAC! POISONED
```

**Check attacker is blocked:**

```bash
# Try to ping from attacker — should fail now
mininet> h3 ping 10.0.0.1 -c 3
```

You'll see: `100% packet loss` — attacker is blocked! ✅

---

## 8. Building the ML Model

The ML model adds a second layer of detection on top of rule-based detection.

### Why Two Layers?

| Layer | Method | Detects |
|-------|--------|---------|
| Layer 1 | Rule-based (ARP table) | ARP spoofing instantly |
| Layer 2 | CNN+LSTM ML model | Complex flow-level anomalies |

The ML model catches attacks that don't show obvious ARP spoofing — like sophisticated MITM that uses other techniques.

---

### Step 1: Prepare your dataset

Place your CSV dataset in:
```bash
~/Desktop/Mitm_detection/dataset/mitm_dataset.csv
```

Check it has a `Label` column with values like `Normal` and `Attack` (or `MITM`).

---

### Step 2: Train the model

```bash
cd ~/Desktop/Mitm_detection
python3 train_model.py
```

After training you should see:
```
✅ Test Accuracy: 0.9800
✅ Model saved to model/mitm_model.h5
✅ Scaler saved to model/scaler.pkl
```

---

### Step 3: Verify model works

```bash
python3 test_model.py
```

Output:
```
✅ Model loaded successfully
Normal traffic score: 0.12 → Normal ✅
Attack traffic score: 0.94 → MITM ⚠️
```

---

### Step 4: Model is automatically loaded by Ryu controller

Once `model/mitm_model.h5` exists, `my_controller.py` loads it automatically on startup:
```
✅ ML model files found — ML detection ENABLED
✅ ML Model loaded successfully!
```

---

### CNN+LSTM Architecture (From the Research Paper)

```
Input Features (flow statistics)
         │
         ▼
┌─────────────────┐
│   Conv1D (64)   │  ← Extracts local patterns from flow data
│   ReLU          │
│   MaxPooling    │
└────────┬────────┘
         │
┌────────▼────────┐
│   Conv1D (128)  │  ← Extracts deeper patterns
│   ReLU          │
│   MaxPooling    │
└────────┬────────┘
         │
┌────────▼────────┐
│   LSTM (64)     │  ← Captures temporal/sequential patterns
│   Dropout 0.3   │
└────────┬────────┘
         │
┌────────▼────────┐
│   Dense (64)    │  ← Final decision layer
│   Dropout 0.2   │
└────────┬────────┘
         │
┌────────▼────────┐
│   Dense (1)     │  ← Output: 0=Normal, 1=MITM
│   Sigmoid       │
└─────────────────┘
```

---

## 9. Troubleshooting

### ❌ `sudo mn -c` — Always run this if Mininet crashes

```bash
sudo mn -c
```

---

### ❌ Docker container name conflict

```bash
sudo docker stop ryu-container
sudo docker rm ryu-container
# Then start again
```

---

### ❌ Ryu shows "loading app" but exits immediately

Your controller has an error. Check:
```bash
sudo docker run -it --network host \
  -v $(pwd):/app osrg/ryu \
  ryu-manager --verbose /app/my_controller.py
```

---

### ❌ pingall fails (packets dropped)

```bash
# Check OVS is running
sudo systemctl status ovsdb-server
sudo systemctl status ovs-vswitchd

# Check Ryu is connected to switches
sudo ovs-vsctl show
# Look for: is_connected: true
```

---

### ❌ arpspoof not found

```bash
# Install in normal terminal
sudo pacman -S dsniff

# Verify
which arpspoof
```

---

### ❌ Port already in use

```bash
# Inside Mininet
mininet> h2 fuser -k 8080/tcp
mininet> h2 python3 /tmp/loginserver.py &
```

---

### ❌ Address already in use (socket error)

```bash
sudo mn -c
sudo systemctl restart ovsdb-server
sudo systemctl restart ovs-vswitchd
```

---

## 🚀 Quick Start Cheatsheet

Print this and keep it on your desk!

```
EVERY SESSION — DO IN ORDER:
─────────────────────────────────────────────────────
1. cd ~/Desktop/Mitm_detection

2. sudo systemctl start ovsdb-server ovs-vswitchd

3. sudo mn -c

4. [Terminal 1 - Ryu]
   sudo docker stop ryu-container; sudo docker rm ryu-container
   sudo docker run -it --name ryu-container \
     --network host -v $(pwd):/app \
     osrg/ryu ryu-manager /app/my_controller.py

5. [Terminal 2 - Mininet]
   sudo mn -c
   sudo python3 topology.py

6. Inside Mininet:
   mininet> pingall              ← verify 0% dropped

7. Copy scripts:
   cp scripts/* /tmp/

DEMO SEQUENCE:
─────────────────────────────────────────────────────
mininet> h2 python3 /tmp/loginserver.py &
mininet> h1 curl http://10.0.0.2:8080/              ← normal
mininet> h1 curl -X POST http://10.0.0.2:8080/login \
           -d "username=alice&password=secret123"   ← login
mininet> h3 sysctl -w net.ipv4.ip_forward=1         ← attack step 1
mininet> h3 arpspoof -i h3-eth0 -t 10.0.0.1 10.0.0.2 &  ← attack step 2
mininet> h3 arpspoof -i h3-eth0 -t 10.0.0.2 10.0.0.1 &  ← attack step 3
mininet> h1 arp -n                                  ← verify poisoning
mininet> h1 curl -X POST http://10.0.0.2:8080/login \
           -d "username=alice&password=secret123"   ← credentials stolen!
                                                    ← watch Ryu detect it!
─────────────────────────────────────────────────────
EXPECTED RYU OUTPUT:
🚨 ARP SPOOFING DETECTED! — MITM ATTACK IN PROGRESS!
🔒 BLOCKED MAC: xx:xx:xx:xx:xx:xx
```

---

*Document prepared for Minor Project: Detection of MITM Attacks with Flow Level Monitoring*  
*Stack: Garuda Linux · Mininet · Ryu (Docker) · Python · CNN+LSTM*

