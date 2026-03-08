# 🛡️ MITM Detection Demo Guide

This guide details exactly how to run your MITM Detection Demo for your college project presentation.

## 🚀 1. Setup Phase (Do this BEFORE the demo starts)

**Step 1: Clean and Build Docker**
```bash
# Stop old containers
docker compose down
plots/
# Build fresh image
docker compose up -d --build
```

**Step 2: Start Ryu Controller**
Open **Terminal 1** and run:
```bash
# Enter the container

docker exec -it ryu-mitm /bin/bash

# Inside container:
ryu-manager my_controller.py
```
*You should see:* `MITM DETECTION CONTROLLER v1.0` and `ML Model Loaded Successfully`.

**Step 3: Start Mininet Topology**
Open **Terminal 2** and run:
```bash
# Setup scripts first (creates /tmp copies)
bash setup.sh

# Start Mininet
sudo python3 run_demo.py
```
*You should see:* Mininet starting and eventually `DEMO COMPLETE — Opening interactive CLI`.

---

## 🎬 2. The Live Demonstration

### **Phase A: Show Normal Traffic**
*Examiner Script: "First, I will demonstrate normal network behavior where the victim communicates safely with the bank server."*

1. **Terminal 2 (Mininet CLI):**
   ```bash
   # Check initial ARP table (should look normal)
   victim arp -n
   ```
   *Show:* `10.0.0.2` maps to the correct Server MAC (`00:00:00:00:02:01`).

2. **Terminal 3 (Victim):**
   ```bash
   # Start the victim user simulation
   victim python3 /tmp/victim_traffic.py 10.0.0.2
   ```
   *Show:* "Login successful" messages. Point out green logs in **Terminal 1 (Ryu)** showing `NORMAL ✅`.

---

### **Phase B: Launch the Attack**
*Examiner Script: "Now, the attacker enters the network and performs an ARP Spoofing Man-in-the-Middle attack."*

1. **Terminal 4 (Attacker):**
   ```bash
   # Start the MITM attack script (Victim=10.0.0.1 Server=10.0.0.2)
   attacker python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2
   ```
   *Show:* `🔴 ARP poisoning victim...` and `🔴 ARP poisoning server...`.

2. **Terminal 5 (Observer):**
   ```bash
   # Watch stolen credentials appear live
   watch -n 1 "cat /tmp/mitm_stolen.txt"
   ```
   *Show:* Wait for the Victim script to login again. You will see:
   `🎯 CREDENTIALS CAPTURED: user=alice pass=secret123`

3. **Terminal 2 (Mininet CLI):**
   ```bash
   # Verify ARP Poisoning
   victim arp -n
   ```
   *Show:* `10.0.0.2` (Server IP) now has `00:00:00:00:01:FF` (Attacker MAC!). **This proves the poisoning.**

---

### **Phase C: Detection and Blocking**
*Examiner Script: "My SDN Controller analyzes the traffic flow using the CNN+LSTM Deep Learning model. It detects the anomaly and blocks the attacker."*

1. **Look at Terminal 1 (Ryu Controller):**
   *Wait for it...*
   *Show:* The Big Red Banner:
   ```
   ╔══════════════════════════════════════════════╗
   ║  🚨 MITM ATTACK DETECTED — ML ANOMALY      ║
   ...
   ║  ACTION:    BLOCKING HOST                    ║
   ╚══════════════════════════════════════════════╝
   ```

2. **Verify Blocking (Terminal 2):**
   ```bash
   # Attacker tries to ping victim
   attacker ping -c 3 victim
   ```
   *Show:* **100% Packet Loss**. The attacker is isolated.

3. **Verify Victim Safety (Terminal 3):**
   The victim script might timeout initially (as connections reset), but traffic is no longer being stolen.

---

## 🛠️ Troubleshooting Commands

**If Ryu crashes or doesn't show stats:**
- Restart the Docker container: `docker restart ryu-mitm`

**If Mininet freezes:**
- Run `sudo mn -c` to clean up.

**If no traffic flows:**
- Check if `h1 ping h2` works in Mininet.



1. Setup Steps (Run These First)

  You need to rebuild your Docker environment to fix the Python versions and library issues.


   1 # 1. Stop any running containers
   2 docker compose down
   3
   4 # 2. Build the new clean environment (this will take a few minutes)
   5 docker compose up -d --build
   6
   7 # 3. Prepare the scripts for Mininet
   8 bash setup.sh

  2. How to Run the Demo (5-Terminal Layout)


  For the best effect, open 5 terminal tabs/windows.

  Terminal 1: The Controller (Your Dashboard)
  This is where the magic happens.


   1 # Enter the container
   2 docker exec -it ryu-mitm /bin/bash
   3
   4 # Run the controller (inside container)
   5 ryu-manager my_controller.py
  You will see the big cyan banner and live stats updating every 30 seconds.


  Terminal 2: Mininet CLI
   1 # Start the network topology
   2 sudo python3 run_demo.py
  Wait for it to say "DEMO COMPLETE". It will open the mininet> prompt.


  Terminal 3: Victim Traffic
  Run this inside the Mininet CLI (Terminal 2) OR open a new terminal, sudo mn -c if needed,
  but easier from the Mininet prompt in Terminal 2:
   1 mininet> h1 python3 /tmp/victim_traffic.py
  You will see: Victim browsing homepage..., Login successful.

  Terminal 4: Attacker (The "Bad Guy")


   1 mininet> h3 python3 /tmp/attacker_mitm.py
  You will see: 🔴 STARTING MITM ATTACK..., ARP poisoning....


  Terminal 5: Live Stolen Data (The Proof)
  Open a real terminal on your host machine (not in Mininet):
   1 watch -n 1 "cat /tmp/mitm_stolen.txt"
  As soon as the attack works, you will see usernames and passwords appear here.


  3. What I Fixed & Built
   * Docker: Created a Dockerfile based on python:3.10-slim that installs tensorflow, scapy,
     ryu (from source), and eventlet in the correct order. The docker-compose.yml uses
     network_mode: "host" so Mininet can talk to it easily.
   * Controller (my_controller.py):
       * Live Dashboard: Prints a beautiful banner and a summary table every 30 seconds.
       * Live Logging: Shows colored one-line logs for ARP, HTTP, and ML events.
       * ML Integration: Calculates all 25 features (like packet_asymmetry, piat_variance)
         on-the-fly from packets and feeds them to your CNN+LSTM model.
       * Blocking: Automatically installs DROP rules for both MAC and IP when an attack is
         detected.
   * Scripts:
       * attacker_mitm.py: Uses scapy to ARP poison and sniff. It prints "CREDENTIAL
         CAPTURED" in red.
       * victim_traffic.py: Simulates a real user logging in and out, which is critical for
         the ML model to have traffic to analyze.
       * server_login.py: A simple HTTP server that logs requests.


  4. Demo Guide
  I created a file named DEMO_GUIDE.md in your folder. Open it to see the exact script to say
  to your examiner ("First I show normal traffic...", "Now I launch the attack...").


  Note: If you see h3 python3 ... not showing output in the Mininet CLI, it might be because
  the attack script is running in the background or output buffering. I added
  sys.stdout.reconfigure(line_buffering=True) to all scripts so you should see output
  immediately now.

## error





It looks like your Victim (device1) cannot reach the Bank
  Server (device2). This is usually caused by one of two things:
  the server script isn't running, or the Ryu Controller is
  blocking the traffic.

  Let's fix this so your demo works smoothly.


  1. Check if the Server is actually running
  The victim script is trying to connect to
  http://10.0.0.2:8080. You need to make sure the server script
  is active on the server host.


  In your Mininet CLI, run:
   1 mininet> device2 python3 /tmp/server_login.py &
  (The & at the end runs it in the background so you can keep
  using the CLI).


  2. Verify basic connectivity (Ping)
  Before testing the HTTP traffic, check if the hosts can even
  "see" each other at the network level.


  In your Mininet CLI, run:
   1 mininet> device1 ping -c 3 device2
   * If you get 0% packet loss: The network is fine; the issue
     was just the server script not running.
   * If you get 100% packet loss: Your Ryu Controller is likely
     blocking the traffic or hasn't installed the flows
     correctly.


  3. Check your Ryu Controller Terminal
  Look at the window where ryu-manager is running. 
   * Do you see [HTTP ] or [TCP ] logs appearing when you try to
     run the victim script?
   * Do you see a RED BANNER saying 🚨 MITM ATTACK DETECTED? 
       * If yes, the controller has already blocked the host.
         You might need to restart the controller to "unblock"
         everyone for a fresh start of the demo.


  💡 Recommendation for the Demo:
  To make sure everything is "clean" before you start your
  presentation:
   1. Restart Ryu: Stop it (Ctrl+C) and run ryu-manager
      my_controller.py.
   2. Restart Mininet: Exit the CLI and run sudo mn -c then sudo
      python3 run_demo.py.
   3. Start the Server FIRST: device2 python3
      /tmp/server_login.py &
   4. Then start the Victim: device1 python3
      /tmp/victim_traffic.py