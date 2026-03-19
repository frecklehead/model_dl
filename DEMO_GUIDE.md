# MITM Detection Demo Guide (Examiner Ready)

This guide provides the exact terminal commands and talking points to demonstrate the SDN-based MITM detection system clearly.

## 5-Terminal Demo Layout

Prepare 5 terminal windows for a professional look:

1. **Terminal 1: Ryu Controller Dashboard** 
2. **Terminal 2: Mininet CLI**
3. **Terminal 3: Victim (h1) Traffic**
4. **Terminal 4: Attacker (h3) Output**

5. **Terminal 5: Live Stolen Data Monitor**
docker exec -it /ryu-mitm /bin/bash
---


## STEP 1: PREPARATION & NORMAL TRAFFIC

**Terminal 1 (Ryu):**
```bash
# Start the controller inside the Docker container
docker-compose up ryu-mitm
```
*Wait for the header banner and "✅ ML Model Loaded" message.*

**Terminal 2 (Mininet):**
```bash
# Start Mininet with specific topology
sudo python3 topology.py
```
*Inside Mininet CLI, verify connections:* `pingall`

**Terminal 3 (Victim h1):**
```bash
# Start victim browsing
mininet> h1 python3 victim_traffic.py
```
*Point out the normal `GET` and `POST` logs appearing in Ryu.*

---

## STEP 2: PROVING ARP POISONING

**Terminal 2 (Mininet - Before Attack):**
```bash
# Check ARP table on h1 before the attack
mininet> h1 arp -n
```
*Point out that the server (10.0.0.2) has its legitimate MAC.*

**Terminal 4 (Attacker h3 - Launch Attack):**
```bash
# Launch the poisoning attack
mininet> h3 python3 attacker_mitm.py
```

**Terminal 2 (Mininet - After Attack):**
```bash
# Check ARP table on h1 again
mininet> h1 arp -n
```
*EXAMINER TIP: Show that the MAC for 10.0.0.2 now matches h3 (10.0.0.3), proving h1 is being poisoned.*

---

## STEP 3: PROVING INTERCEPTION

**Terminal 5 (Stolen Credentials Monitor):**
```bash
# Watch the credentials file in real-time
tail -f /tmp/mitm_stolen.txt
```
*Wait for h1 (Victim) to perform a login. You will see Alice/Bob's password appear here.*

**Terminal 4 (Attacker Output):**
*Point out the "🎯 CREDENTIAL CAPTURED" logs.*

---

## STEP 4: PROVING DETECTION & BLOCKING

**Terminal 1 (Ryu Dashboard):**
*Wait for the big detection banner to appear:*
`🚨 MITM ATTACK DETECTED — LAYER 1 (ARP) / ML DETECT`

**Terminal 2 (Mininet - Verify Blocking):**
```bash
# Try to reach the server from the attacker
mininet> h3 ping -c 3 10.0.0.2
```
*Point out that the ping FAILS (100% packet loss), showing Ryu has blocked h3.*

**Terminal 2 (Mininet - Check Flow Table):**
```bash
# View the OVS flow table rules
sudo ovs-ofctl dump-flows s1
```
*Point to the high-priority rule with `actions=drop` matching h3's MAC.*

---

## EXAMINER TALKING POINTS

1. **"First, I will show normal traffic."** - Point to Terminal 3 (Victim) and Terminal 1 (Ryu showing normal score).
2. **"Now I launch the attack from h3."** - Start script in Terminal 4.
3. **"Notice the ARP poisoning."** - Show the MAC change in Terminal 2 (h1 arp).
4. **"The attacker is now successfully intercepting credentials."** - Show Terminal 5.
5. **"Watch terminal 1: The ML model analyzes the timing and size distribution."** - Wait for the score to spike.
6. **"Ryu has now triggered an automatic block."** - Show the RED detection banner.
7. **"Finally, I will prove h3 is isolated."** - Show the failed ping and the drop rule in Terminal 2.

---

## TROUBLESHOOTING

- **No ML Scores?** Ensure you have sent at least 20 packets from the victim script (it analyzes every 20-packet window).
- **Ryu not showing logs?** Docker-compose might be buffering; use `export PYTHONUNBUFFERED=1` (already set in our YAML).
- **ARP Poisoning failing?** Ensure `ip_forward=1` inside the attacker's namespace (the script does this automatically).