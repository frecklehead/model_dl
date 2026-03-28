# MITM Detection System: Manual Demonstration Guide

This guide provides step-by-step instructions to manually execute the MITM attacks and observe their detection by the Ryu SDN controller.

---

## 1. Preparation

Open two terminal windows.

### Terminal 1: Ryu SDN Controller
Start the controller first. It will load the ML model and begin listening for OpenFlow connections.

```bash
# Navigate to the project directory
cd ~/Desktop/model_dl

# Start the Ryu controller with the custom detection logic
ryu-manager my_controller.py
```

### Terminal 2: Mininet Topology
Once the controller is running, start the network. We will use a script to set up the topology and then drop into the Mininet CLI.

```bash
# Start the network topology
sudo python3 run_demo.py
```
*Note: `run_demo.py` will automatically clean up old processes, start the network, and deploy attack scripts to `/tmp/`. Stay in the Mininet CLI `mininet>` for the following steps.*

---

## 2. Baseline & Connectivity

Before attacking, verify the network is healthy and establish a "Normal" traffic baseline for the ML model.

### Warm up ARP Caches
In the `mininet>` CLI:
```bash
victim ping -c 2 10.0.0.2
server ping -c 2 10.0.0.1
```

### Start the Target Web Server
```bash
server python3 /tmp/server_login.py &
```

### Generate Normal Traffic
Simulate a legitimate user login to establish a baseline.
```bash
victim curl -s -X POST http://10.0.0.2:8080/login -d "username=alice&password=secret123"
```
**Check Terminal 1 (Ryu):** You should see flow logs marked as **NORMAL** with low ML scores.

---

## 3. Attack Phase 1: SSL Stripping

This attack targets secure (HTTPS/TLS) ports to downgrade or intercept encrypted traffic.

### Execute Attack (from device1)
```bash
device1 python3 /tmp/ssl_strip.py 10.0.0.2 &
```

### Observe Detection
**Check Terminal 1 (Ryu):** 
- The controller will monitor the port-443/8443 traffic.
- After ~20 packets, the ML model or the rule-based fallback will trigger.
- **Look for:** `[ML] DETECTED SSL STRIPPING` or `RULE-BASED FALLBACK`.
- **Action:** The controller will automatically install a DROP rule for `device1`.

---

## 4. Attack Phase 2: Session Hijacking

This attack uses TCP RST injection to disrupt and take over an active session.

### Execute Attack (from device2)
```bash
device2 python3 /tmp/session_hijack.py 10.0.0.1 10.0.0.2 device2-eth0 &
```

### Observe Detection
**Check Terminal 1 (Ryu):** 
- The controller detects the high ratio of RST packets relative to ACKs.
- **Look for:** `[ML] DETECTED SESSION HIJACKING`.
- **Action:** `device2` will be blocked from the network.

---

## 5. Attack Phase 3: ARP Poisoning (MITM)

The most advanced attack: the attacker positions themselves between the victim and the server to steal credentials.

### Prepare Attacker (from attacker)
```bash
attacker sysctl -w net.ipv4.ip_forward=1
attacker python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0 &
```

### Trigger Victim Traffic
```bash
victim python3 /tmp/victim_traffic.py 10.0.0.2 &
```

### Observe Detection & Credential Theft
**1. Check Terminal 1 (Ryu):** 
- The controller detects the ARP conflict (two MACs claiming one IP).
- The ML model confirms the anomaly in the relayed flow.
- **Look for:** `🚨 *** MITM ATTACK DETECTED ***` and `Attack Type: ARP POISONING`.

**2. Verify Stolen Data (on attacker):**
```bash
attacker cat /tmp/mitm_stolen.txt
```
You should see the intercepted `username` and `password`.

---

## 6. Verification & Cleanup

### Check OVS Flow Rules
See the "DROP" rules installed by the controller:
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

### Exit and Cleanup
```bash
exit
sudo mn -c
pkill -f python3
```
