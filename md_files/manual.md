# Manual Demo Guide — MITM Detection

## Prerequisites
- Ryu controller running in a separate terminal **before** anything else
- `run_demo.py` started to create the Mininet topology

---

## Step 0 — Start Ryu (separate terminal, BEFORE run_demo.py)
```bash
cd /path/to/project
ryu-manager my_controller.py
```
Wait until you see: `connected socket` or `datapath connected`

---

## Step 1 — Start Mininet topology
```bash
# In a new terminal
sudo python3 run_demo.py
```
The demo auto-runs phases 1–7. When it finishes it opens the Mininet CLI.
To run everything **manually** from here, let it reach the CLI then proceed below.

---

## Step 2 — Open xterm windows (from Mininet CLI)
```
mininet> xterm server victim attacker
```
Three windows open — one per host.

---

## Step 3 — Start the login server (in SERVER xterm)
```bash
fuser -k 8080/tcp 2>/dev/null
python3 /tmp/server_login.py
```
You should see: `Server started on port 8080`

---

## Step 4 — Verify connectivity (in VICTIM xterm)
```bash
ping -c 3 10.0.0.2
curl http://10.0.0.2:8080/
```
You should see the SecureBank HTML. If not, check Ryu is connected.

---

## Step 5 — Launch the MITM attack (in ATTACKER xterm)
```bash
# The script auto-detects the interface — no need to pass it
python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2
```
You will see:
```
[*] Auto-selected interface 'attacker-eth0' (has IP 10.0.0.100)
[+] ARP resolved: 10.0.0.1 → 00:00:00:00:00:01
[+] ARP resolved: 10.0.0.2 → 00:00:00:00:00:02
[+] Poisoning 10.0.0.1  (telling it: 10.0.0.2 = 00:00:00:00:00:03)
[+] Poisoning 10.0.0.2  (telling it: 10.0.0.1 = 00:00:00:00:00:03)
✅ ARP Poisoning : active
```

Wait ~3 seconds, then check the Ryu terminal — you should see:
```
[ARP  ] REPLY  10.0.0.100 (00:00:00:00:00:03) → 10.0.0.1
🚨 ARP SPOOFING detected ...
```

---

## Step 6 — Send credentials as victim (in VICTIM xterm)
```bash
python3 /tmp/victim_traffic.py 10.0.0.2
```
The victim will browse and POST credentials repeatedly.

---

## Step 7 — Watch stolen credentials (in ATTACKER xterm — new tab)
```bash
watch -n 1 cat /tmp/mitm_stolen.txt
```
Or:
```bash
tail -f /tmp/mitm_stolen.txt
```

---

## Step 8 — Confirm ARP poisoning worked (in VICTIM xterm)
```bash
arp -n
```
The entry for `10.0.0.2` should show MAC `00:00:00:00:00:03` (attacker's MAC)
instead of `00:00:00:00:00:02` (server's real MAC).

---

## Step 9 — Watch ML detection (Ryu terminal)
After ~20 packets through the attacker, the ML model fires:
```
[ML   ] Flow: 10.0.0.1→10.0.0.2 | pkts=20 | score=0.9123 | MITM 🚨
🚨 MITM ATTACK DETECTED — ML ANOMALY
ACTION: BLOCKING MAC ADDRESS
```
The attacker MAC `00:00:00:00:00:03` is now dropped by OVS.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Cannot find 10.0.0.x` | ARP resolution failed | Run `ping -c 3 10.0.0.1` from attacker first |
| `No route to host` | Ryu blocked attacker + ARP still poisoned | Normal — victim_traffic.py auto-refreshes ARP |
| `Connection refused` | server_login.py not running | Run Step 3 again |
| `Connection timed out` | Ryu not connected, OVS has no flows | Check Ryu terminal, run `ovs-ofctl dump-flows s1` |
| Attacker uses wrong interface | Auto-detect failed | Pass interface explicitly: `python3 /tmp/attacker_mitm.py 10.0.0.1 10.0.0.2 attacker-eth0` |
| ML score always low | Not enough packets (need 20) | Wait longer, or lower threshold in my_controller.py to 0.5 |

---

## Verify OVS is working at any time (root terminal)
```bash
ovs-ofctl dump-flows s1        # see all flows including DROP rules
ovs-vsctl show                 # confirm controller is connected
```