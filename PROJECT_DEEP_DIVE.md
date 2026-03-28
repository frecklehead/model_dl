# MITM Attack Detection in SDN using CNN+LSTM
## Complete Project Deep Dive — From Concept to Code

---

# 1. WHAT THIS PROJECT DOES

This project detects four types of Man-in-the-Middle (MITM) attacks in real-time inside a Software-Defined Network. It uses a hybrid approach: a CNN+LSTM neural network for statistical flow analysis, combined with rule-based detection for protocol-level violations. When an attack is detected, the system automatically blocks the attacker by installing DROP rules on the OpenFlow switch.

**In one sentence:** An SDN controller that watches every packet in the network, feeds live flow statistics into a trained deep learning model, and automatically blocks any host performing MITM attacks.

---

# 2. THE TECHNOLOGY STACK

```
Layer             Technology        Role
──────────────────────────────────────────────────────────────
Network Emulation   Mininet         Creates virtual hosts, switches, links
SDN Switch          OVS (Open vSwitch)  Software OpenFlow switch (data plane)
SDN Controller      Ryu (Python)    Centralized brain (control plane)
SDN Protocol        OpenFlow 1.3    Communication between OVS and Ryu
ML Framework        TensorFlow/Keras  CNN+LSTM model for flow scoring
Feature Scaling     scikit-learn StandardScaler  Normalizes features before inference
Packet Crafting     Scapy           Constructs raw ARP, TCP, UDP, DNS packets
Login Server        Python http.server  Simulates SecureBank on port 8080
OS                  Ubuntu Linux (VM)
```

---

# 3. THE NETWORK TOPOLOGY

```
                    ┌──────────────────────────────────┐
                    │     Ryu SDN Controller            │
                    │     my_controller.py              │
                    │     Port 6633 (OpenFlow 1.3)      │
                    └──────────────┬───────────────────┘
                                   │ OpenFlow
                    ┌──────────────┴───────────────────┐
                    │     OVS Switch (s1)               │
                    │     OpenFlow 1.3                  │
                    │     Table-miss → send to controller│
                    └──┬──────┬──────┬──────┬──────┬───┘
                       │      │      │      │      │
            ┌──────────┘  ┌───┘  ┌───┘  ┌───┘  ┌───┘
            │             │      │      │      │
     ┌──────┴──────┐ ┌────┴────┐ ┌┴──────────┐ ┌┴──────┐ ┌┴──────┐
     │   victim    │ │  server │ │  attacker  │ │device1│ │device2│
     │ 10.0.0.1    │ │10.0.0.2 │ │10.0.0.100  │ │10.0.0.11│10.0.0.12│
     │ MAC: ...01  │ │MAC: ..02│ │MAC: ...03  │ │MAC:..11│ │MAC:..12│
     │             │ │SecureBank│ │ARP+DNS atk│ │SSL atk│ │Sess atk│
     └─────────────┘ │  :8080  │ └────────────┘ └───────┘ └───────┘
                      └─────────┘
```

**Five hosts, one switch, one controller:**
- `victim` (10.0.0.1) — The target. Runs `victim_traffic.py` which simulates a user logging into SecureBank, sending credentials over HTTP.
- `server` (10.0.0.2) — Runs `server_login.py`, a real HTTP server on port 8080 that serves a login page, accepts POST /login with username/password, and returns responses.
- `attacker` (10.0.0.100) — Runs `attacker_mitm.py`. Performs ARP poisoning and DNS hijacking. Intercepts and relays traffic between victim and server.
- `device1` (10.0.0.11) — Runs `ssl_strip.py`. Sends RST packets to port 443 to simulate SSL stripping.
- `device2` (10.0.0.12) — Runs `session_hijack.py`. Injects RST+ACK packets to simulate TCP session hijacking.

**Why this layout:** Each attack comes from a different host so the controller can attribute and block each attacker independently. A single switch means all traffic passes through one inspection point.

---

# 4. THE FOUR ATTACKS — HOW EACH WORKS

## 4.1 ARP Poisoning (Primary Attack — ML-detected)

**What ARP is:** ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. When victim wants to send a packet to server (10.0.0.2), it broadcasts "Who has 10.0.0.2?" and server replies "10.0.0.2 is at MAC 00:00:00:00:00:02". Victim caches this mapping.

**What the attacker does:**
1. Sends forged ARP replies to victim: "10.0.0.2 is at MAC 00:00:00:00:00:03" (attacker's MAC).
2. Sends forged ARP replies to server: "10.0.0.1 is at MAC 00:00:00:00:00:03" (attacker's MAC).
3. Both victim and server now send traffic to the attacker instead of each other.
4. Attacker enables IP forwarding (`net.ipv4.ip_forward=1`) and relays packets between them — neither knows the attacker is in the middle.
5. Meanwhile, attacker inspects payloads for credentials (POST data with username/password).

**What `attacker_mitm.py --mode=arp` launches:**
- Two `arp_poison_loop` threads (one poisons victim, one poisons server) — sends forged ARP replies every 0.5s.
- After 5 seconds: `relay_flood` thread — creates 50 TCP connections to server:8080, each sending 8 HTTP requests with 20ms spacing. This generates the ML-detectable flow signature.
- `relay_and_intercept` via Scapy `sniff()` — inspects all relayed packets for credentials (looks for POST bodies containing "username" or "password") and writes them to `/tmp/mitm_stolen.txt`.

**How the controller detects it:**
1. `_handle_arp()` sees an ARP reply where 10.0.0.2 is claimed by MAC ...03, but the ARP table already has 10.0.0.2 = MAC ...02. This is an **ARP conflict**.
2. Registers an ARP suspect with a 20-second window.
3. `_scan_flows_for_arp_suspect()` immediately scores any existing flows involving 10.0.0.2.
4. As relay_flood traffic flows, `FlowTracker` accumulates statistics. Every 5 packets, `_run_ml_on_flow()` feeds the flow's 25 features through the CNN+LSTM model.
5. The relay traffic generates scores of 0.85-0.99 because it has: low PIAT variance (machine-paced 20ms), high byte asymmetry (sends more than receives), many packets in short duration.
6. When score >= 0.5 (ML_THRESHOLD), `_trigger_alert()` fires: prints the detection box, adds MAC/IP to block lists, installs two DROP rules on the switch (one matching source MAC, one matching source IP).

**Detection timing:** ~10-20 seconds from attack start. The 5-second internal wait + 7-second wait in run_demo + 15+ packets needed for reliable scoring = first alert around 12-15 seconds.

## 4.2 SSL Stripping (ML + Rule-based fallback)

**What it is:** The attacker intercepts a victim's HTTPS connection (port 443) and downgrades it to plain HTTP (port 80). The victim thinks they're on HTTPS but the connection is unencrypted.

**What `ssl_strip.py` does (runs on device1):**
- Sends 30 TCP SYN packets to server:443 using a **fixed source port** (44300). Fixed port is critical because it makes all packets land in the **same flow entry** in the controller. If ports were random, each packet would create a new flow and the controller would never accumulate 20+ packets.
- Packets are spaced 150ms apart — fast enough to trigger detection within the countdown window.

**How the controller detects it:**
1. `_handle_ip()` creates a FlowTracker for (device1_ip:44300, server_ip:443, TCP).
2. Every 5 packets: ML scores the flow. If score >= 0.5, ML alert fires.
3. After 20 packets: `_rule_fallback()` checks if `dst_port in (443, 8443)` — yes. Fires RULE-BASED FALLBACK for SSL STRIPPING.

**The dual detection:** ML may catch it earlier (at 5-10 packets) if the flow statistics are anomalous enough. Rule-based is the safety net at 20 packets — if ML missed it, the port-based heuristic catches it.

## 4.3 Session Hijacking — RST Injection (ML + Rule-based fallback)

**What it is:** The attacker injects spoofed TCP RST (reset) packets into an existing session between victim and server, tearing it down. The attacker then takes over the connection.

**What `session_hijack.py` does (runs on device2):**
- Phase 1: Sends 10 ACK packets (flags="A") — builds `ack_count > 5` in the flow.
- Phase 2: Sends 25 RST packets (flags="R") — builds `rst_ratio > 0.15` in the flow.
- All 35 packets use fixed ports (55555 → 8080) so they land in one flow.
- Result: rst_count=25, ack_count=10, total=35. RST ratio = 25/35 = 0.71 (>> 0.15).

**How the controller detects it:**
1. FlowTracker tracks SYN/ACK/RST/FIN counts via TCP flag bitmasks: `flags & 0x04` for RST, `flags & 0x10` for ACK.
2. After 20 packets: `_rule_fallback()` checks `rst_r > 0.15 and flow.ack_count > 5` — both true. Fires SESSION HIJACKING.

## 4.4 DNS Hijacking (Rule-based only)

**What it is:** The attacker sends spoofed DNS responses for a domain, redirecting the victim to a fake IP.

**What `attacker_mitm.py --mode=dns` launches:**
- `dns_hijack_loop` thread crafts raw DNS response packets:
  - Response A: `test.local → 10.0.0.2` (sent from server IP, looks legitimate)
  - Response B: `test.local → 10.0.0.99` (sent from attacker IP, spoofed)
- Packets are crafted at the byte level: transaction ID (0xAAAA), flags (0x8180 = standard response), 1 question, 1 answer RR, type A, class IN, TTL 60, 4-byte IP address.
- Sent to victim via Scapy every 2 seconds.

**How the controller detects it:**
1. `_check_dns()` parses every UDP packet on port 53.
2. Checks the QR bit (bit 15 of byte 2) to confirm it's a response (not a query).
3. Checks ANCOUNT (bytes 6-7) > 0 to confirm there's an answer.
4. Parses the domain name from the question section (length-prefixed labels: `\x04test\x05local\x00` = "test.local").
5. Records `dns_responses["test.local"].add(src_ip)`.
6. First response: `{"test.local": {"10.0.0.2"}}` — 1 IP, no alert.
7. Second response: `{"test.local": {"10.0.0.2", "10.0.0.100"}}` — 2 IPs = **divergence**. Alert fires.

**Why not ML:** DNS responses are 2-3 packets. The ML model needs 15+ packets to build reliable statistics. The anomaly here is semantic (same domain, different IPs), not statistical.

---

# 5. THE ML MODEL — CNN+LSTM

## 5.1 Architecture

```
Input: (1, 25, 1) — 25 features reshaped as a 1D sequence
  ↓
Conv1D layer — extracts local feature correlations
  (e.g., byte_asymmetry + low PIAT variance appearing together)
  ↓
LSTM layer — captures temporal/sequential patterns
  (e.g., gradual RST accumulation over a session)
  ↓
Dense layers
  ↓
Sigmoid output — single float in [0.0, 1.0]
  0.0 = normal traffic
  1.0 = MITM attack
  Threshold = 0.5
```

## 5.2 The 25 Features

```
FEATURE NAME                      CATEGORY      WHAT IT MEASURES
────────────────────────────────────────────────────────────────────
src_port                          Port          Source port number
dst_port                          Port          Destination port number
bidirectional_duration_ms         Timing        Total flow duration in ms
bidirectional_bytes               Volume        Total bytes both directions
src2dst_packets                   Volume        Packets from source → destination
src2dst_bytes                     Volume        Bytes from source → destination
dst2src_bytes                     Volume        Bytes from destination → source
bidirectional_min_ps              Size          Smallest packet in flow
bidirectional_mean_ps             Size          Average packet size
bidirectional_stddev_ps           Size          Packet size standard deviation
bidirectional_max_ps              Size          Largest packet in flow
src2dst_min_ps                    Size          Smallest packet (src→dst only)
src2dst_mean_ps                   Size          Average packet size (src→dst)
dst2src_min_ps                    Size          Smallest packet (dst→src only)
dst2src_mean_ps                   Size          Average packet size (dst→src)
bidirectional_mean_piat_ms        Timing        Average inter-arrival time (all)
bidirectional_stddev_piat_ms      Timing        PIAT standard deviation (all)
bidirectional_max_piat_ms         Timing        Longest gap between packets
src2dst_mean_piat_ms              Timing        Average PIAT (src→dst only)
src2dst_max_piat_ms               Timing        Longest PIAT gap (src→dst)
byte_asymmetry                    Derived       |s2d_bytes - d2s_bytes| / total
bytes_per_packet                  Derived       total_bytes / total_packets
src2dst_bpp                       Derived       s2d_bytes / s2d_packets
duration_ratio                    Derived       s2d_duration / d2s_duration
ps_variance_ratio                 Derived       (stddev_ps^2) / (mean_ps + 1)
```

### The Feature That Matters Most: `byte_asymmetry`

```
byte_asymmetry = |src2dst_bytes - dst2src_bytes| / (total_bytes + 1)
```

Normal HTTP: Client sends small requests (few hundred bytes), server sends large HTML responses (thousands of bytes). Asymmetry exists but follows a predictable application-specific pattern.

MITM relay: Attacker receives FROM server AND sends TO victim. The relay creates flows where traffic volume in both directions is dominated by forwarded data. The ratio differs fundamentally from normal client-server patterns.

### Why PIAT (Packet Inter-Arrival Time) Catches Relays

Normal human traffic has variable PIATs — humans click, pause, read, scroll. The standard deviation is high.

Relay flood traffic has `time.sleep(0.02)` — every packet arrives exactly 20ms after the previous one. `bidirectional_stddev_piat_ms` drops near zero. `ps_variance_ratio` also drops because all relay packets carry similar-sized HTTP requests.

The CNN layer sees this pattern: byte_asymmetry + low PIAT stddev + high packet count in short duration = relay. Score: 0.85-0.99.

## 5.3 Feature Extraction — FlowTracker Class

Every unique flow (identified by `(src_ip, src_port, dst_ip, dst_port, protocol)`) gets a `FlowTracker` object.

On every packet:
```python
def update(self, size, direction, flags):
    # Record inter-arrival time
    self.piats.append((now - self.last_time) * 1000)  # ms
    # Record packet size
    self.packet_sizes.append(size)
    # Direction-specific counters
    if direction == 's2d':
        self.s2d_packets += 1
        self.s2d_bytes += size
    else:
        self.d2s_packets += 1
        self.d2s_bytes += size
    # TCP flag counters
    if flags & 0x02: self.syn_count += 1   # SYN
    if flags & 0x10: self.ack_count += 1   # ACK
    if flags & 0x04: self.rst_count += 1   # RST
    if flags & 0x01: self.fin_count += 1   # FIN
```

`get_features()` computes all 25 features from accumulated data using numpy for statistics (mean, std, min, max).

## 5.4 Inference Pipeline

```
FlowTracker.get_features()           # returns dict of 25 feature values
    ↓
pd.DataFrame([[values]], columns=FEATURES)  # named columns for scaler
    ↓
StandardScaler.transform(df)          # zero-mean, unit-variance normalization
    ↓
.astype(np.float32)                   # cast to float32 for TensorFlow
    ↓
.reshape(1, 25, 1)                    # reshape to (batch=1, timesteps=25, features=1)
    ↓
model.predict(vec)                    # CNN+LSTM inference
    ↓
float score in [0.0, 1.0]            # sigmoid output
    ↓
score >= 0.5 ? → ALERT               # ML_THRESHOLD
```

## 5.5 Model Files

```
model/
├── mitm_model.h5                # Keras HDF5 model (primary)
├── mitm_model.keras             # Keras native format (backup)
├── mitm_model_saved/            # TensorFlow SavedModel format
│   ├── saved_model.pb
│   ├── fingerprint.pb
│   └── variables/
│       ├── variables.data-00000-of-00001
│       └── variables.index
├── scaler.pkl                   # scikit-learn StandardScaler (fitted on training data)
├── selected_features.pkl        # List of 25 feature names (used at runtime)
├── model_summary.pkl            # Model architecture summary
├── best_checkpoint.h5           # Best training checkpoint
└── results.json                 # Training results/metrics
```

At startup, `_load_model()` tries:
1. `mitm_model_saved/` directory → `tf.saved_model.load()` (fastest inference)
2. `mitm_model.h5` → `tf.keras.models.load_model()` (fallback)
3. Loads `scaler.pkl` and `selected_features.pkl` alongside

---

# 6. THE CONTROLLER — my_controller.py (Line by Line Logic)

## 6.1 Initialization (__init__)

When Ryu starts, `MITMController.__init__` creates:
```
mac_to_port      = {}          # MAC learning table for forwarding
arp_table        = {}          # IP → MAC (first seen = trusted)
arp_conflicts    = {}          # IP → (known_mac, forged_mac)
dai_bindings     = {}          # Dynamic ARP Inspection: IP → set of MACs
dns_responses    = {}          # domain → set of IPs (for divergence check)
flows            = {}          # flow_key → FlowTracker
blocked_macs     = set()       # MACs that have been blocked (DROP rules installed)
blocked_ips      = set()       # IPs that have been blocked
detections       = []          # List of all detection events
triggered_alerts = set()       # (ip, mac, attack_type) — dedup key
ml_flagged_flows = set()       # Flow keys already flagged by ML
attack_counts    = defaultdict(int)  # count per attack type
arp_suspects     = {}          # IP → {known, forged, attacker_ip, mac, dp, at}
_alert_quiet_until = 0         # Timestamp until which packet-in logs are suppressed
```

Then loads the ML model, prints the banner, and spawns the stats loop (greenthread via `hub.spawn`).

## 6.2 Switch Connection (switch_features_handler)

When OVS connects via OpenFlow:
1. Clears all detection state (fresh start).
2. Installs the **table-miss flow** (priority 0, match all, action: send to controller).
   Without this, the switch would drop all packets and the controller would see nothing.
3. Prints a green connection box in the terminal.

## 6.3 Packet-In Handler (_packet_in_handler)

Every packet that doesn't match a higher-priority rule triggers this:
1. Parse the Ethernet frame.
2. Skip LLDP (link-layer discovery protocol) packets.
3. Skip packets from blocked MACs.
4. If ARP: → `_handle_arp()`
5. If IPv4: skip if source IP is blocked → `_handle_ip()`
6. MAC learning: record src_mac → in_port mapping.
7. Forward packet: if destination MAC is known, send to that port; otherwise, flood.

## 6.4 ARP Handler (_handle_arp)

For every ARP packet:
1. If the source IP is already in `arp_table` with a DIFFERENT MAC → **ARP CONFLICT**.
   - Records the conflict: `arp_conflicts[src_ip] = (known_mac, forged_mac)`
   - Reverse-lookups attacker's real IP from the ARP table (which IP was previously associated with this MAC?)
   - If ML model is loaded: registers an ARP suspect and immediately scans existing flows.
   - If ML not loaded: fires rule-based alert immediately.
   - Does NOT update the ARP table with the forged MAC (preserves trusted first-seen entry).
2. If IP not in table: adds it (first-seen = trusted).
3. Updates DAI bindings (tracks all MACs that have ever claimed an IP).

## 6.5 IPv4 Handler (_handle_ip)

For every IPv4 packet:
1. Parse TCP/UDP headers for ports and flags.
2. If UDP: check for DNS (port 53) → `_check_dns()`.
3. Log the packet (unless in quiet period after an alert).
4. Create or update a `FlowTracker` for this flow.
5. **ML scoring trigger**: Every 5 packets (5, 10, 15, 20...), if the flow hasn't been flagged yet, run `_run_ml_on_flow()`.
6. **Rule-based fallback**: Every 10 packets starting at 20 (20, 30, 40...), if ML hasn't flagged it, run `_rule_fallback()`.

## 6.6 ML Scoring (_run_ml_on_flow)

1. Call `_ml_score(flow)` — extracts features, scales, reshapes, runs inference.
2. If score >= 0.5:
   - Mark flow as flagged.
   - `classify_subtype()` determines which specific attack type (ARP, SSL, Session, DNS, Relay, etc.) based on flow heuristics.
   - If the flow involves an IP that has an ARP conflict, override to "ARP POISONING".
   - Fire `_trigger_alert()`.
3. If score < 0.5: print a dim scan line (suppressed during quiet period).

## 6.7 Trigger Alert (_trigger_alert)

The central alert function:
1. Dedup check: `(ip, mac, attack_type)` — each combination can only alert once.
2. Prints a large red `╔═══ MITM ATTACK DETECTED ═══╗` box with: attack type, method, how it was detected, time, host IP, MAC, details, action taken.
3. Prints a sticky one-liner below the box.
4. Sets `_alert_quiet_until = now + 5s` — suppresses packet-in logs for 5 seconds so the alert box doesn't scroll away.
5. Adds attacker to `blocked_macs` and `blocked_ips`.
6. Writes detection to `/tmp/mitm_alerts.json`.
7. Installs two OpenFlow DROP rules at priority 100:
   - `OFPMatch(eth_src=mac)` → empty actions (drop all frames from this MAC)
   - `OFPMatch(eth_type=0x0800, ipv4_src=ip)` → empty actions (drop all IPv4 from this IP)

## 6.8 Stats Loop (_stats_loop + _flush_old_arp_suspects + _print_stats)

Every 10 seconds:

**`_flush_old_arp_suspects()`**: For any ARP suspect older than 20 seconds:
- Final ML scan: score all flows involving the conflicting IP.
- If best_score >= 0.5 → ML-confirmed ARP POISONING alert.
- If flows exist but all scored < 0.5 → NOT flagged (insufficient evidence).
- If no flows at all → RULE-BASED alert (ARP conflict itself is definitive).

**`_print_stats()`**: Prints a bordered status table showing switch count, flow count, ARP entries, attack statistics (with red markers for detected types), recent alerts, and blocked IPs.

---

# 7. THE DEMO — run_demo.py

## 7.1 Startup Sequence

```
1. cleanup_orphans()
   - Kill leftover attack processes (pkill)
   - Remove stale OVS bridge: ovs-vsctl --if-exists del-br s1
   - Remove leftover network namespaces

2. wait_for_ryu_port(6633)
   - Socket probe to verify Ryu is listening
   - Aborts if Ryu not running

3. create_topology() + net.start()
   - Creates Mininet with 5 hosts + 1 OVS switch + remote controller

4. OVS fast connection
   - ovs-vsctl set controller s1 max_backoff=1000 inactivity_probe=5000
   - ovs-appctl -t ovs-vswitchd reconnect  (forces immediate connection attempt)

5. deploy_scripts()
   - Copies all .py scripts from scripts/ to /tmp/ (Mininet hosts share the filesystem)

6. wait_for_controller()
   - Polls ovs-vsctl get controller s1 is_connected every 250ms
   - Re-kicks ovs-appctl reconnect every 2 seconds if stuck

7. wait_for_flows()
   - Verifies Ryu has installed the table-miss flow via ovs-ofctl dump-flows

8. ARP warm-up
   - Pings between all hosts to populate ARP tables and establish MAC learning

9. check_ping()
   - Verifies victim can reach server (connectivity check)

10. Start SecureBank server
    - Launches server_login.py on server:8080
    - Verifies login page is reachable

11. Baseline traffic
    - Sends normal HTTP requests + pings for 5 seconds
    - Establishes "normal" flow baselines in the controller

12. attack_menu()
    - Interactive menu for launching individual attacks
```

## 7.2 Attack Menu

```
╔════════════════════════════════════════════════════════════════╗
║   MITM ATTACK DETECTION SYSTEM  —  LIVE DEMONSTRATION        ║
║   SDN + OpenFlow13  |  ML Model (CNN+LSTM)  |  Rule-Based    ║
╠════════════════════════════════════════════════════════════════╣
║  victim    10.0.0.1    →  target host sending credentials     ║
║  server    10.0.0.2    →  SecureBank login server  (:8080)    ║
║  attacker  10.0.0.100  →  malicious host  (ARP + DNS)        ║
║  device1   10.0.0.11   →  SSL stripping attacker             ║
║  device2   10.0.0.12   →  session hijacking attacker         ║
╠════════════════════════════════════════════════════════════════╣
║  [1]  ARP Poisoning MITM          intercepts all traffic      ║
║  [2]  SSL Stripping               downgrades HTTPS to HTTP    ║
║  [3]  Session Hijacking           RST injection seizes TCP    ║
║  [4]  DNS Hijacking               spoofs domain → fake IP     ║
║  [a]  Run all 4 attacks sequentially                          ║
║  [r]  Reset state  (flush ARP + stop attacks)                 ║
║  [c]  Open Mininet CLI                                        ║
║  [x]  Exit demo                                               ║
╚════════════════════════════════════════════════════════════════╝
```

Each attack:
1. Prints an attack header box explaining what the attack does.
2. Launches the attack (starts victim traffic + attacker scripts).
3. Runs a countdown timer with a progress bar.
4. Shows results (ARP table changes, intercepted credentials, attack logs).
5. Tells the user to check the Ryu terminal for [ALERT].

## 7.3 The `--mode` Flag

`attacker_mitm.py` accepts `--mode=arp|dns|ssl|session|all`:
- `--mode=arp`: Launches ARP poisoning + relay flood + sniff. Does NOT launch DNS/SSL/session threads.
- `--mode=dns`: Launches DNS hijack loop only. Stays alive with `while True: sleep(1)`.
- `--mode=all` (default): Launches everything (used for standalone testing).

This prevents DNS attack from accidentally triggering ARP detection (they were previously coupled).

---

# 8. HOW EACH FILE CONNECTS

```
run_demo.py
  ├── Starts Mininet topology (calls create_topology())
  ├── Copies scripts/* to /tmp/
  ├── Launches attack_menu()
  │   ├── attack_arp()
  │   │   ├── victim runs: /tmp/victim_traffic.py → sends HTTP to server:8080
  │   │   └── attacker runs: /tmp/attacker_mitm.py --mode=arp
  │   │       ├── arp_poison_loop × 2 (poisons both victim and server)
  │   │       ├── relay_flood (50 TCP connections with 20ms pacing)
  │   │       └── sniff() + relay_and_intercept (steals credentials)
  │   ├── attack_ssl()
  │   │   └── device1 runs: /tmp/ssl_strip.py → 30 SYN packets to :443
  │   ├── attack_session_hijack()
  │   │   └── device2 runs: /tmp/session_hijack.py → 10 ACK + 25 RST packets
  │   └── attack_dns()
  │       └── attacker runs: /tmp/attacker_mitm.py --mode=dns
  │           └── dns_hijack_loop → spoofed DNS responses
  │
  └── All traffic flows through OVS switch s1
      └── Table-miss → PacketIn → Ryu controller
          └── my_controller.py
              ├── _handle_arp() → ARP conflict detection
              ├── _handle_ip() → FlowTracker + ML scoring
              ├── _check_dns() → DNS divergence detection
              ├── _rule_fallback() → SSL/Session rule-based
              ├── _trigger_alert() → Block attacker + print alert
              └── _stats_loop() → Periodic flush + status report
```

---

# 9. KEY DESIGN DECISIONS

**Why hybrid ML + rule-based:**
- ML alone needs 15+ packets. DNS attacks produce 2-3 packets. ARP-only scans produce 0 IP packets.
- Rule-based alone can't detect statistically anomalous relay traffic that doesn't match hardcoded patterns.
- Hybrid = defence in depth.

**Why 0.5 threshold:**
- Default sigmoid midpoint. Not optimized — honest baseline choice.
- The model's ARP detection scores 0.85-0.99, far above threshold, so there's a wide margin.

**Why 15-packet minimum:**
- Below 15 packets, PIAT statistics are unreliable (too few samples for meaningful standard deviation).
- Previously used 3-packet minimum, which gave inconsistent scores (0.3 sometimes, 0.99 other times).

**Why 20-second ARP suspect window:**
- ARP poisoning + 5s wait + relay flood start + 15+ packets for ML = ~12-15 seconds minimum.
- 20 seconds gives enough time with margin for VM slowness.

**Why table-miss at priority 0:**
- Catches ALL packets that don't match higher-priority rules.
- Higher-priority DROP rules (100) installed by `_trigger_alert` override it — blocked traffic is dropped before reaching the controller.

**Why dual DROP rules (MAC + IP):**
- Attacker might change MAC but keep IP (MAC spoofing).
- Attacker might change IP but keep MAC (IP spoofing).
- Both rules together block the attacker regardless.

**Why `pd.DataFrame` instead of numpy array for scaler:**
- `StandardScaler` was fitted on a pandas DataFrame with named columns.
- Passing a numpy array triggers a UserWarning because sklearn can't verify feature order.
- Fix: wrap features in `pd.DataFrame(columns=FEATURES)` at inference time.

**Why `ovs-appctl reconnect` after `net.start()`:**
- OVS uses exponential backoff between connection attempts (up to 60s by default).
- After a failed attempt, it waits 1s, 2s, 4s, 8s... before retrying.
- `reconnect` resets the backoff timer and forces an immediate attempt.
- Combined with `max_backoff=1000`, all future retries are capped at 1s.

**Why 5-second quiet period after alerts:**
- Packet-in events generate rapid log output (every packet prints a line).
- The alert box (`╔═══ MITM ATTACK DETECTED ═══╗`) scrolls off screen within 1-2 seconds.
- Suppressing packet-in logs for 5s keeps the alert visible.

---

# 10. WHAT RUNS IN EACH TERMINAL

**Terminal 1 — Ryu Controller:**
```bash
ryu-manager my_controller.py
```
Shows: banner, switch connection, packet-in logs, ML scan results, ALERT boxes, status reports.

**Terminal 2 — Mininet Demo:**
```bash
sudo python3 run_demo.py
```
Shows: setup progress, attack menu, countdown timers, attack results, ARP tables, stolen credentials.

---

# 11. COMPLETE FILE INVENTORY

```
model_dl/
├── my_controller.py          # Ryu SDN controller (810 lines)
│                               - FlowTracker class (feature extraction)
│                               - MITMController class (detection logic)
│                               - ML inference pipeline
│                               - Alert system + blocking
│
├── run_demo.py               # Demo launcher (585 lines)
│                               - Mininet topology creation
│                               - OVS connection management
│                               - Interactive attack menu
│                               - Attack orchestration
│
├── scripts/
│   ├── attacker_mitm.py      # Main attack script (416 lines)
│   │                           - ARP poisoning (2 threads)
│   │                           - Relay flood (50 connections)
│   │                           - Session hijack RST injection
│   │                           - SSL strip RST injection
│   │                           - DNS hijack (spoofed responses)
│   │                           - Credential interception (sniff)
│   │                           - --mode flag for selective launch
│   │
│   ├── victim_traffic.py     # Victim simulator (110 lines)
│   │                           - HTTP requests to SecureBank
│   │                           - POST /login with credentials
│   │                           - Randomized browsing patterns
│   │
│   ├── server_login.py       # Login server (118 lines)
│   │                           - HTTP server on port 8080
│   │                           - GET / (login page)
│   │                           - POST /login (accepts credentials)
│   │                           - GET /dashboard, POST /transfer
│   │
│   ├── ssl_strip.py          # SSL strip attack (68 lines)
│   │                           - 30 SYN packets to port 443
│   │                           - Fixed source port (single flow)
│   │
│   └── session_hijack.py     # Session hijack attack (89 lines)
│                               - 10 ACK + 25 RST packets
│                               - Fixed ports (single flow)
│
├── model/
│   ├── mitm_model.h5         # Keras model (primary)
│   ├── mitm_model.keras      # Keras native format
│   ├── mitm_model_saved/     # TF SavedModel (fastest)
│   ├── scaler.pkl            # StandardScaler
│   ├── selected_features.pkl # 25 feature names
│   ├── model_summary.pkl     # Architecture summary
│   ├── best_checkpoint.h5    # Best training checkpoint
│   └── results.json          # Training metrics
│
├── DEFENSE_QA.md             # 40 Q&A for project defense
├── GPT_PRESENTATION_PROMPT.md # Prompt for generating slides
└── PROJECT_DEEP_DIVE.md      # This file
```

---

*This document covers every component, every design decision, and every line of logic in the project. Anyone reading this should be able to understand, explain, and defend the system end-to-end.*
