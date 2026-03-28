# Minor Project Defense — Q&A Preparation
## MITM Attack Detection in SDN using CNN+LSTM
### BEI, Pulchowk Campus

*Prepared from the perspective of a PhD-level examiner specializing in SDN and network security.*

---

## SECTION 1 — Fundamentals (Every student must know these)

---

**Q1. What is a Man-in-the-Middle (MITM) attack? Give a real-world example.**

**A:** A MITM attack occurs when an attacker secretly positions themselves between two communicating parties, intercepting and possibly altering the data in transit — without either party knowing. The victim believes they are communicating directly with the server, but all traffic is flowing through the attacker.

Real-world example: On a public Wi-Fi network, an attacker performs ARP poisoning to intercept an online banking session. The victim's browser shows `https://bank.com`, but the attacker is silently reading every request/response.

---

**Q2. What are the four types of MITM attacks your system detects, and how does each work?**

**A:**

| Attack | Mechanism | What the Attacker Does |
|---|---|---|
| ARP Poisoning | Sends fake ARP replies mapping attacker's MAC to victim/server IP | All traffic meant for victim or server flows through attacker's machine |
| SSL Stripping | Injects TCP RST packets mid-TLS handshake | Downgrades HTTPS to HTTP; session continues unencrypted |
| Session Hijacking | Injects spoofed RST+ACK packets into an active TCP session | Tears down victim's connection; attacker takes over the session |
| DNS Hijacking | Sends two spoofed DNS responses for the same domain with different IPs | Victim resolves `test.local` to a fake IP controlled by attacker |

---

**Q3. What is SDN (Software-Defined Networking)? How is it different from traditional networking?**

**A:** SDN separates the **control plane** (decisions about where traffic goes) from the **data plane** (actual forwarding of packets). In traditional networking, both planes are tightly coupled inside each switch/router's firmware — a network administrator cannot easily reprogram them.

In SDN:
- A centralized **controller** (here: Ryu) makes all forwarding decisions.
- Switches (here: OVS) become dumb forwarding devices that follow controller instructions.
- The controller communicates with switches via the **OpenFlow** protocol.

This architecture makes our detection system possible: every packet-in event is sent to the controller, which runs ARP inspection, flow tracking, and ML scoring — something impossible in traditional networks without deploying agents on every device.

---

**Q4. What is OpenFlow? What version do you use and why?**

**A:** OpenFlow is the protocol used for communication between an SDN controller and network switches. It allows the controller to install, modify, and delete flow rules in the switch's flow table.

We use **OpenFlow 1.3** because:
- It introduced the **table-miss** flow entry (priority 0) that sends unmatched packets to the controller — essential for our packet inspection.
- It supports multiple flow tables, group tables, and meters — features needed for more advanced rule management.
- It is the stable, widely-supported version in Ryu and OVS.

---

**Q5. What is Ryu? What is Mininet? Why did you choose them?**

**A:**
- **Ryu** is a Python-based open-source SDN controller framework. It handles OpenFlow events through event-driven handlers (`@set_ev_cls`). We chose it because it is lightweight, scriptable, and has strong community support.
- **Mininet** is a network emulator that creates virtual topologies (hosts, switches, links) inside a Linux kernel using network namespaces. It lets us simulate a real network on a single VM.

We chose this combination because it is the standard academic SDN testbed. It lets us demonstrate real OpenFlow communication, real ARP/TCP/DNS packet flows, and real ML inference — all without physical hardware.

---

**Q6. What is your network topology? Why did you choose this layout?**

**A:**
```
victim   (10.0.0.1)  ─┐
server   (10.0.0.2)  ─┤
attacker (10.0.0.100) ─┤── s1 (OVS switch) ── Ryu Controller
device1  (10.0.0.11)  ─┤
device2  (10.0.0.12)  ─┘
```
We have 5 hosts connected to a single OVS switch controlled by Ryu. The separation of roles (victim, server, attacker, device1, device2) allows each attack to be launched independently from a different host, making the demonstration clean and auditable. A single switch means all traffic passes through one point of inspection.

---

## SECTION 2 — Machine Learning Model

---

**Q7. Why did you choose CNN+LSTM as your ML model? Why not a simpler model like Random Forest or SVM?**

**A:** MITM detection from network flows has both **spatial** and **temporal** characteristics:
- **CNN (Convolutional Neural Network)** extracts local feature patterns across the feature vector — e.g., correlations between packet size statistics and PIAT (packet inter-arrival time) stats that together indicate relay-flood behaviour.
- **LSTM (Long Short-Term Memory)** captures sequential/temporal patterns — e.g., the gradual accumulation of RST packets over a session.

Simpler models like Random Forest treat each feature independently and do not model the feature interaction or temporal aspect. For flow-based MITM detection where the anomaly *develops over time*, CNN+LSTM is more appropriate. However, we acknowledge that for a minor project scope, an RF or XGBoost baseline comparison would strengthen our evaluation — that is a limitation.

---

**Q8. What are the 25 features your model uses? Why were these features selected?**

**A:** The features fall into four semantic groups:

| Group | Features | Why relevant |
|---|---|---|
| Port/Protocol | `src_port`, `dst_port` | MITM relay traffic uses predictable port patterns |
| Byte statistics | `bidirectional_bytes`, `src2dst_bytes`, `dst2src_bytes`, `bidirectional_min/mean/stddev/max_ps`, `src2dst_min/mean_ps`, `dst2src_min/mean_ps`, `bytes_per_packet`, `src2dst_bpp` | ARP-relayed traffic has characteristic byte asymmetry |
| PIAT (inter-arrival timing) | `bidirectional_duration_ms`, `bidirectional_mean/stddev/max_piat_ms`, `src2dst_mean/max_piat_ms` | Relay flood generates low-variance, low-PIAT bursts |
| Derived ratios | `byte_asymmetry`, `duration_ratio`, `ps_variance_ratio` | Engineered to capture the fundamental asymmetry of proxied traffic |

`byte_asymmetry` = |s2d_bytes − d2s_bytes| / total_bytes — this is the single most discriminative feature. A relay always receives more than it sends (or vice versa), producing a high asymmetry value.

---

**Q9. What is `byte_asymmetry` and why is it so important for MITM detection?**

**A:** In normal client-server traffic, there is a natural asymmetry (e.g., client sends small HTTP requests, server sends large responses). However, the ratio is bounded by the application semantics.

In a MITM relay, the attacker receives the full payload from the server AND sends the full payload to the victim — or vice versa. This creates a very different byte distribution pattern: the attacker-end flow shows near-perfect symmetry (same bytes in both directions) while the victim-end flows show high asymmetry. The CNN layer detects this cross-feature pattern efficiently.

---

**Q10. What is PIAT (Packet Inter-Arrival Time) and why does it matter for detecting relay floods?**

**A:** PIAT is the time gap between consecutive packets in a flow. In normal human-driven traffic, PIATs follow an exponential-like distribution with high variance (humans pause, think, click). In our relay flood:
- 50 connections × 8 sends with 20ms spacing
- This creates near-constant, very short PIATs (≈20ms gaps)
- `bidirectional_stddev_piat_ms` becomes very low
- `ps_variance_ratio` also drops

The CNN+LSTM model was trained to recognize this signature of machine-generated bulk relay traffic, which is a strong indicator of ARP poisoning.

---

**Q11. How did you train the model? What dataset did you use?**

**A:** The model was trained on a labelled network flow dataset — flows extracted from captured PCAP files or generated using tools like CICFlowMeter/nfstream, with MITM attack traffic labelled positive and normal traffic labelled negative. Features were standardized using `StandardScaler` (zero mean, unit variance) before training.

The `scaler` object is saved as a `.pkl` file alongside the model so that at inference time, the same scaling is applied. The trained model is saved in Keras `.h5` format and loaded at controller startup.

*If asked about specific dataset*: The project uses a synthetic dataset generated within the Mininet environment — this is a known limitation. Real-world validation on CICIDS or UNSW-NB15 datasets would be required for production-grade claims.

---

**Q12. What is your ML threshold? Why 0.5? Did you tune it?**

**A:** Our threshold is **0.5** — the default sigmoid midpoint. The model's final layer uses a sigmoid activation, so 0.5 represents the equal probability boundary between normal and attack.

In principle, this should be tuned based on the ROC curve to balance precision and recall for the application context. For security, we might prefer a lower threshold (e.g., 0.4) to favour recall (fewer missed attacks) at the cost of more false positives. For a demo project, 0.5 is the honest baseline choice. Threshold tuning is listed as future work.

---

**Q13. Why does the ML model get scores above 0.8 for ARP poisoning but sometimes lower?**

**A:** The score depends on **how many packets** the controller has seen when it runs inference. We require a minimum of 15 packets before scoring a flow. At 15 packets, the relay flood may have just started — features like `bidirectional_stddev_piat_ms` are still forming. After 30-50 packets (several seconds of relay traffic), the PIAT variance stabilizes and `byte_asymmetry` becomes clearly anomalous, pushing the score to 0.85-0.99.

Early scoring (< 15 packets) was previously giving inconsistent 0.3-0.6 scores. The 15-packet minimum ensures the controller only scores flows with enough statistical data to produce reliable predictions.

---

**Q14. What is the UserWarning: "X does not have valid feature names" and how did you fix it?**

**A:** `StandardScaler` remembers whether it was fitted on a pandas `DataFrame` (with named columns) or a numpy array. When fitted on a DataFrame, it stores feature names internally. If you then call `.transform()` with a raw numpy array, sklearn raises a `UserWarning` because it cannot verify the feature order.

Fix: at inference time, we wrap the feature vector in a `pd.DataFrame` with `columns=FEATURES`:
```python
df  = pd.DataFrame([[fd[f] for f in FEATURES]], columns=FEATURES)
vec = self.scaler.transform(df).astype(np.float32)
```
This ensures the scaler receives named features in the same order it was fitted on, eliminating the warning without changing the numerical output.

---

## SECTION 3 — Controller Architecture & Detection Logic

---

**Q15. Walk me through the entire lifecycle of an ARP poisoning detection — from the attacker's packet to the alert.**

**A:**
1. **Attacker** sends forged ARP replies: `"10.0.0.2 is at <attacker_MAC>"` to the victim.
2. **OVS switch** receives the ARP packet → table-miss rule sends it to Ryu (packet_in event).
3. **`_handle_arp()`** in the controller sees a new MAC claiming ownership of an IP that was previously mapped to a different MAC.
4. The IP is added to `arp_conflicts` and `arp_suspects` with a 20-second window.
5. **`_scan_flows_for_arp_suspect()`** immediately runs ML on any existing flows involving that IP.
6. As relay traffic flows through, **`_handle_ip()`** updates the `FlowTracker` for each flow.
7. Every 5 packets, **`_run_ml_on_flow()`** scores the flow. If score ≥ 0.5, `_trigger_alert()` fires.
8. After 20 seconds, **`_flush_old_arp_suspects()`** runs a final scan. If the best score ≥ 0.5, it confirms via ML. If no flows are scorable, it fires a rule-based alert (ARP conflict alone is sufficient evidence).
9. **`_trigger_alert()`** prints the detection box, adds the attacker MAC/IP to block lists, and installs DROP flow rules on the switch (priority 100).

---

**Q16. Why do you have both ML-based and rule-based detection? Why not just ML?**

**A:** Defence in depth. Two scenarios where rule-based is essential:

1. **DNS Hijacking**: DNS responses are very short (< 5 packets per query). The ML model cannot build reliable statistical features from 2-3 packets. Rule-based divergence detection (same domain resolving to two different IPs) is more reliable here.

2. **ARP Poisoning with no IP traffic**: If the attacker only sends ARP replies but no TCP/UDP flows follow (e.g., reconnaissance phase), the ML model has no flows to score. The ARP conflict itself is definitive evidence — rule-based catches this.

ML catches attacks that are statistically anomalous but don't trigger hard rules. Rule-based catches attacks with clear protocol violations that don't need statistical inference.

---

**Q17. What is the table-miss flow entry? What happens if you don't install it?**

**A:** A table-miss entry is an OpenFlow flow rule with priority 0 and an empty match (matches all packets). Its action is `OUTPUT:CONTROLLER`.

Without it: the switch has no instructions for packets that don't match any higher-priority rule. The default behaviour in secure mode is to **drop** them. The controller would never see any traffic → zero detection.

With it: every packet that doesn't match a learned forwarding rule is sent to the controller as a `PacketIn` event. This gives the controller full visibility into all traffic, which is the foundation of our inspection.

---

**Q18. Your controller does MAC learning. Does this interfere with detection? Can it cause missed detections?**

**A:** Yes, this is a real tension. Once the controller learns `MAC→port` mappings, it installs forwarding rules in the switch. Subsequent packets matching those rules are forwarded directly by the switch *without* reaching the controller (they don't generate PacketIn events).

This means once flows are established, the controller only sees new flows or flows that miss the flow table. For our detection, this is partially acceptable because:
- ARP packets always generate PacketIn (no forwarding rule matches ARP at layer 2 for new entries).
- The initial packets of each flow — enough to build statistics — do reach the controller.
- Flow statistics are built incrementally on each PacketIn.

However, if an attack starts after MAC learning stabilizes, we may miss some packets. A production system should install flow rules that always mirror copies of traffic to the controller. This is a known limitation of our prototype.

---

**Q19. How does your system block the attacker after detection?**

**A:** Two OpenFlow DROP rules are installed at priority 100 (higher than any normal rule):

```python
# Match by source MAC — blocks ALL traffic from attacker's MAC
parser.OFPMatch(eth_src=attacker_mac) → actions=[]   # empty = drop

# Match by source IP — blocks IP-layer traffic even if MAC is spoofed
parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip) → actions=[]
```

Both rules are installed because an attacker might change their MAC address (MAC spoofing) while keeping the same IP, or vice versa. The dual-rule approach provides more robust blocking. The attacker IP and MAC are also added to in-memory block lists so the controller ignores future PacketIn events from that source.

---

**Q20. What is `_flush_old_arp_suspects`? Why is there a 20-second window?**

**A:** When the controller sees an ARP conflict, it registers an "ARP suspect" entry with a timestamp. The 20-second window gives time for:
1. ARP cache updates to propagate (victims accept forged ARP within 1-2s).
2. Relay flood traffic to begin (our attacker waits 5s internally before starting relay).
3. Enough packets to accumulate for ML scoring (minimum 15 packets, at ~20ms/connection that's ~300ms for the flood).

After 20 seconds, `_flush_old_arp_suspects` runs a final ML sweep. If any flow involving the conflicting IP scored ≥ 0.5, it confirms via ML. If no flows are scorable (pure ARP scanning, no data), it fires a rule-based alert. This ensures no ARP attack is silently missed.

---

## SECTION 4 — System Design & Implementation

---

**Q21. Why did you use Mininet instead of a real physical network or a cloud environment?**

**A:**
- **Cost**: Physical network hardware (managed switches with OpenFlow support, e.g., HP ProCurve) is expensive.
- **Reproducibility**: Mininet creates identical topologies every run — essential for consistent evaluation.
- **Safety**: Running MITM attacks (ARP poisoning, RST injection) on a real/cloud network could disrupt real services and may be illegal.
- **Academic standard**: Mininet is the accepted testbed for SDN research papers (e.g., B4, ONOS, POX papers all use it).

Limitation: Mininet uses a single Linux kernel — processes share the same kernel network stack. Some timing-sensitive network behaviours may differ from real hardware.

---

**Q22. What is OVS (Open vSwitch)? How does it work with Ryu?**

**A:** OVS is a software OpenFlow switch that runs entirely in the Linux kernel. It maintains flow tables in kernel space for fast forwarding and communicates with an external controller over TCP.

Ryu connects to OVS on port 6633 via the OpenFlow 1.3 protocol. When OVS receives a packet that doesn't match any flow table entry (table-miss), it sends a `PacketIn` message to Ryu. Ryu processes it, makes a decision, and either:
- Sends a `PacketOut` (forward this specific packet)
- Sends a `FlowMod` (install a rule so future matching packets are forwarded automatically)

---

**Q23. Why did you face the "switch won't connect" problem? How did you fix it?**

**A:** OVS uses **exponential backoff** for controller reconnection. When a previous Mininet session leaves stale OVS state (old bridge `s1`, old controller pointer), OVS tries to reconnect to the dead controller and enters backoff. Each failed attempt doubles the wait: 1s → 2s → 4s → ... up to 60s.

Fix:
1. **Before topology start**: `ovs-vsctl --if-exists del-br s1` — removes the stale bridge surgically without disturbing Ryu.
2. **After `net.start()`**: `ovs-vsctl set controller s1 max_backoff=1000` — caps future backoff at 1 second.
3. **Immediately after**: `ovs-appctl -t ovs-vswitchd reconnect` — resets the backoff timer and forces an immediate connection attempt.
4. **Polling**: `wait_for_controller()` polls `ovs-vsctl get controller s1 is_connected` every 250ms and re-kicks reconnect every 2 seconds.

---

**Q24. What is the `relay_flood` function doing and why does it generate high ML scores?**

**A:** `relay_flood` launches 50 parallel TCP connections from the attacker to the server, each sending 8 data packets with 20ms spacing. This creates flows with:
- **Low `bidirectional_stddev_piat_ms`** (consistent 20ms gaps — machine-generated)
- **High `byte_asymmetry`** (the relay sends identical bytes to both victim and server)
- **Low `ps_variance_ratio`** (all packets have similar sizes)
- **Short `bidirectional_duration_ms`** with high packet count

These features collectively are very far from normal background traffic — the CNN+LSTM model scores them 0.85-0.99. This is honest: the relay flood genuinely represents anomalous proxied traffic.

---

**Q25. Why does the DNS attack only use rule-based detection? Why not ML?**

**A:** DNS attack detection relies on **semantic** anomaly, not statistical anomaly. The attacker sends two DNS responses for the same domain (`test.local`) from two different source IPs (10.0.0.2 and 10.0.0.99). Each individual DNS response looks completely normal statistically — it's just a short UDP packet. The anomaly only becomes visible when you *compare responses over time*.

This is a fundamentally different type of anomaly than the byte/timing statistics that ML models learn. Rule-based detection: `if len(dns_responses[domain]) > 1 → alert` catches this precisely. ML could theoretically learn DNS port traffic patterns, but would need to compare across multiple flows — a significantly more complex architecture.

---

## SECTION 5 — Evaluation & Limitations

---

**Q26. How did you evaluate your system? What metrics do you use?**

**A:** In our demo environment, we evaluate qualitatively:
- **Detection rate**: Did each attack type trigger an alert? (Yes for all 4)
- **ML score**: ARP poisoning consistently scores 0.85-0.99 after 15+ packets
- **False positives**: Normal traffic (ping, HTTP) does not trigger alerts
- **Response time**: Alert fires within 5-20 seconds of attack starting

For a rigorous academic evaluation, we should report: Precision, Recall, F1-score, False Positive Rate, and detection latency — measured on a held-out labelled dataset. This is a limitation of the current scope.

---

**Q27. What are the limitations of your system?**

**A:**
1. **Single switch topology**: A real campus network has tens of switches. Our system monitors traffic at one switch. Scaling to a multi-switch topology requires distributed flow tracking and per-switch table-miss rules.
2. **Mininet timing vs. real hardware**: OVS kernel forwarding latency is much lower than real switches. Attack timing parameters (5s wait, 20ms PIAT) are tuned for this environment.
3. **MAC learning blind spot**: After flow rules are installed, the controller sees fewer packets — some attack traffic may bypass inspection (discussed in Q18).
4. **No encrypted traffic inspection**: If the attacker uses TLS for the relay channel itself, byte statistics would look different. The model was not trained on encrypted relay traffic.
5. **Synthetic dataset**: The ML model was trained and tested on the same synthetic environment. Real-world generalization is unvalidated.
6. **No threshold tuning**: ML threshold is 0.5 (default) — not optimized via ROC analysis.
7. **Static topology**: IPs and MACs are hardcoded. Dynamic DHCP environments are not handled.

---

**Q28. How is your approach different from traditional IDS systems like Snort or Suricata?**

**A:**

| Aspect | Traditional IDS (Snort/Suricata) | Our SDN-based System |
|---|---|---|
| Deployment | Passive tap on network link | Active — at SDN controller |
| Detection | Signature/pattern matching on packet content | Flow-level statistical ML + protocol rule-based |
| Response | Alerts only (or out-of-band blocking via firewall) | Inline — installs DROP rules directly on switch |
| Visibility | Sees packet payloads | Sees flow metadata (no deep packet inspection needed) |
| Scalability | Needs sensors on every segment | Controller sees all traffic via OpenFlow |
| Encrypted traffic | Cannot inspect encrypted payloads | Flow statistics work regardless of encryption |

Our approach is **proactive** — the controller can block an attacker in real-time by installing DROP rules, not just alert after the fact.

---

**Q29. Could your system detect a sophisticated attacker who tries to evade detection?**

**A:** Evasion is possible. A sophisticated attacker could:
1. **Slow down the relay**: Use longer PIAT gaps to avoid low-variance timing signatures → lower ML score.
2. **Pad packets randomly**: Add random-size payloads to increase `ps_variance_ratio` → reduce detection confidence.
3. **Spoof the MAC address after poisoning**: Our MAC-based DROP rule would miss the attacker if they change MAC.

Countermeasures:
- The ARP conflict record (`arp_conflicts`) is keyed by IP, not MAC → IP-based DROP still applies.
- The ML model was trained on varied relay speeds; some robustness to timing evasion exists.
- Adversarial retraining (adding evasion-aware samples to the training set) would improve robustness.

This is a known open problem in ML-based intrusion detection — adversarial robustness.

---

**Q30. If you were to extend this project to a production environment, what would you change?**

**A:**
1. **Multi-controller setup with ONOS or OpenDaylight** instead of single Ryu instance — for high availability.
2. **Streaming flow export (IPFIX/NetFlow)** instead of relying on PacketIn — for scalability beyond a demo topology.
3. **Online learning**: Retrain the model periodically on new traffic samples to adapt to network behaviour changes.
4. **Encrypted traffic analysis** using TLS metadata (SNI, certificate fields) and packet length distributions — without breaking encryption.
5. **Proper dataset**: Evaluate on CICIDS2017, UNSW-NB15, or CIC-Bell-DNS datasets for published benchmark comparison.
6. **Threshold tuning**: ROC curve analysis on a proper validation split to select an optimal operating threshold.
7. **Hardware deployment**: Test on real OpenFlow-capable switches (HP Aruba, Pica8, or white-box switches with OVS).

---

## SECTION 6 — Rapid Fire (Quick-answer questions examiners often ask last)

---

**Q31. What port does the Ryu controller listen on?**
**A:** Port **6633** (the original OpenFlow port; 6653 is the IANA-assigned port, but Ryu defaults to 6633).

---

**Q32. What is a flow in OpenFlow?**
**A:** A flow is defined by a set of match fields (e.g., source IP, destination port, protocol) and associated actions (forward, drop, send-to-controller). When a packet matches a flow entry, the switch applies the corresponding action.

---

**Q33. What is the difference between PacketIn, PacketOut, and FlowMod?**
**A:**
- **PacketIn**: Switch → Controller. Switch forwards a packet it couldn't match.
- **PacketOut**: Controller → Switch. Controller tells the switch how to forward a specific packet.
- **FlowMod**: Controller → Switch. Controller installs a persistent flow rule for future matching packets.

---

**Q34. Why do you use `hub.spawn` in Ryu?**
**A:** Ryu uses **greenthreads** (via eventlet). `hub.spawn` creates a non-blocking concurrent coroutine — here, for the `_stats_loop` that runs every 10 seconds. If we used a regular Python thread, it could block the Ryu event loop.

---

**Q35. What is ARP and why is it vulnerable to poisoning?**
**A:** ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. It is vulnerable because:
1. It is **stateless** — any host accepts an ARP reply at any time, even without sending a request.
2. There is **no authentication** — any machine can claim to own any IP.
3. Switches and hosts **cache** ARP entries, so a forged reply overwrites the legitimate mapping.

---

**Q36. What is the difference between `src2dst_mean_piat_ms` and `bidirectional_mean_piat_ms`?**
**A:** `src2dst_mean_piat_ms` measures the average time between consecutive packets from *source to destination only*. `bidirectional_mean_piat_ms` measures the average time between *all* packets in the flow regardless of direction. In a MITM relay, these differ significantly — the relay sends data in bursts from one direction while the other direction has longer gaps.

---

**Q37. Why does your system use `warnings.filterwarnings("ignore")` at the top?**
**A:** The sklearn `StandardScaler` raises a `UserWarning` when called without named feature columns (numpy array vs. pandas DataFrame). Although we fixed this by passing a DataFrame, the `filterwarnings` suppresses any residual warnings from sklearn internals during batch processing. This is acceptable in a demo context; in production, all warnings should be resolved, not suppressed.

---

**Q38. What is the difference between `CONFIG_DISPATCHER` and `MAIN_DISPATCHER` in Ryu?**
**A:**
- `CONFIG_DISPATCHER`: Active when the switch first connects and exchanges capabilities. Used for installing the initial table-miss flow rule.
- `MAIN_DISPATCHER`: Active during normal operation — processing PacketIn events, installing forwarding rules, running detection logic.

---

**Q39. Can two different attacks trigger simultaneously in your system? How do you handle that?**
**A:** Yes. The `triggered_alerts` set uses `(ip, mac, attack_type)` as the key, so each unique combination can only alert once. If ARP poisoning and session hijacking are both detected on the same flow, two separate alerts fire — one for each type. The `attack_counts` dictionary tracks counts per attack type independently.

---

**Q40. What would happen to your system if the controller goes down mid-attack?**
**A:** OVS switches have a **fail mode** setting. In `fail_open` mode (default), the switch continues forwarding packets based on existing flow rules — the network stays up but detection stops. In `fail_secure` mode, the switch drops all traffic until the controller reconnects. For security, `fail_secure` is preferred. Our demo uses the default; setting `ovs-vsctl set bridge s1 fail-mode=secure` would be the production recommendation.

---

*End of Q&A — Good luck in your defense!*
