
Technical Deep-Dive: ML-Powered IDS for Software-Defined Networks

1. Research Problem and Architectural Overview
Modern networking is shifting from hardware-centric traditional routing to
Software-Defined Networking (SDN). While SDN offers centralized control, it
introduces a single point of failure and a high-value target: the Control Plane. This
project implements a Network Intrusion Detection System (NIDS) that leverages the
centralized visibility of the Ryu SDN Controller and the predictive power of a Hybrid
CNN-LSTM Deep Learning Model to mitigate Man-In-The-Middle (MITM) attacks in
real-time.

The SDN Architecture
* Data Plane: Consists of Open vSwitches (OVS) managed by Mininet. These switches
operate as "dumb" forwarding hardware that reacts based on flow table entries.
* Control Plane: The Ryu Controller, acting as the Network Operating System (NOS).
It communicates with the Data Plane via the OpenFlow 1.3 Protocol.
* Intelligence Layer: A Python-based ML inference engine integrated into the Ryu
application, utilizing TensorFlow and Scapy for deep packet and flow analysis.

---

2. Technical Analysis of Project Files

enterprise_topology.py (The Infrastructure Layer)
This script utilizes the Mininet API to instantiate a multi-subnet enterprise
environment.
* Subnet Isolation: It creates 5 distinct subnets (DMZ, Internal, Database,
Management, and Lab) connected via a LinuxRouter node. This router uses IP
forwarding (net.ipv4.ip_forward=1) and distinct interface names (e.g., r0-eth1) to
handle inter-VLAN/inter-subnet routing.
* Control/Data Plane Separation: Switches are explicitly configured for OpenFlow 1.3
and point to the Remote Controller at 127.0.0.1:6633.
* Attack Simulation Pipeline: The file orchestrates the "Lifecycle of an Attack,"
moving from baseline traffic generation to sophisticated SSL Stripping and Session
Hijacking phases.

my_controller.py (The Control Plane Logic)
This is the core of the project, implementing a Reactive Flow Management strategy.
* Event Handlers: Uses @set_ev_cls to hook into OpenFlow events like
EventOFPPacketIn and EventOFPSwitchFeatures.
* Flow Tracking: The FlowTracker class maintains a stateful 5-tuple (Src IP, Dst IP,
Src Port, Dst Port, Protocol) mapping. It computes real-time statistical features
such as Packet Inter-Arrival Time (PIAT), Byte Asymmetry, and Duration Ratios.
* Inference Triggering: The controller does not run ML on every packet (which would
cause control-plane saturation). Instead, it triggers inference every 5 packets
for active flows, ensuring a balance between detection latency and CPU overhead.
* Hybrid Detection Logic:
* Rule-Based: Immediate detection of ARP cache poisoning via IP-MAC mapping
conflict checks.
* ML-Based: CNN-LSTM scoring for traffic relay behavior.
* Fallback: If ML scores are inconclusive, it falls back to heuristic rules
(e.g., monitoring RST/ACK ratios for session hijacking).

train_model.py (The Intelligence Layer)
This file handles the Off-line Training Pipeline.
* Feature Engineering: Extracts 25 features derived from flow statistics. It uses
RFE (Recursive Feature Elimination) with a Random Forest estimator to select the
most discriminative features, reducing dimensionality and preventing the "Curse of
Dimensionality."
* Class Imbalance Mitigation: Uses SMOTE (Synthetic Minority Over-sampling
Technique). In network security, attack traffic is often much rarer than benign
traffic; SMOTE ensures the model doesn't become biased toward the "Normal" class.
* Scaling: Implements StandardScaler to ensure that features with large ranges (like
bidirectional_bytes) don't overwhelm features with small ranges (like
duration_ratio).

---

3. The Deep Learning Engine: CNN-LSTM Architecture

The project employs a Hybrid CNN-LSTM model, which is uniquely suited for network
traffic analysis.

1. CNN (Convolutional Neural Network) Layer:
* Treats the flow features as a 1D spatial vector.
* The convolutional filters act as automated feature extractors, identifying
complex relationships between disparate features like port numbers and packet
size variance.
2. LSTM (Long Short-Term Memory) Layer:
* Flows are essentially Time-Series data.
* The LSTM layer captures the temporal dependencies between packets. For
instance, in an SSL Stripping attack, the sequence of TCP SYN -> RST -> HTTP
GET is a temporal pattern that LSTM identifies more effectively than
traditional algorithms like Random Forest.
3. Output Layer: A sigmoid activation function produces a probability score in the
range $[0, 1]$. A score $> 0.5$ triggers a "Malicious" classification.

---

4. Technical Analysis of Attacks

ARP Poisoning (L2 Identity Spoofing)
* Mechanism: Exploits the stateless nature of the Address Resolution Protocol. The
attacker (atk1) broadcasts unsolicited ARP Reply packets to the gateway and the
victim.
* Network Impact: Maps the Victim’s IP to the Attacker’s MAC in the switch's CAM
table and the hosts' ARP caches, effectively redirecting all L3 traffic through
the Attacker's L2 interface.
* Detection: The Controller detects the IP-MAC Binding Conflict (Static analysis)
and verifies the relay behavior using ML (Dynamic analysis).

SSL Stripping (HTTPS Downgrade)
* Mechanism: The attacker intercepts the initial HTTP 302 redirect or HSTS header
and prevents the client from upgrading to Port 443 (TLS).
* Network Impact: Traffic that should be encrypted is forced into Port 80/8080
(Cleartext).
* Detection: The system monitors flows targeting Port 443. If a flow exhibits high
RST (Reset) ratios or packet size distributions typical of proxy-relayed traffic
(high asymmetry), it is flagged.

Session Hijacking (TCP Control Flow Manipulation)
* Mechanism: Attacker injects spoofed TCP packets with the correct Sequence and
Acknowledgment numbers to desynchronize the legitimate client.
* Network Impact: Results in a "TCP ACK Storm" or frequent RST packets as the
victim's OS tries to reconcile the invalid state.
* Detection: Monitored via the ps_variance_ratio and rst_ratio features. Legitimate
TCP teardowns follow a specific FIN/ACK sequence; hijacking attempts create
chaotic statistical outliers in the flow profile.

---

5. Working Mechanism: The Packet-to-Mitigation Pipeline

1. Packet-In (Southbound): An OVS switch receives a packet. If no matching flow
entry exists, it encapsulates the header and sends an OFPT_PACKET_IN message to
Ryu.
2. Feature Computation: Ryu's FlowTracker extracts the 5-tuple and updates the
sliding window statistics for that flow.
3. ML Inference (Northbound): Once the flow reaches a packet threshold, the feature
vector is fed into the mitm_model.h5. The model runs a forward pass to determine
the anomaly score.
4. Flow Mod (Mitigation): If the score indicates an attack, the Controller generates
an OFPFlowMod message.
* Priority: Set higher than the default forwarding rules (e.g., 100).
* Match: Specifically targets the malicious eth_src or ipv4_src.
* Instruction: The OFPIT_CLEAR_ACTIONS or an empty action list is used,
resulting in the switch dropping all subsequent packets from the attacker at
the hardware level (Line-rate mitigation).

---

6. Evaluation Metrics and Technical Justification

* Precision vs. Recall: In a network environment, High Precision is critical to
avoid "False Positives" (blocking legitimate users), while High Recall is critical
to ensure no attack goes undetected. The CNN-LSTM model optimizes the F1-Score,
the harmonic mean of both.
* Detection Latency: By performing inference on a per-flow basis rather than a
per-packet basis, the system maintains a sub-second detection time while keeping
the Controller's CPU utilization within acceptable limits for a production
environment.
* OpenFlow Advantages: Using OpenFlow allows for Granular Quarantine. Instead of
shutting down a whole port, we can drop only the specific malicious flow,
preserving the availability of the rest of the network.

---

7. Conclusion
This project demonstrates a robust implementation of an Intelligent Control Plane. By
combining traditional rule-based networking logic with deep learning, it addresses
the dynamic and evolving nature of MITM attacks, providing a scalable security
framework for modern SDN-enabled data centers.
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
> give  long even in depth technical explanation of this whole projectt
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
✦ This technical report provides an exhaustive, multi-layered analysis of the
ML-Powered SDN Intrusion Detection System (NIDS). It explores the intersection of
Software-Defined Networking (SDN) control-plane logic, deep learning architectures,
and cryptographic/network protocol vulnerabilities.

---

🛡 Technical Architecture: Autonomous SDN Intrusion Detection

1. The Paradigm: Software-Defined Security
Traditional network security relies on decentralized middleboxes (Firewalls, IDS)
that inspect traffic at specific points. In this project, we leverage SDN to
centralize intelligence.

By separating the Control Plane (the decision-maker) from the Data Plane (the
packet-forwarder), we gain "Global Network Visibility." The Ryu Controller sees every
new flow across every switch, allowing it to perform stateful flow analysis that is
impossible for traditional switches.

---

2. Infrastructure & Topology (The Data Plane)
The environment is instantiated using Mininet, simulating an enterprise-grade
hierarchical network.

A. Subnet Segmentation (enterprise_topology.py)
The project utilizes a LinuxRouter node to connect five distinct functional zones,
simulating VLAN/Subnet isolation:
* DMZ (10.0.1.0/24): Hosts public-facing services (HTTP Login Server, DNS).
* Internal (10.0.2.0/24): Contains the "Victim" and "Insider Attackers."
* Database/Management/Lab: Restricted zones for sensitive data and external testing.

B. Southbound Interface (OpenFlow 1.3)
The communication between the switches (Open vSwitch) and the Ryu controller follows
the OpenFlow 1.3 protocol.
* Reactive Flow Entry: When a switch receives a packet it doesn't recognize (a
"Table-Miss"), it encapsulates the header into an OFPT_PACKET_IN message and sends
it to the controller.
* Control Overhead: To minimize latency, the controller installs flow rules with a
specific "Hard Timeout," ensuring the switch handles subsequent packets at
line-rate hardware speeds without bothering the controller.

---

3. The Controller Logic (my_controller.py)
The Ryu application acts as the Network Operating System (NOS). It is responsible for
three primary tasks: Learning, Detection, and Mitigation.

A. Stateful Flow Tracking (FlowTracker Class)
The controller maintains a high-fidelity state of every active connection. It tracks
the 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol).
* Feature Extraction: For every packet, the controller calculates:
* PIAT (Packet Inter-Arrival Time): The delta between packets. MITM relays often
introduce "jitter," which shows up as high variance in PIAT.
* Byte Asymmetry: Calculated as $| \text{SrcBytes} - \text{DstBytes} | /
(\text{TotalBytes} + 1)$. This helps identify data exfiltration or relay
behavior.
* TCP Flags: It monitors the ratio of RST (Reset) to ACK (Acknowledgment)
packets to detect hijacking attempts.

B. Hybrid Detection Engine
The system uses a two-pronged approach:
1. Deterministic Rules: For ARP Poisoning, it checks the IP-MAC Binding. If IP
10.0.2.50 was first seen with MAC A, and suddenly appears with MAC B, a conflict
is flagged.
2. Probabilistic ML: If the rules are bypassed (e.g., sophisticated relaying), the
CNN-LSTM model provides a second opinion based on traffic behavior.

---

4. The Intelligence: CNN-LSTM Deep Learning
The core "Brain" of the project is a Hybrid Deep Learning Model (train_model.py).

A. The Architecture
* 1. Convolutional Neural Network (CNN) Layers: These layers treat the 25 extracted
features as a 1D signal. The filters perform Spatial Feature Extraction,
identifying hidden correlations between variables like src_port and
bidirectional_mean_ps (Packet Size).
* 2. Long Short-Term Memory (LSTM) Layers: Network traffic is essentially a
time-series. The LSTM layer provides Temporal Memory, allowing the model to
"remember" the sequence of packets. This is critical for detecting attacks like
SSL Stripping, where the order of messages (HTTP request $\rightarrow$ Redirect
$\rightarrow$ RST) is the indicator of malice.

B. Data Preprocessing & Optimization
* Feature Selection (RFE): Using Recursive Feature Elimination to find the top 20
most discriminative features, ensuring the model is lightweight enough for
real-time inference.
* SMOTE (Synthetic Minority Over-sampling): In any network, "Benign" traffic
outweighs "Attack" traffic 1000:1. SMOTE generates synthetic attack samples during
training so the model doesn't become biased toward the "Normal" class.
* Standardization: Using StandardScaler to normalize the data $(\mu=0, \sigma=1)$,
preventing features with large numbers (like bytes) from drowning out small but
vital features (like piat_variance).

---

5. Attack Vector Analysis

A. ARP Cache Poisoning
* Mechanism: The attacker sends unverified ARP responses to the victim, mapping the
Gateway’s IP to the Attacker’s MAC.
* Controller Detection: The Ryu controller detects the Gratuitous ARP and flags the
MAC conflict. It then monitors the resulting "Man-in-the-Middle" flow to see if
the ML score exceeds the $0.5$ threshold.

B. SSL Stripping (HTTPS Downgrade)
* Mechanism: The attacker intercepts a request to a secure site and forces the
victim to use HTTP (Port 80/8080) instead of HTTPS (Port 443).
* ML Detection: The model identifies this via ps_variance_ratio. Since the attacker
is acting as a proxy, the packet sizes and timing distributions deviate
significantly from a direct Client-Server TLS handshake.

C. Session Hijacking (TCP Desynchronization)
* Mechanism: Attacker injects spoofed TCP packets to reset the legitimate connection
and take over the session.
* Detection: High rst_ratio and packet_asymmetry. The controller tracks the sudden
spike in RST packets which indicates an attempt to terminate a legitimate socket.

---

6. The Mitigation Pipeline (Closing the Loop)
Once the ML model predicts an attack (Score $> 0.5$):

1. Alert Generation: The controller logs the event with the "Method" (e.g., ML MODEL
(CNN+LSTM)).
2. Flow-Mod Insertion: The controller sends an OFPFlowMod message to the switches.
* Priority: 100 (Highest).
* Match: eth_src = [Attacker MAC] or ipv4_src = [Attacker IP].
* Action: [] (Empty list). In OpenFlow, an empty action list means the switch
should DROP the packet.
3. Hardware-Level Blocking: Because this rule is now in the switch's hardware (TCAM
memory), the attacker is blocked at Line-Rate (nanoseconds), preventing any
further data theft.

---

7. Performance Evaluation Metrics
A network teacher would evaluate this project based on:
* Detection Latency: How many packets passed before the block was applied? (Our
system: ~5-10 packets).
* FPR (False Positive Rate): How often do we block legitimate users? (Minimally, due
to the high Precision of the CNN-LSTM).
* Controller CPU Overhead: The use of Batch Inference (scoring every 5 packets)
ensures that the Ryu controller does not become a bottleneck, maintaining the
scalability of the SDN architecture.

---

8. Summary of Files & Technical Purpose

┌────────────────────────┬────────────────┬──────────────────────────────────────┐
│ File                   │ Technical Role │ Networking/AI Concept                │
├────────────────────────┼────────────────┼──────────────────────────────────────┤
│ enterprise_topology.py │ Infrastructure │ L3 Routing, Subnetting, Mininet API  │
│ my_controller.py       │ NOS / Logic    │ OpenFlow 1.3, Event-driven           │
│                        │                │ Programming                          │
│ flow_collector.py      │ Telemetry      │ 5-tuple tracking, Statistical        │
│                        │                │ Feature Extraction                   │
│ train_model.py         │ Model Training │ Deep Learning (CNN+LSTM), SMOTE, RFE │
│ attacker_mitm.py       │ Exploitation   │ L2 Poisoning, Scapy Packet           │
│                        │                │ Manipulation                         │
│ mitm_model.h5          │ Inference      │ Neural Network Weights & Biases      │
│                        │ Brain          │                                      │
└────────────────────────┴────────────────┴──────────────────────────────────────┘


This project represents a Closed-Loop Self-Healing Network, where the AI acts as a
virtual security engineer, constantly monitoring and reconfiguring the hardware to
defend against sophisticated cyber threats.

