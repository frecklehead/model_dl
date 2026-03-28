# 🛡️ Technical Architecture: Autonomous SDN Intrusion Detection

This document provides a comprehensive analysis of the **ML-Powered SDN Intrusion Detection System (NIDS)**, integrating Software-Defined Networking (SDN), Deep Learning, and network protocol security.

---

## 1. The Paradigm: Software-Defined Security
Traditional network security relies on decentralized middleboxes (Firewalls, IDS) that inspect traffic at specific points. In this project, we leverage **SDN** to centralize intelligence. 

By separating the **Control Plane** (the decision-maker) from the **Data Plane** (the packet-forwarder), we gain "Global Network Visibility." The Ryu Controller sees every new flow across every switch, allowing it to perform **stateful flow analysis** that is impossible for traditional switches.

---

## 2. Infrastructure & Topology (The Data Plane)
The environment is instantiated using **Mininet**, simulating an enterprise-grade hierarchical network.

### A. Subnet Segmentation (`enterprise_topology.py`)
The project utilizes a `LinuxRouter` node to connect five distinct functional zones, simulating **VLAN/Subnet isolation**:
*   **DMZ (10.0.1.0/24):** Hosts public-facing services (HTTP Login Server, DNS).
*   **Internal (10.0.2.0/24):** Contains the "Victim" and "Insider Attackers."
*   **Database/Management/Lab:** Restricted zones for sensitive data and external testing.

### B. Southbound Interface (OpenFlow 1.3)
The communication between the switches (Open vSwitch) and the Ryu controller follows the **OpenFlow 1.3 protocol**. 
*   **Reactive Flow Entry:** When a switch receives a packet it doesn't recognize (a "Table-Miss"), it encapsulates the header into an `OFPT_PACKET_IN` message and sends it to the controller.
*   **Control Overhead:** To minimize latency, the controller installs flow rules with a specific "Hard Timeout," ensuring the switch handles subsequent packets at line-rate hardware speeds without bothering the controller.

---

## 3. The Controller Logic (`my_controller.py`)
The Ryu application acts as the **Network Operating System (NOS)**. It is responsible for three primary tasks: Learning, Detection, and Mitigation.

### A. Stateful Flow Tracking (`FlowTracker` Class)
The controller maintains a high-fidelity state of every active connection. It tracks the **5-tuple** (Src IP, Dst IP, Src Port, Dst Port, Protocol).
*   **Feature Extraction:** For every packet, the controller calculates:
    *   **PIAT (Packet Inter-Arrival Time):** The delta between packets. MITM relays often introduce "jitter," which shows up as high variance in PIAT.
    *   **Byte Asymmetry:** Calculated as $| \text{SrcBytes} - \text{DstBytes} | / (\text{TotalBytes} + 1)$. This helps identify data exfiltration or relay behavior.
    *   **TCP Flags:** It monitors the ratio of `RST` (Reset) to `ACK` (Acknowledgment) packets to detect hijacking attempts.

### B. Hybrid Detection Engine
The system uses a two-pronged approach:
1.  **Deterministic Rules:** For ARP Poisoning, it checks the **IP-MAC Binding**. If `IP 10.0.2.50` was first seen with `MAC A`, and suddenly appears with `MAC B`, a conflict is flagged.
2.  **Probabilistic ML:** If the rules are bypassed (e.g., sophisticated relaying), the CNN-LSTM model provides a second opinion based on traffic behavior.

---

## 4. The Intelligence: CNN-LSTM Deep Learning
The core "Brain" of the project is a **Hybrid Deep Learning Model** (`train_model.py`).

### A. The Architecture
*   **1. Convolutional Neural Network (CNN) Layers:** These layers treat the 25 extracted features as a 1D signal. The filters perform **Spatial Feature Extraction**, identifying hidden correlations between variables like `src_port` and `bidirectional_mean_ps` (Packet Size).
*   **2. Long Short-Term Memory (LSTM) Layers:** Network traffic is essentially a time-series. The LSTM layer provides **Temporal Memory**, allowing the model to "remember" the sequence of packets. This is critical for detecting attacks like SSL Stripping, where the *order* of messages (HTTP request $\rightarrow$ Redirect $\rightarrow$ RST) is the indicator of malice.

### B. Data Preprocessing & Optimization
*   **Feature Selection (RFE):** Using Recursive Feature Elimination to find the top 20 most discriminative features, ensuring the model is lightweight enough for real-time inference.
*   **SMOTE (Synthetic Minority Over-sampling):** In any network, "Benign" traffic outweighs "Attack" traffic 1000:1. SMOTE generates synthetic attack samples during training so the model doesn't become biased toward the "Normal" class.
*   **Standardization:** Using `StandardScaler` to normalize the data $(\mu=0, \sigma=1)$, preventing features with large numbers (like `bytes`) from drowning out small but vital features (like `piat_variance`).

---

## 5. Attack Vector Analysis

### A. ARP Cache Poisoning
*   **Mechanism:** The attacker sends unverified ARP responses to the victim, mapping the Gateway’s IP to the Attacker’s MAC.
*   **Controller Detection:** The Ryu controller detects the **Gratuitous ARP** and flags the MAC conflict. It then monitors the resulting "Man-in-the-Middle" flow to see if the ML score exceeds the $0.5$ threshold.

### B. SSL Stripping (HTTPS Downgrade)
*   **Mechanism:** The attacker intercepts a request to a secure site and forces the victim to use `HTTP` (Port 80/8080) instead of `HTTPS` (Port 443).
*   **ML Detection:** The model identifies this via `ps_variance_ratio`. Since the attacker is acting as a proxy, the packet sizes and timing distributions deviate significantly from a direct Client-Server TLS handshake.

### C. Session Hijacking (TCP Desynchronization)
*   **Mechanism:** Attacker injects spoofed TCP packets to reset the legitimate connection and take over the session.
*   **Detection:** High `rst_ratio` and `packet_asymmetry`. The controller tracks the sudden spike in `RST` packets which indicates an attempt to terminate a legitimate socket.

---

## 6. The Mitigation Pipeline (Closing the Loop)
Once the ML model predicts an attack (Score $> 0.5$):

1.  **Alert Generation:** The controller logs the event with the "Method" (e.g., `ML MODEL (CNN+LSTM)`).
2.  **Flow-Mod Insertion:** The controller sends an `OFPFlowMod` message to the switches.
    *   **Priority:** 100 (Highest).
    *   **Match:** `eth_src = [Attacker MAC]` or `ipv4_src = [Attacker IP]`.
    *   **Action:** `[]` (Empty list). In OpenFlow, an empty action list means the switch should **DROP** the packet.
3.  **Hardware-Level Blocking:** Because this rule is now in the switch's hardware (TCAM memory), the attacker is blocked at **Line-Rate** (nanoseconds), preventing any further data theft.

---

## 7. Performance Evaluation Metrics
A network teacher would evaluate this project based on:
*   **Detection Latency:** How many packets passed before the block was applied? (Our system: ~5-10 packets).
*   **FPR (False Positive Rate):** How often do we block legitimate users? (Minimally, due to the high Precision of the CNN-LSTM).
*   **Controller CPU Overhead:** The use of **Batch Inference** (scoring every 5 packets) ensures that the Ryu controller does not become a bottleneck, maintaining the scalability of the SDN architecture.
