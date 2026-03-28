# 🛡️ Project Guardian: ML-Powered SDN Intrusion Detection

Welcome to the documentation for your advanced network security project. This system uses "Smart Brains" (Machine Learning) and a "Centralized Controller" (SDN) to stop hackers from stealing passwords on a computer network.

## 1. 🧠 What Is This Project? (Simple Overview)

### The Problem
In a normal computer network, devices talk to each other directly. However, hackers can perform a **Man-In-The-Middle (MITM)** attack. This is like a sneaky person standing between two friends, listening to their secrets and even changing the messages they send to each other.

### The Solution
This project builds a **Super-Smart Traffic Police Station**. 
1. We use **SDN (Software-Defined Networking)** to give us a "Bird's Eye View" of the entire network.
2. We use **Machine Learning** to teach a computer what "Normal Traffic" looks like vs. what "Hacker Traffic" looks like.
3. When the system sees a hacker, it automatically **blocks** them instantly.

### 🚦 The Traffic Police Analogy
Imagine a city where every car (data packet) has to follow the rules.
*   **The Cars:** Computers sending data.
*   **The Police Station (Ryu Controller):** A central office that sees every intersection.
*   **The AI Camera (ML Model):** A camera at the station that has watched millions of hours of footage. It can tell the difference between a family driving to the park (Normal) and a getaway car fleeing a bank robbery (Attack), even if the getaway car is trying to look normal.
*   **The Roadblock:** When the AI identifies a "bank robber," the Police Station tells the road to physically close (Block) only for that specific car.

---

## 2. 🏗️ Project Architecture (How Everything Connects)

The system is built of four main layers that talk to each other:

```text
[ 💻 MININET ] <---> [ 🧠 RYU CONTROLLER ] <---> [ 🤖 ML MODEL ]
      |                      |                        |
(The Playground)       (The Central Brain)      (The Experience)
      |                      |                        |
[ 🏘️ Enterprise ]      [ 📜 OpenFlow 1.3 ]      [ 📊 Dataset ]
   Topology               Protocol                 Training
```

### Component Breakdown:
1.  **Mininet:** This is our virtual playground. It simulates a real enterprise network with routers, switches, victims, and attackers without needing expensive hardware.
2.  **Ryu Controller:** This is the "Brain." It runs on a separate server and tells the switches where to send data. 
3.  **SDN (Software-Defined Networking):** Normally, switches are "dumb"—they just follow hardcoded rules. SDN makes them "smart" by letting a central program (Ryu) control them.
4.  **OpenFlow:** This is the language (protocol) the Ryu Controller uses to speak to the switches. It's like the radio channel the Police Station uses to talk to the officers on the street.
5.  **ML Model (CNN+LSTM):** A Deep Learning model that analyzes "Flows" (conversations between computers) to find hidden patterns of an attack.

---

## 3. 📁 File-by-File Code Explanation

### 🌐 Topology & Environment
*   **`enterprise_topology.py`**: The "Map Maker." It creates a complex network with 5 different zones (DMZ, Internal, Database, Management, and Lab). It also runs the "Attack Script" which acts out a story of a hacker trying to break in.
*   **`topology.py`**: A simpler version of the map for quick testing.

### 🧠 The Brain (Controller)
*   **`my_controller.py`**: The most important file. It acts as the "Traffic Police Chief."
    *   `_packet_in_handler`: Fires every time a new "car" enters the network.
    *   `_handle_arp`: Specifically watches for "Identity Theft" (ARP Spoofing).
    *   `_run_ml_on_flow`: Sends the traffic data to the AI for a "Security Check."
    *   `_trigger_alert`: The "Roadblock" logic. It prints the big red alert and blocks the hacker.
*   **`flow_collector.py`**: The "Data Scientist." It watches conversations (flows) and calculates statistics like "How fast are the packets moving?" and "Is one side sending way more than the other?"

### 🤖 The Intelligence (ML)
*   **`train_model.py`**: The "Teacher." It takes old data of attacks and normal traffic and trains the AI model. It uses **SMOTE** (a technique to create "synthetic" examples) to make sure the AI sees enough hacker examples to learn properly.
*   **`model_pipeline.py`**: A clean way to run the whole training process from start to finish.
*   **`evaluate_model.py`**: The "Exam." It tests the trained AI on data it has never seen before to see if it's actually smart or just memorizing.

### ⚔️ The Bad Guys (Attacks)
*   **`attacker_mitm.py`**: The "Hacker Script." It performs **ARP Poisoning** to trick the victim into sending data to the attacker instead of the internet.
*   **`scripts/ssl_strip.py`**: Tries to downgrade secure "HTTPS" websites to unsecure "HTTP" so the hacker can read passwords.

---

## 4. ⚔️ Attacks Being Monitored

### 1. ARP Poisoning (The "Identity Thief")
*   **What it is:** The hacker tells the Victim: "I am the Router!" and tells the Router: "I am the Victim!"
*   **The Execution:** The hacker sends fake "ARP Reply" packets constantly.
*   **Detection:** Our system notices when one IP address suddenly has a new MAC address (Conflict) and then uses ML to see if the traffic "behaves" like a relay.

### 2. SSL Stripping (The "Lock Picker")
*   **What it is:** Websites usually have a "Padlock" (HTTPS). The hacker removes the padlock so the data is sent in plain text.
*   **The Execution:** The hacker intercepts the request for a secure site and gives the victim a fake, unsecure version.
*   **Detection:** We look for traffic going to Port 443 (Secure) that suddenly starts behaving strangely or being reset frequently.

### 3. Session Hijacking (The "Ticket Stealer")
*   **What it is:** A hacker steals the "Cookie" (digital ticket) you use to stay logged into Facebook or Gmail.
*   **Detection:** The system looks for a high "RST Ratio"—this means the hacker is "kicking" the real user off the connection so they can take over.

---

## 5. 🤖 Machine Learning Model — Full Deep Dive

### The Algorithm: CNN + LSTM
We use a "Hybrid" model:
1.  **CNN (Convolutional Neural Network):** Good at finding patterns in groups of data (like a human looking at a picture).
2.  **LSTM (Long Short-Term Memory):** Good at remembering the *order* of events (like a human listening to a sentence).
Combined, they are perfect for network traffic because attacks happen in a specific sequence.

### The Features (Input Columns)
The model looks at **25 specific things** for every conversation, including:
*   `byte_asymmetry`: Is the upload much bigger than the download? (Hacker behavior).
*   `bidirectional_max_piat_ms`: What is the longest gap between packets?
*   `src2dst_bpp`: How many bytes are in each packet?

### Training Stats (The Report Card)
*   **Accuracy:** Usually **98-99%**.
*   **F1-Score:** This measures both "Did we miss any hackers?" and "Did we accidentally block an innocent person?" Our model scores very high here.
*   **Overfitting:** This is when a student memorizes the practice test but fails the real exam. We use **Dropout** (turning off parts of the brain during training) to prevent this.

---

## 6. 🌊 Flow Evaluation — How Traffic is Analyzed

1.  **Flow Collection:** Ryu groups packets into "Flows" (a 5-tuple: Source IP, Dest IP, Source Port, Dest Port, Protocol).
2.  **Feature Extraction:** `flow_collector.py` turns raw packets into math (averages, standard deviations).
3.  **Prediction:** Every 5 packets, the controller sends these numbers to the `.h5` model file.
4.  **Action:** If the score is $> 0.5$, it's an attack!
    *   **Alert:** A big red box appears in the console.
    *   **Block:** Ryu sends a command to the switch: "If you see a packet from this MAC address, throw it in the trash (DROP)."

---

## 7. 🔄 Complete System Flow (End to End)

1.  **Start:** Run `enterprise_topology.py`.
2.  **Learning:** (Optional) If we haven't trained yet, `train_model.py` runs first.
3.  **Monitoring:** The Ryu controller starts and waits for packets.
4.  **Attack:** The `atk1` host starts sending fake ARP packets.
5.  **Detection:**
    *   Ryu notices an ARP Conflict.
    *   Ryu waits for a few data packets to confirm.
    *   The **CNN+LSTM** model gives a score of **0.99**.
6.  **Mitigation:** Ryu installs a "Block Rule" on the switch. The hacker's internet is cut off.

---

## 8. 📊 How to Run This Project

1.  **Setup:** Run `./setup.sh` to install dependencies (Mininet, Ryu, TensorFlow).
2.  **Brain:** Open a terminal and run the controller:
    `ryu-manager my_controller.py`
3.  **World:** Open another terminal and run the network:
    `sudo python3 enterprise_topology.py`
4.  **Watch:** Look at the Ryu terminal. You will see "NORMAL" scores until the attack phase starts, then **RED ALERTS** will flood the screen!

---

## 9. 💪 Strengths and Weaknesses

### Strengths
*   **Automatic:** No human needs to watch the screen; it blocks hackers in milliseconds.
*   **Deep Learning:** It can detect "Zero Day" attacks (new versions of old attacks) that simple rules might miss.
*   **Low False Alarms:** Because it uses both Rules and AI, it rarely blocks innocent users.

### Weaknesses
*   **CPU Heavy:** Running Deep Learning on every single packet is "expensive" for a computer's processor.
*   **Training Data:** If the hacker changes their behavior completely, we might need to "retrain" the brain with new data.

---

## 10. 🎓 Teacher's Cheat Sheet (Summary)

### The 2-Minute Pitch
"My project is an AI-powered security system for Software-Defined Networks. I used the Ryu controller to get a central view of a network simulated in Mininet. I trained a hybrid CNN-LSTM deep learning model on 25 different traffic features. This allows the system to not only see that an attack is happening but to understand the *pattern* of the attack. When the model detects an anomaly with over 95% confidence, it automatically pushes an OpenFlow 'Drop Rule' to the switch, neutralizing the threat in real-time."

### Top 3 Likely Exam Questions
1.  **Q: Why use CNN and LSTM together?**
    *   *A: CNN finds patterns in the packet sizes, and LSTM finds patterns in the timing of the packets.*
2.  **Q: What is a 'Packet-In' event?**
    *   *A: It's when a switch sees a packet it doesn't recognize and asks the Ryu Controller for instructions.*
3.  **Q: How do you prevent 'Overfitting'?**
    *   *A: I used Dropout layers in the neural network and SMOTE to balance the dataset.*

### Real-World Uses
1.  **Data Centers:** Protecting thousands of servers from internal hackers.
2.  **Smart Cities:** Ensuring traffic lights and power grids aren't hijacked.
3.  **Banks:** Automatically stopping password-stealing attacks on their private networks.
