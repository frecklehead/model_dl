# Complete Project Documentation
## Detection of Man-in-the-Middle (MITM) Attacks with Flow-Level Monitoring

---

## Part 1: What Is This Project? (For Absolute Beginners)

### The Problem — In Simple Words

Imagine you are texting your friend, but without you knowing, someone is standing between you, reading every message, and sometimes changing what you write before forwarding it. That person is the "Man-in-the-Middle." In computer networks, this is called a **MITM attack**.

The most common way MITM attacks happen on local networks is through **ARP Spoofing**:

- Every device on a network has two addresses: an **IP address** (like a house number) and a **MAC address** (like the name on the mailbox).
- When your computer wants to talk to the server, it sends a broadcast: "Who has IP 10.0.0.2?"
- The server replies: "That's me — my MAC is AA:BB:CC."
- Now your computer sends traffic directly to AA:BB:CC.

**ARP spoofing breaks this:**

The attacker constantly sends fake replies: "10.0.0.2? That's ME — my MAC is DD:EE:FF."
Your computer believes it and now sends everything to the attacker instead.
The attacker reads your data, then silently forwards it to the real server so you don't notice.

**Our project detects this attack automatically using Machine Learning.**

---

### The Solution — In Simple Words

We built a system with two layers of defense:

1. **Rule-based detection (fast, simple):** The SDN controller (Ryu) watches every ARP packet. It remembers who said what MAC address belongs to what IP. The moment someone lies (sends a different MAC for the same IP), it raises an alarm and blocks the attacker.

2. **ML-based detection (smart, deep):** Even if someone does a more subtle attack that doesn't trigger ARP rules, our trained neural network looks at the statistical patterns of network flows (how much data is flowing, from where, how fast, how symmetric) and decides: is this normal traffic, or is an attacker relaying traffic through themselves?

---

## Part 2: How Everything Is Connected — The Big Picture

```
Your Laptop
  |
  |-- Mininet (virtual network simulator)
  |     |-- h1: Victim  (IP: 10.0.0.1) -- sends login credentials
  |     |-- h2: Server  (IP: 10.0.0.2) -- runs a login web page
  |     |-- h3: Attacker(IP: 10.0.0.3) -- performs ARP spoofing
  |     |-- s1, s2: Virtual switches (controlled by Ryu)
  |
  |-- Ryu Controller (runs in Docker)
  |     |-- Controls all switches via OpenFlow protocol
  |     |-- Monitors every packet that passes through
  |     |-- Detects ARP spoofing (Rule-based Layer 1)
  |     |-- Feeds flow stats to ML model (ML Layer 2)
  |
  |-- ML Model (model/mitm_model.h5)
        |-- Trained on ~148,000 labeled network flows
        |-- CNN + BiLSTM + Attention architecture
        |-- Input: 25 statistical features of a network flow
        |-- Output: 0 = Normal, 1 = MITM Attack
```

**Think of it like a hospital:** Ryu is the triage nurse (catches obvious emergencies instantly), and the ML model is the specialist doctor (catches subtle cases that look normal on the surface).

---

## Part 3: Every File Explained

### Core Files

| File | What It Does | When It Runs |
|------|-------------|--------------|
| `model_pipeline.ipynb` | Trains the ML model — the brain of detection | Once, before demo |
| `topology.py` | Creates the virtual network (h1, h2, h3, s1, s2) | Every demo session |
| `flow_collector.py` | Collects live flow statistics from the running network | During demo |
| `run_demo.py` | Orchestrates the full demo automatically | For presentation |
| `Dockerfile` | Instructions to build the Ryu controller Docker image | Once during setup |
| `docker-compose.yml` | Defines how to run the Docker container | During setup |
| `setup.sh` | Shell script that installs all dependencies | Once |

### scripts/ Folder (runs INSIDE Mininet hosts)

| File | What It Does | Runs On |
|------|-------------|---------|
| `scripts/server_login.py` | Fake bank login page (HTTP server on port 8080) | h2 (server) |
| `scripts/victim_traffic.py` | Simulates victim browsing and logging in | h1 (victim) |
| `scripts/attacker_mitm.py` | Performs the real ARP poisoning MITM attack | h3 (attacker) |
| `scripts/session_hijack.py` | Extended attack: hijacks an active session | h3 (attacker) |

### dataset/ Folder

Five real-world CSV files containing labeled network flows:

| File | Rows | Source |
|------|------|--------|
| `All_Labelled.csv` | 74,343 | Mixed real captures |
| `CIC_MITM_ArpSpoofing_All_Labelled.csv` | 69,248 | CIC dataset (Canadian Institute) |
| `GIT_arpspoofLabelledData.csv` | 246 | GitHub-sourced captures |
| `UQ_MITM_ARP_labeled_data.csv` | 3,478 | University of Queensland |
| `iot_intrusion_MITM_ARP_labeled_data.csv` | 1,371 | IoT environment captures |

Each row is one **network flow** — a conversation between two devices. Each column is a statistical measurement of that conversation (how many packets, how many bytes, how long it lasted, etc.).

Labels are either `normal` (regular traffic) or `arp_spoofing` (attack traffic).

### model/ Folder (created automatically after training)

| File | What It Does |
|------|-------------|
| `model/mitm_model.h5` | The trained neural network weights |
| `model/scaler.pkl` | The StandardScaler — must be applied to new data before feeding to model |
| `model/selected_features.pkl` | The list of 25 features the model expects |
| `model/results.json` | JSON with all performance metrics |
| `model/best_checkpoint.h5` | Best model checkpoint saved during training |

### plots/ Folder (generated by notebook)

| File | What It Shows |
|------|--------------|
| `01_label_distribution.png` | Bar chart of normal vs attack counts |
| `02_feature_importance.png` | Which features matter most (RF-RFE) |
| `03_split_distributions.png` | Class balance in train/val/test sets |
| `04_training_history.png` | How accuracy, loss, AUC improved over epochs |
| `05_confusion_matrix.png` | Prediction vs truth (counts + percentages) |
| `06_roc_pr_curves.png` | ROC and Precision-Recall curves |
| `07_score_distribution.png` | Histogram of model confidence scores |
| `08_metrics_summary.png` | Bar chart of all final metrics |
| `09_cross_validation.png` | Box plot of 5-fold cross-validation results |

---

## Part 4: How the ML Pipeline Works — Step by Step

### Step 1: Load and Merge Data

We load all 5 CSV files and stack them into one big table (~148,000 rows). Different files have slightly different column names for the label, so we normalize them all to "Label".

**Why merge?** More diverse data = model learns more general patterns, not just memorizing one source.

### Step 2: Drop Non-Feature Columns

We remove columns like IP addresses, MAC addresses, timestamps, and application names. These are **identifiers**, not **behavioral patterns**.

- IP address: tells us WHO is talking, not HOW — an attacker can use any IP
- Timestamps: absolute time values don't generalize across captures
- Application names: not always available in real-time detection

We keep only numeric statistical measurements that describe the *behavior* of the flow.

### Step 3: Binary Label Encoding

We convert text labels to numbers:
- `normal` / `benign` / `0` → **0** (no attack)
- `arp_spoofing` / `MITM` / `Attack` → **1** (attack)

This is because neural networks work with numbers, not text.

### Step 4: Handle Missing and Infinite Values

Some features (like division-based ratios) can be infinite (dividing by zero) or missing (NaN). We replace all of these with 0. This prevents the model from crashing on bad input.

### Step 5: Feature Engineering — The 10 Custom Features

These features are **not** in the original dataset. We calculate them ourselves because they capture MITM-specific behavioral signatures:

| Feature | What It Measures | Why It Detects MITM |
|---------|-----------------|---------------------|
| `packet_asymmetry` | Imbalance between packets sent vs received | MITM relay creates 3-way asymmetry |
| `byte_asymmetry` | Imbalance between bytes sent vs received | Relayed data has different sizes |
| `bytes_per_packet` | Average packet size | MITM header modifications change sizes |
| `src2dst_bpp` | Bytes per packet (source to destination) | Directional size anomaly |
| `dst2src_bpp` | Bytes per packet (destination to source) | Directional size anomaly |
| `duration_ratio` | Ratio of flow duration in each direction | Extra hop adds latency asymmetry |
| `syn_ratio` | Proportion of SYN packets | ARP poisoning triggers reconnections |
| `rst_ratio` | Proportion of RST packets | Connection resets during attack |
| `piat_variance_ratio` | Variability in time between packets | Relaying adds jitter |
| `ps_variance_ratio` | Variability in packet sizes | Manipulation changes size distribution |

**Think of it like a doctor's vitals:** just measuring blood pressure gives some info, but calculating the ratio of systolic to diastolic gives richer diagnostic power.

### Step 6: Feature Selection (RF-RFE)

We started with ~60 features. Training a model on all of them wastes computation and can cause **overfitting** (model memorizes irrelevant noise).

We use **Recursive Feature Elimination (RFE)** with a **Random Forest** as the judge:
1. Train a Random Forest on all features
2. Rank features by how much they help the forest decide correctly
3. Remove the 5 least useful features
4. Repeat until we have 25 features

**Think of it like packing for a trip:** you start with everything you own, then keep removing least-useful items until your suitcase has only what truly matters.

This is done on a sample of 50,000 rows for speed.

### Step 7: Split the Data

We divide the data into three separate groups that never mix:

| Split | Size | Purpose |
|-------|------|---------|
| Training set | 70% | Model learns from this |
| Validation set | 10% | Model tuned on this (early stopping) |
| Test set | 20% | Final honest evaluation |

**Why three splits?** If you use the same data to train and test, you get falsely optimistic scores. It's like studying from the exam paper itself. The test set is kept completely hidden until the very end.

### Step 8: Normalization (StandardScaler)

Neural networks work best when all input features are on similar scales. Without normalization:
- `bidirectional_bytes` can be in the millions
- `syn_ratio` is between 0 and 1

The model would spend more "attention" on the large numbers simply because they are bigger, not because they matter more.

StandardScaler converts every feature to: `z = (value - mean) / standard_deviation`

This centers every feature around 0 with a spread of 1.

**Important:** The scaler is **fit only on training data**, then applied to val and test. This prevents "data leakage" — the model never peeks at test distribution statistics during training.

### Step 9: Class Weighting (the fix for val > train accuracy)

Our dataset has a mild class imbalance (more normal than attack samples in some sources). We tell the model to penalize misclassifying the minority class more heavily:

```
class_weight = {
    0 (Normal): 1.0 (approximate),
    1 (MITM):   heavier weight
}
```

The model's loss function now multiplies the error on MITM samples by this weight, forcing it to pay extra attention to getting attacks right.

**Why this instead of SMOTE?**

SMOTE (Synthetic Minority Over-sampling Technique) creates *fake* training samples by interpolating between real ones. This caused a weird artifact:
- Training data: lots of synthetic (artificial) samples → harder to classify perfectly → lower train accuracy
- Validation data: only real samples + Dropout is OFF → higher val accuracy

This made it look like val accuracy > train accuracy, which is suspicious and misleading.

With class_weight: training data stays 100% real, both sets are evaluated in comparable conditions, and the gap disappears.

### Step 10: Training

The model runs through the training data in batches of 512 flows at a time. After each batch, it updates its weights to make slightly better predictions.

**Callbacks** make training smarter:
- **EarlyStopping**: If validation loss doesn't improve for 7 epochs, stop training and restore the best weights. Prevents overfitting.
- **ReduceLROnPlateau**: If validation loss plateaus for 3 epochs, halve the learning rate. Helps the model find finer improvements.
- **ModelCheckpoint**: Saves the best model to disk during training.

### Step 11: Evaluation

We evaluate the final model on the **test set only** (data never seen during training or validation):

- **Accuracy**: What percentage of flows are classified correctly
- **Precision**: Of all predicted attacks, how many were real attacks (false alarm rate)
- **Recall**: Of all real attacks, how many did we catch (miss rate)
- **F1-Score**: Harmonic mean of precision and recall — single balanced score
- **ROC-AUC**: Area under the ROC curve — measures discrimination ability (1.0 = perfect, 0.5 = random)
- **PR-AUC (Average Precision)**: More informative for imbalanced datasets than ROC-AUC
- **MCC (Matthews Correlation Coefficient)**: Best single metric for binary classification — accounts for all four cells of confusion matrix. Range: -1 to +1, where +1 is perfect.

### Step 12: 5-Fold Cross-Validation

For publication, a single train/test split is not enough — results depend on which data ended up in which split by chance.

5-fold CV:
1. Divide all data into 5 equal parts
2. Train on 4 parts, test on the 1 remaining part
3. Repeat 5 times, rotating which part is held out
4. Report: Mean ± Standard Deviation across all 5 runs

This gives statistically robust results: "Our model achieves F1 = 0.98 ± 0.01" is much stronger than "Our model achieves F1 = 0.98 on one run."

---

## Part 5: The Neural Network Architecture — Deep Dive

### Why CNN + BiLSTM + Attention?

Each component captures a different type of pattern:

#### CNN (Convolutional Neural Network)

In image recognition, CNN looks at small patches of pixels to find edges and textures. In our case, after RFE ordering, neighboring features often have related meaning (e.g., `src2dst_packets` and `dst2src_packets` are adjacent). CNN with kernel_size=3 looks at groups of 3 consecutive features and finds local correlations between them.

```
[f1, f2, f3, f4, f5 ... f25]  (25 features)
  |_____|                       <- CNN kernel detects local pattern
        |_____|
              |_____|
```

Two CNN layers with increasing filter counts (64, then 128) learn increasingly abstract patterns.

#### Bidirectional LSTM

LSTM (Long Short-Term Memory) is designed for **sequences** — data with temporal or positional dependencies. After the CNN's MaxPooling, the feature sequence is compressed. The BiLSTM reads this compressed representation both **forward** (feature 1 → 25) and **backward** (feature 25 → 1), then concatenates both directions.

This is better than a one-direction LSTM because:
- Some features make more sense in context of later features
- Both directions of context are captured simultaneously

#### Multi-Head Self-Attention

Attention asks: "Which features are most important for THIS specific flow?"

For a normal flow, maybe `packet_asymmetry` and `byte_asymmetry` are the key signals.
For an attack flow, maybe `piat_variance_ratio` and `syn_ratio` matter most.

Self-Attention dynamically weights each feature's contribution per sample. "Multi-head" means it learns multiple different types of attention simultaneously (2 heads in our architecture).

A residual connection is added (the input is added back to the attention output) to prevent the gradients from vanishing during training.

#### Full Architecture Flow

```
Input: 25 features, reshaped to (25, 1) for CNN
    |
    v
Conv1D(64 filters, kernel=3) -- looks at 3 features at a time, learns 64 different patterns
BatchNormalization -- normalizes activations for stable training
MaxPooling1D(2) -- compresses from 25 to 12 (takes max of each pair)
Dropout(0.15) -- randomly zeros 15% of neurons to prevent overfitting
    |
    v
Conv1D(128 filters, kernel=3) -- 128 deeper, more abstract patterns
BatchNormalization
MaxPooling1D(2) -- compresses from 12 to 6
Dropout(0.15)
    |
    v
Bidirectional LSTM(64 units, return_sequences=True)
-- 64 units forward + 64 units backward = 128 total per timestep
-- return_sequences=True: keeps all 6 timestep outputs (for attention)
Dropout(0.20)
    |
    v
Multi-Head Self-Attention (2 heads, 32 key dimensions)
Add (residual) + LayerNormalization
    |
    v
GlobalAveragePooling1D -- averages across the 6 timesteps into one 128-dim vector
    |
    v
Dense(64, relu, L2 regularization) -- dense interpretation layer
BatchNormalization
Dropout(0.20)
    |
    v
Dense(32, relu, L2 regularization) -- further compression
Dropout(0.15)
    |
    v
Dense(1, sigmoid) -- output between 0 and 1
    |
    v
Output: >= 0.5 -> MITM Attack (1) | < 0.5 -> Normal (0)
```

---

## Part 6: The SDN + Mininet System

### What is SDN (Software Defined Networking)?

Traditional networks: each switch independently decides how to forward packets (like many independent traffic cops making their own decisions).

SDN separates the **control plane** (who decides) from the **data plane** (who forwards):
- All decisions happen in one place: the **Ryu Controller**
- Switches just follow orders from the controller via the **OpenFlow protocol**

This gives us global visibility — the controller sees ALL traffic on ALL switches.

### What is Mininet?

Mininet creates a **virtual network** on your laptop. It simulates real hosts (h1, h2, h3), real switches (s1, s2), and real links — all in software. Network namespaces in Linux isolate each host so they think they are separate machines with separate network stacks.

### Attack and Detection Flow

```
Normal State:
h1 sends: "Who has 10.0.0.2?" (ARP Request, broadcast)
h2 replies: "I have 10.0.0.2, my MAC is AA:BB:CC" (ARP Reply)
Ryu records: { 10.0.0.2 -> AA:BB:CC }
h1 stores: ARP cache { 10.0.0.2 -> AA:BB:CC }
h1 now sends data directly to AA:BB:CC (h2's MAC) -- secure

Attack Begins:
h3 starts sending unsolicited ARP Replies:
  "I have 10.0.0.2, my MAC is DD:EE:FF" (lie -- h3's MAC)
h1's ARP cache gets updated: { 10.0.0.2 -> DD:EE:FF }  <- poisoned!
h1 now sends data to DD:EE:FF (h3!) thinking it's h2

Detection:
Ryu receives the ARP Reply: "10.0.0.2 is DD:EE:FF"
Ryu checks its table: "But I know 10.0.0.2 was AA:BB:CC!"
MISMATCH -> ARP Spoofing Alert!
Ryu installs a DROP rule: any packet from DD:EE:FF -> discard
Attacker is blocked from the network
```

---

## Part 7: Proving Your Work — What to Include in a Research Paper

### Abstract (template)

"We present a dual-layer detection system for Man-in-the-Middle (MITM) attacks in SDN environments. Layer 1 employs rule-based ARP table inspection in a Ryu SDN controller to detect ARP spoofing in real time. Layer 2 applies a CNN-Bidirectional LSTM-Attention hybrid neural network trained on five heterogeneous network flow datasets (N=148,686 flows) to detect flow-level anomalies. The model achieves F1 = XX ± YY, ROC-AUC = XX ± YY, and MCC = XX over 5-fold cross-validation, outperforming [baselines]. The complete system was validated in a Mininet simulation environment with real ARP poisoning attacks."

### Related Work (areas to cite)

1. **CIC-MITM dataset paper** — the paper that produced the CIC dataset you used
2. **NFStream** — tool that generated flow features in your datasets
3. **SMOTE** (Chawla et al., 2002) — for comparison/discussion of why you chose class_weight
4. **Attention is All You Need** (Vaswani et al., 2017) — foundation of attention mechanism
5. **Ryu SDN framework** — the controller you used
6. **Previous MITM detection papers** — for comparison table

### Methodology Justification

| Choice | Why |
|--------|-----|
| Binary classification | Sufficient for detection; multi-class future work |
| CNN + BiLSTM + Attention | CNN extracts local correlations; BiLSTM captures directional patterns; Attention focuses on discriminative features |
| RF-RFE feature selection | Robust to irrelevant features; computationally efficient; interpretable importance scores |
| class_weight over SMOTE | Avoids data leakage from synthetic samples; prevents train < val accuracy artifact |
| 5-fold cross-validation | Statistically robust evaluation; required for publication claims |
| StandardScaler | Feature scale normalization critical for gradient-based training |

### Comparison Table (add when you have baseline results)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | MCC |
|-------|----------|-----------|--------|----|---------|-----|
| Random Forest | - | - | - | - | - | - |
| Simple LSTM | - | - | - | - | - | - |
| CNN only | - | - | - | - | - | - |
| **Ours (CNN+BiLSTM+Attn)** | **XX** | **XX** | **XX** | **XX** | **XX** | **XX** |

### Figures to Include in Paper

1. System architecture diagram (SDN + ML pipeline)
2. CNN+BiLSTM+Attention architecture diagram
3. Training history curves (accuracy + loss)
4. Confusion matrix (normalized)
5. ROC curve
6. Precision-Recall curve
7. Feature importance bar chart
8. Cross-validation box plot

All of these are already saved in `plots/` by the notebook.

---

## Part 8: How to Make the Model Better

### Short-Term Improvements (easy wins)

1. **Threshold tuning:** Instead of always using 0.5, find the threshold that maximizes F1 on the validation set
2. **Ensemble:** Train 3 different models with different seeds, average their predictions
3. **Data augmentation:** Add small Gaussian noise to training features (data augmentation without synthetic samples)

### Medium-Term Improvements (for a stronger paper)

1. **Add baseline comparisons:** Random Forest, XGBoost, simple LSTM — show your model is better
2. **Ablation study:** Test CNN-only, LSTM-only, no-attention — prove each component adds value
3. **Feature importance from attention weights:** Visualize which features the attention head focuses on most for attack vs normal flows
4. **SHAP values:** Explain individual predictions — powerful for paper and for real deployment

### Long-Term (advanced research directions)

1. **Real-time streaming:** Adapt the pipeline to classify flows as they arrive (using NFStream or similar)
2. **Transfer learning:** Train on CIC dataset, fine-tune on IoT dataset — test cross-environment generalization
3. **Federated learning:** Train across multiple network environments without sharing raw data
4. **Adversarial robustness:** Test if an attacker can craft traffic that evades the model
5. **Zero-day detection:** Use anomaly detection (autoencoder) as a third layer for unknown attack types

---

## Part 9: Key Concepts Glossary (For Beginners)

| Term | Simple Explanation |
|------|--------------------|
| ARP | Address Resolution Protocol — how computers map IP addresses to MAC addresses |
| MITM | Man-in-the-Middle — attacker secretly intercepts communication |
| ARP Spoofing | Sending fake ARP replies to poison a device's ARP cache |
| SDN | Software Defined Networking — centralized network control |
| OpenFlow | Protocol for SDN controller to talk to switches |
| Ryu | Python-based SDN controller framework |
| Mininet | Virtual network simulator for Linux |
| Flow | A single network conversation between two endpoints |
| Feature | A measurable property of a flow (e.g., number of packets) |
| CNN | Convolutional Neural Network — good at local pattern detection |
| LSTM | Long Short-Term Memory — good at sequence/temporal patterns |
| BiLSTM | Bidirectional LSTM — reads sequence both forward and backward |
| Attention | Mechanism that weights input features by importance |
| RFE | Recursive Feature Elimination — feature selection method |
| SMOTE | Synthetic Minority Over-sampling — creates fake training samples |
| class_weight | Tells model to penalize errors on minority class more heavily |
| StandardScaler | Normalizes features to zero mean and unit variance |
| Overfitting | Model memorizes training data, fails on new data |
| Dropout | Randomly disables neurons during training to prevent overfitting |
| BatchNorm | Normalizes layer activations for stable and faster training |
| ROC-AUC | Measures how well model separates two classes (1.0 = perfect) |
| MCC | Matthews Correlation Coefficient — best single metric for binary classification |
| Cross-validation | Training/testing on multiple data splits for robust evaluation |
| Early Stopping | Halt training when validation performance stops improving |

---

*Document generated for: Detection of MITM Attacks with Flow Level Monitoring*
*Stack: Garuda Linux · Mininet · Ryu SDN (Docker) · Python · CNN + BiLSTM + Attention*
*Architecture improved and documented: 2026-03-20*
