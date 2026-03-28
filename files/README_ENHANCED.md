# 🛡️ MITM Detection System — Enhanced v2.0

## What Was Added / Changed
## Test Okay##

### From `sdn-mitm-attacks-research` integration:
| Feature | Where |
|---|---|
| **DNS Hijacking attack script** | `scripts/dns_hijack.py` |
| **DNS Hijacking detection** in controller | `my_controller.py` — `_check_dns_hijacking()` |
| **Dynamic ARP Inspection (DAI)** | `my_controller.py` — `dai_bindings` tracking |
| **Multi-IP domain tracking** | Detects when same domain → multiple IPs |
| **JSON alert log** | `/tmp/mitm_alerts.json` |

### Model & Evaluation enhancements:
| Feature | Where |
|---|---|
| **DNS/Session-hijacking features** | 10 new features in `enhanced_model_pipeline.ipynb` |
| **Strict train/val/test split** | No data leakage between splits |
| **Multi-class labelling** | 5 attack types + Normal |
| **Per-attack detection rate** | Plot 11 |
| **Threshold sensitivity analysis** | Plot 6 — optimal threshold finder |
| **Detection latency analysis** | Plot 10 — packets needed to detect |
| **False Positive Rate comparison** | Plot 8 — critical for security |
| **ROC comparison (all models)** | Plot 9 |
| **Feature correlation heatmap** | Plot 12 |
| **Summary dashboard** | Plot 14 |

---

## New Feature Engineering (26 features → 35+ candidates)

```
# DNS Hijacking features (NEW)
is_dns              — flow targets UDP/53
is_tls_port         — flow targets 443/8443
small_pkt_ratio     — mean packet size < 100 bytes

# Session Hijacking features (NEW)  
rst_ack_combined    — RST × ACK count (injection indicator)
flow_intensity      — packets per second
piat_cv             — coefficient of variation of inter-arrival time
low_piat_high_rate  — robotic traffic flag
high_syn_flag       — syn_ratio > 0.3
high_rst_flag       — rst_ratio > 0.15
```

---

## Attack Detection Layers

```
Layer 1 — ARP Poisoning:     MAC/IP mismatch in ARP table + DAI
Layer 2 — DNS Hijacking:     Multiple IPs for same domain (NEW)
Layer 3 — SSL Stripping:     Rule-based TLS port analysis
Layer 4 — Session Hijacking: RST injection pattern
Layer 5 — CNN+LSTM ML:       Flow-level anomaly scoring
```

---

## Evaluation Plots Generated

| # | File | What it shows |
|---|---|---|
| 1 | `01_feature_importance.png` | RF-RFE top-25 importance bars |
| 2 | `02_training_history.png` | Loss/Accuracy/AUC/Precision per epoch |
| 3 | `03_confusion_matrix.png` | Raw + normalised CM |
| 4 | `04_roc_pr_curves.png` | ROC + Precision-Recall |
| 5 | `05_score_distribution.png` | Score histograms (linear + log) |
| 6 | `06_threshold_sensitivity.png` | Metrics vs threshold + FPR |
| 7 | `07_model_comparison.png` | All models, all metrics |
| 8 | `08_fpr_comparison.png` | False Positive Rate — safety metric |
| 9 | `09_roc_all_models.png` | ROC curves — all models overlaid |
| 10 | `10_detection_latency.png` | Packets needed to detect attack |
| 11 | `11_per_attack_detection.png` | ARP / DNS / SSL / Session rates |
| 12 | `12_feature_correlation.png` | Security feature correlations |
| 13 | `13_convergence.png` | Training convergence |
| 14 | `14_summary_dashboard.png` | Complete 6-panel dashboard |

---

## Quick Start

### 1. Train (in Docker / with dataset)
```bash
jupyter nbconvert --to notebook --execute enhanced_model_pipeline.ipynb
```

### 2. Evaluate only
```bash
python3 evaluate_model.py
```

### 3. Run demo
```bash
# Terminal 1
ryu-manager my_controller.py

# Terminal 2
sudo python3 run_demo.py
```

### 4. DNS Hijacking attack (Mininet CLI)
```
device1 python3 /tmp/dns_hijack.py 10.0.0.2 securebank.com 10.0.0.11
```

---

## Key Evaluation Metrics Explained

| Metric | Why it matters for MITM detection |
|---|---|
| **Recall** | Must be high — missing an attack is dangerous |
| **FPR** | Must be low — false alarms disrupt normal users |
| **F1** | Balances precision and recall |
| **AUC** | Model discrimination — threshold-independent |
| **Detection Latency** | How quickly can we catch an attack in progress |
| **Per-attack Rate** | Validates detection generalises across attack types |

---

## Files Added / Modified

```
mitm_project/
├── enhanced_model_pipeline.ipynb   ← NEW: Full training + 14 plots
├── my_controller.py                ← ENHANCED: DNS detection + DAI
├── evaluate_model.py               ← ENHANCED: 12 evaluation plots
├── scripts/
│   ├── dns_hijack.py               ← NEW: DNS hijacking simulator
│   ├── ssl_strip.py                (unchanged)
│   ├── session_hijack.py           (unchanged)
│   └── attacker_mitm.py            (unchanged)
└── README_ENHANCED.md              ← This file
```
