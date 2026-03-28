# 🛡️ MITM Detection System — Comprehensive Plot Analysis

This document provides a detailed analysis of the visual evaluation metrics generated for the **CNN + LSTM Hybrid MITM Detection System**. The analysis covers both binary detection (Normal vs. Attack) and multi-class classification (ARP, DNS, SSL, Session attacks).

---

## 1. Model Performance & Comparison
**Key Plots:** `files/07_model_comparison.png`, `files/09_roc_all_models.png`, `plots/metrics_radar.png`, `plots/model_comparison_full.png`

### 📊 Performance Summary (Test Set)
The hybrid **CNN+LSTM** model consistently outperforms traditional machine learning baselines across all major metrics:
- **Accuracy:** ~99.2% – 99.8% (highest among all tested models)
- **F1-Score:** ~0.985+ (excellent balance between precision and recall)
- **ROC-AUC:** ~0.999+ (near-perfect class discrimination)

### 📈 ROC & Precision-Recall Curves
- The **ROC curves** (`09_roc_all_models.png`) show the CNN+LSTM model achieving a True Positive Rate (TPR) of nearly 1.0 at extremely low False Positive Rates (FPR). It sits significantly above the Logistic Regression and MLP baselines.
- The **Precision-Recall curves** (`plots/pr_curves_all_models.png`) demonstrate that the model maintains high precision even at high recall levels, which is critical for minimizing "alarm fatigue" in a network operations center.
- The **Radar Chart** (`plots/metrics_radar.png`) visually confirms the robustness of the hybrid architecture, showing a larger "area under the metric" compared to any single-algorithm approach.

---

## 2. Per-Attack Type Performance (Multi-Class)
**Key Plots:** `files/11_per_attack_detection.png`

The system's ability to detect different MITM variants is non-uniform but highly effective:
- **ARP Poisoning:** Highest detection rate (~99%+), likely due to distinct MAC/IP mismatch patterns.
- **DNS Hijacking:** Strong detection (~97%+) through the analysis of UDP/53 flow characteristics and multi-IP domain tracking.
- **SSL Stripping:** Detected via TLS port analysis and flow asymmetry.
- **Session Hijacking:** Identified through the detection of RST/ACK injection patterns (high `rst_ratio`).

---

## 3. Feature Importance & Correlation
**Key Plots:** `files/01_feature_importance.png`, `files/12_feature_correlation.png`, `plots/feature_importance_rank.png`

### 🔍 Top 5 Discriminatory Features
Analysis from the **RF-RFE** (Random Forest Recursive Feature Elimination) shows the most important features are:
1. `syn_ratio` & `rst_ratio`: Indicators of connection manipulation.
2. `bidirectional_duration_ms`: MITM flows often have longer durations than benign automated traffic.
3. `packet_asymmetry`: Critical for detecting relay-based MITM.
4. `is_dns`: Essential for identifying Layer 2 hijacks.
5. `piat_variance_ratio`: Variance in inter-arrival times helps distinguish robotic relay scripts from human traffic.

### 🔗 Correlation Matrix
The **Correlation Heatmap** (`12_feature_correlation.png`) shows strong positive correlation between `rst_ratio` and `rst_ack_combined`, confirming that session hijacking attempts are clearly identifiable in the feature space.

---

## 4. Operational Metrics (Real-Time Suitability)
**Key Plots:** `files/08_fpr_comparison.png`, `files/10_detection_latency.png`, `plots/false_positive_rate.png`

### 🛡️ False Positive Rate (FPR)
For a security system, a low FPR is vital to prevent blocking legitimate users.
- **CNN+LSTM FPR:** < 0.1% (compared to ~1.2% for Decision Trees).
- This means fewer than 1 in 1000 normal flows are incorrectly flagged as MITM.

### ⏱️ Detection Latency
The **Latency Analysis** (`10_detection_latency.png`) shows:
- **10 Packets:** ~85% detection rate.
- **20 Packets:** ~95%+ detection rate.
- **30+ Packets:** 99.9% detection rate.
The system is configured to trigger an ML check every **20 packets**, balancing speed with accuracy.

---

## 5. Architectural Analysis
**Key Plots:** `plots/ablation_study.png`, `files/13_convergence.png`

### 🏗️ Ablation Study (CNN vs. LSTM vs. Hybrid)
- **CNN-Only:** Good at spatial feature extraction but lacks temporal understanding.
- **LSTM-Only:** Good at temporal sequence but slower to converge.
- **CNN+LSTM (Hybrid):** Combines both, showing a significant lift in **AUC** (~2-3% improvement) over either individual architecture.

### 📉 Training Convergence
The **Loss/AUC curves** (`13_convergence.png`) show smooth convergence within 15-20 epochs, with early stopping (patience=7) successfully preventing overfitting to the training data.

---

## 6. Summary Dashboard
**Key Plots:** `files/14_summary_dashboard.png`

The **Summary Dashboard** provides a "Single Pane of Glass" view of the system's health, showing the confusion matrix, ROC curve, and key statistics (`TP`, `FP`, `TN`, `FN`) in one view. It confirms that the system is ready for deployment in the SDN controller.

---
*Analysis generated on Friday, March 20, 2026.*
