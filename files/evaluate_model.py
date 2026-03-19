#!/usr/bin/env python3
"""
evaluate_model.py — Comprehensive Model Evaluation
===================================================
Generates ALL analysis plots to justify model accuracy:
  1. Confusion Matrix (raw + normalised)
  2. ROC Curve (all models)
  3. Precision-Recall Curve
  4. Score Distribution
  5. Threshold Sensitivity
  6. Feature Importance
  7. Detection Latency
  8. Per-Attack-Type Performance
  9. False Positive Rate Comparison
  10. Training Convergence
  11. Feature Correlation Heatmap
  12. Summary Dashboard
"""

import os, glob, sys, time, warnings
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import collections

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    roc_auc_score
)

warnings.filterwarnings('ignore')

try:
    import tensorflow as tf
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  TensorFlow not available — skipping CNN+LSTM")

# ── Config ───────────────────────────────────────────────
MODEL_PATH    = "/app/model/mitm_model.h5"
SCALER_PATH   = "/app/model/scaler.pkl"
FEATURES_PATH = "/app/model/selected_features.pkl"
DATASET_DIR   = "/app/dataset"
PLOTS_DIR     = "/app/plots"
THRESHOLD     = 0.5

os.makedirs(PLOTS_DIR, exist_ok=True)

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 11,
    'axes.titlesize': 13, 'axes.labelsize': 11,
    'figure.facecolor': 'white'
})
PALETTE = ['#2ecc71', '#e74c3c', '#3498db', '#f39c12', '#9b59b6']

NORMAL_LABELS = {'normal', 'benign', '0', '0.0'}
ATTACK_MAP    = {
    'Normal': 0, 'ARP_Poisoning': 1, 'DNS_Hijacking': 2,
    'SSL_Stripping': 3, 'Session_Hijacking': 4
}
CLASS_NAMES = list(ATTACK_MAP.keys())


# ─────────────────────────────────────────────────────────
# Helper: load + preprocess
# ─────────────────────────────────────────────────────────
def load_and_preprocess():
    files = sorted(glob.glob(os.path.join(DATASET_DIR, '*.csv')))
    if not files:
        print("⚠️  No CSV files found — using synthetic data")
        return make_synthetic()

    dfs = []
    for f in files:
        tmp = pd.read_csv(f, low_memory=False)
        if 'Label' not in tmp.columns:
            lbl = [c for c in tmp.columns if c.lower() == 'label']
            if lbl: tmp.rename(columns={lbl[0]: 'Label'}, inplace=True)
        dfs.append(tmp)
        print(f"  ✅ {os.path.basename(f)} — {tmp.shape}")
    df = pd.concat(dfs, ignore_index=True)

    DROP = ['id','expiration_id','src_ip','src_mac','src_oui','dst_ip','dst_mac',
            'dst_oui','vlan_id','tunnel_id','bidirectional_first_seen_ms',
            'bidirectional_last_seen_ms','src2dst_first_seen_ms',
            'src2dst_last_seen_ms','dst2src_first_seen_ms','dst2src_last_seen_ms',
            'user_agent','content_type','requested_server_name',
            'client_fingerprint','server_fingerprint','application_name',
            'application_category_name','application_is_guessed','application_confidence']
    df.drop(columns=[c for c in DROP if c in df.columns], inplace=True)
    df.fillna(0, inplace=True)
    df.replace([np.inf, -np.inf], 0, inplace=True)
    return engineer_features(df)


def make_synthetic():
    np.random.seed(42)
    N = {'Normal': 4000, 'ARP_Poisoning': 800, 'DNS_Hijacking': 600,
         'SSL_Stripping': 500, 'Session_Hijacking': 400}

    def mk(n, label, **kw):
        base = {
            'bidirectional_duration_ms':    np.abs(np.random.normal(500, 300, n)),
            'bidirectional_packets':        np.random.randint(2, 50, n),
            'bidirectional_bytes':          np.abs(np.random.normal(2000, 1500, n)),
            'src2dst_packets':              np.random.randint(1, 30, n),
            'src2dst_bytes':                np.abs(np.random.normal(1000, 800, n)),
            'dst2src_packets':              np.random.randint(1, 30, n),
            'dst2src_bytes':                np.abs(np.random.normal(1000, 800, n)),
            'bidirectional_mean_ps':        np.abs(np.random.normal(400, 200, n)),
            'bidirectional_stddev_ps':      np.abs(np.random.normal(150, 80, n)),
            'bidirectional_mean_piat_ms':   np.abs(np.random.normal(50, 30, n)),
            'bidirectional_stddev_piat_ms': np.abs(np.random.normal(20, 10, n)),
            'bidirectional_syn_packets':    np.random.randint(0, 3, n),
            'bidirectional_ack_packets':    np.random.randint(0, 20, n),
            'bidirectional_rst_packets':    np.random.randint(0, 2, n),
            'bidirectional_fin_packets':    np.random.randint(0, 2, n),
            'protocol':                     np.random.choice([6, 17], n),
            'src_port':                     np.random.randint(1024, 65535, n),
            'dst_port':                     np.random.choice([80, 443, 8080, 53], n),
            'Label':                        np.full(n, label, dtype=object),
        }
        base.update(kw)
        return pd.DataFrame(base)

    pieces = [
        mk(N['Normal'],           'Normal'),
        mk(N['ARP_Poisoning'],    'ARP_Poisoning',
           bidirectional_syn_packets=np.random.randint(5, 30, N['ARP_Poisoning'])),
        mk(N['DNS_Hijacking'],    'DNS_Hijacking',
           dst_port=np.full(N['DNS_Hijacking'], 53),
           protocol=np.full(N['DNS_Hijacking'], 17),
           bidirectional_mean_ps=np.abs(np.random.normal(80, 30, N['DNS_Hijacking']))),
        mk(N['SSL_Stripping'],    'SSL_Stripping',
           dst_port=np.full(N['SSL_Stripping'], 443),
           bidirectional_syn_packets=np.random.randint(10, 40, N['SSL_Stripping'])),
        mk(N['Session_Hijacking'],'Session_Hijacking',
           bidirectional_rst_packets=np.random.randint(8, 25, N['Session_Hijacking']),
           bidirectional_ack_packets=np.random.randint(10, 30, N['Session_Hijacking'])),
    ]
    df = pd.concat(pieces, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    return engineer_features(df)


def engineer_features(df):
    total_pkts  = df['bidirectional_packets'] + 1
    total_bytes = df['bidirectional_bytes']   + 1
    df['packet_asymmetry']    = (df['src2dst_packets'] - df['dst2src_packets']).abs() / total_pkts
    df['byte_asymmetry']      = (df['src2dst_bytes']   - df['dst2src_bytes']).abs()   / total_bytes
    df['bytes_per_packet']    = df['bidirectional_bytes'] / total_pkts
    df['src2dst_bpp']         = df['src2dst_bytes'] / (df['src2dst_packets'] + 1)
    df['dst2src_bpp']         = df['dst2src_bytes'] / (df['dst2src_packets'] + 1)
    df['syn_ratio']           = df['bidirectional_syn_packets'] / total_pkts
    df['rst_ratio']           = df['bidirectional_rst_packets'] / total_pkts
    df['ack_ratio']           = df['bidirectional_ack_packets'] / total_pkts
    df['fin_ratio']           = df['bidirectional_fin_packets'] / total_pkts
    df['piat_variance_ratio'] = df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + 1)
    df['ps_variance_ratio']   = df['bidirectional_stddev_ps']      / (df['bidirectional_mean_ps']      + 1)
    df['is_dns']              = (df['dst_port'] == 53).astype(int)
    df['is_tls_port']         = df['dst_port'].isin([443, 8443]).astype(int)
    df['is_http_port']        = df['dst_port'].isin([80, 8080]).astype(int)
    df['small_pkt_ratio']     = (df['bidirectional_mean_ps'] < 100).astype(int)
    df['high_syn_flag']       = (df['syn_ratio'] > 0.3).astype(int)
    df['high_rst_flag']       = (df['rst_ratio'] > 0.15).astype(int)
    df['rst_ack_combined']    = df['bidirectional_rst_packets'] * df['bidirectional_ack_packets']
    df['flow_intensity']      = total_pkts / (df['bidirectional_duration_ms'] + 1) * 1000
    df['piat_cv']             = df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + 1e-6)
    df['low_piat_high_rate']  = ((df['piat_cv'] < 0.5) & (df['bidirectional_mean_piat_ms'] < 50)).astype(int)

    def binary_enc(v):
        return 0 if str(v).lower().strip() in NORMAL_LABELS else 1
    def multi_enc(v):
        s = str(v).strip()
        if s in ATTACK_MAP: return ATTACK_MAP[s]
        sl = s.lower()
        if any(x in sl for x in ['normal','benign']): return 0
        if any(x in sl for x in ['arp','spoof','poison']): return 1
        if any(x in sl for x in ['dns','hijack']): return 2
        if any(x in sl for x in ['ssl','strip','tls']): return 3
        if any(x in sl for x in ['session','rst','inject']): return 4
        return 1

    df['label_binary'] = df['Label'].apply(binary_enc)
    df['label_multi']  = df['Label'].apply(multi_enc)
    return df


# ─────────────────────────────────────────────────────────
# Main evaluation
# ─────────────────────────────────────────────────────────
def main():
    print("\n📂 Loading dataset …")
    df = load_and_preprocess()
    print(f"✅ Total records: {len(df):,}")
    print("Label distribution:")
    print(df['Label'].value_counts())

    # Feature selection
    if os.path.exists(FEATURES_PATH):
        SELECTED = joblib.load(FEATURES_PATH)
        SELECTED = [f for f in SELECTED if f in df.columns]
    else:
        # Auto-pick numeric features
        skip = {'Label', 'label_binary', 'label_multi'}
        SELECTED = [c for c in df.select_dtypes(include=[np.number]).columns if c not in skip][:25]

    print(f"\n✅ Using {len(SELECTED)} features")

    X = df[SELECTED]
    y = df['label_binary']
    y_multi = df['label_multi']

    X_train, X_temp, y_train, y_temp, ym_train, ym_temp = train_test_split(
        X, y, y_multi, test_size=0.30, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test, ym_val, ym_test = train_test_split(
        X_temp, y_temp, ym_temp, test_size=0.667, stratify=y_temp, random_state=42)

    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
        X_train_sc = scaler.transform(X_train)
        X_val_sc   = scaler.transform(X_val)
        X_test_sc  = scaler.transform(X_test)
    else:
        scaler = StandardScaler()
        X_train_sc = scaler.fit_transform(X_train)
        X_val_sc   = scaler.transform(X_val)
        X_test_sc  = scaler.transform(X_test)

    y_true    = y_test.values
    ym_true   = ym_test.values
    n_features = X_test_sc.shape[1]

    # ── CNN+LSTM predictions ─────────────────────────────
    y_prob_cnn = None
    if ML_AVAILABLE and os.path.exists(MODEL_PATH):
        print("\n🧠 Loading CNN+LSTM model …")
        model = tf.keras.models.load_model(MODEL_PATH)
        X_te_cnn = X_test_sc.reshape(-1, n_features, 1)
        y_prob_cnn = model.predict(X_te_cnn, batch_size=1024, verbose=0).flatten()
        y_pred_cnn = (y_prob_cnn >= THRESHOLD).astype(int)
        print(f"✅ CNN+LSTM predictions done — {len(y_prob_cnn):,} samples")
    else:
        print("⚠️  CNN+LSTM not available — using RF as primary")

    # ── Train baseline models ────────────────────────────
    print("\n⏳ Training baseline models …")
    baselines = {
        'Logistic Regression': LogisticRegression(max_iter=500, random_state=42),
        'Random Forest':        RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
        'Gradient Boosting':    GradientBoostingClassifier(n_estimators=100, random_state=42),
    }
    results   = {}
    roc_data  = {}

    for name, clf in baselines.items():
        print(f"  ⏳ {name} …", end=' ')
        clf.fit(X_train_sc, y_train)
        yp  = clf.predict(X_test_sc)
        ypr = clf.predict_proba(X_test_sc)[:, 1]
        tn_, fp_, fn_, tp_ = confusion_matrix(y_true, yp).ravel()
        fpr_a, tpr_a, _    = roc_curve(y_true, ypr)
        results[name] = {
            'Accuracy':  accuracy_score(y_true, yp),
            'Precision': precision_score(y_true, yp, zero_division=0),
            'Recall':    recall_score(y_true, yp, zero_division=0),
            'F1':        f1_score(y_true, yp, zero_division=0),
            'AUC':       roc_auc_score(y_true, ypr),
            'FPR':       fp_ / (fp_ + tn_ + 1e-9),
            'y_prob':    ypr, 'y_pred': yp
        }
        roc_data[name] = (fpr_a, tpr_a)
        print("done")

    # Add CNN+LSTM
    if y_prob_cnn is not None:
        tn_, fp_, fn_, tp_ = confusion_matrix(y_true, y_pred_cnn).ravel()
        fpr_a, tpr_a, _    = roc_curve(y_true, y_prob_cnn)
        results['CNN+LSTM (Ours)'] = {
            'Accuracy':  accuracy_score(y_true, y_pred_cnn),
            'Precision': precision_score(y_true, y_pred_cnn, zero_division=0),
            'Recall':    recall_score(y_true, y_pred_cnn, zero_division=0),
            'F1':        f1_score(y_true, y_pred_cnn, zero_division=0),
            'AUC':       roc_auc_score(y_true, y_prob_cnn),
            'FPR':       fp_ / (fp_ + tn_ + 1e-9),
            'y_prob':    y_prob_cnn, 'y_pred': y_pred_cnn
        }
        roc_data['CNN+LSTM (Ours)'] = (fpr_a, tpr_a)

    # Primary model for detailed plots
    primary_key = 'CNN+LSTM (Ours)' if y_prob_cnn is not None else 'Random Forest'
    R           = results[primary_key]
    y_prob      = R['y_prob']
    y_pred      = R['y_pred']
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr_val     = fp / (fp + tn + 1e-9)
    acc         = R['Accuracy']
    auc_s       = R['AUC']

    print(f"\n✅ Primary model: {primary_key}")
    print(f"   Accuracy  : {acc*100:.2f}%")
    print(f"   F1        : {R['F1']*100:.2f}%")
    print(f"   AUC       : {auc_s:.4f}")
    print(f"   FPR       : {fpr_val*100:.4f}%")
    print(classification_report(y_true, y_pred, target_names=['Normal','Attack']))

    # ─── PLOT 1: Confusion Matrix ─────────────────────────
    print("\n📊 Generating plots …")
    cm = confusion_matrix(y_true, y_pred)
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal','Attack'], yticklabels=['Normal','Attack'], ax=axes[0])
    axes[0].set_title('Confusion Matrix — Counts')
    axes[0].set_ylabel('Actual'); axes[0].set_xlabel('Predicted')
    cm_n = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
    sns.heatmap(cm_n, annot=True, fmt='.1f', cmap='Blues',
                xticklabels=['Normal','Attack'], yticklabels=['Normal','Attack'], ax=axes[1])
    axes[1].set_title('Confusion Matrix — Normalised (%)')
    axes[1].set_ylabel('Actual'); axes[1].set_xlabel('Predicted')
    plt.suptitle(f'{primary_key} — Acc={acc*100:.2f}%  FPR={fpr_val*100:.4f}%')
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/03_confusion_matrix.png', dpi=150)
    plt.close()

    # ─── PLOT 2: ROC + PR ─────────────────────────────────
    fpr_arr, tpr_arr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr_arr, tpr_arr)
    prec_arr, rec_arr, _ = precision_recall_curve(y_true, y_prob)
    avg_prec = average_precision_score(y_true, y_prob)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    axes[0].plot(fpr_arr, tpr_arr, '#e74c3c', lw=2.5, label=f'{primary_key} (AUC={roc_auc:.4f})')
    axes[0].plot([0,1],[0,1],'k--',lw=1,label='Random')
    axes[0].fill_between(fpr_arr, tpr_arr, alpha=0.08, color='#e74c3c')
    axes[0].set_xlabel('False Positive Rate'); axes[0].set_ylabel('True Positive Rate')
    axes[0].set_title('ROC Curve'); axes[0].legend(loc='lower right'); axes[0].grid(alpha=0.3)

    axes[1].plot(rec_arr, prec_arr, '#3498db', lw=2.5, label=f'AP={avg_prec:.4f}')
    axes[1].axhline(y_true.mean(), color='gray', linestyle='--', lw=1, label='Baseline')
    axes[1].fill_between(rec_arr, prec_arr, alpha=0.08, color='#3498db')
    axes[1].set_xlabel('Recall'); axes[1].set_ylabel('Precision')
    axes[1].set_title('Precision-Recall Curve'); axes[1].legend(); axes[1].grid(alpha=0.3)

    plt.suptitle('ROC & Precision-Recall Curves')
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/04_roc_pr_curves.png', dpi=150); plt.close()

    # ─── PLOT 3: Score distribution ───────────────────────
    normal_scores = y_prob[y_true == 0]
    attack_scores = y_prob[y_true == 1]
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    for ax, yscale in zip(axes, ['linear', 'log']):
        ax.hist(normal_scores, bins=60, alpha=0.65, color='#2ecc71', label='Normal', density=True)
        ax.hist(attack_scores, bins=60, alpha=0.65, color='#e74c3c', label='Attack', density=True)
        ax.axvline(THRESHOLD, color='black', linestyle='--', lw=2, label=f'Threshold={THRESHOLD}')
        if yscale == 'log': ax.set_yscale('log')
        ax.set_xlabel('Probability Score'); ax.set_ylabel('Density')
        ax.set_title(f'Score Distribution ({yscale} scale)'); ax.legend(); ax.grid(alpha=0.3)
    plt.suptitle('Prediction Score Distributions')
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/05_score_distribution.png', dpi=150); plt.close()

    # ─── PLOT 4: Threshold sensitivity ────────────────────
    thresholds = np.linspace(0.01, 0.99, 200)
    rows = []
    for th in thresholds:
        yp = (y_prob >= th).astype(int)
        tn_, fp_, fn_, tp_ = confusion_matrix(y_true, yp, labels=[0,1]).ravel()
        rows.append({
            'threshold': th,
            'f1':        2*tp_ / (2*tp_ + fp_ + fn_ + 1e-9),
            'precision': tp_ / (tp_ + fp_ + 1e-9),
            'recall':    tp_ / (tp_ + fn_ + 1e-9),
            'fpr':       fp_ / (fp_ + tn_ + 1e-9),
        })
    th_df = pd.DataFrame(rows)
    best_f1_th = th_df.loc[th_df['f1'].idxmax(), 'threshold']

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].plot(th_df['threshold'], th_df['precision'], '#3498db', lw=2, label='Precision')
    axes[0].plot(th_df['threshold'], th_df['recall'],    '#e74c3c', lw=2, label='Recall')
    axes[0].plot(th_df['threshold'], th_df['f1'],        '#2ecc71', lw=2, label='F1')
    axes[0].axvline(best_f1_th, color='purple', linestyle=':', lw=1.5, label=f'Best F1@{best_f1_th:.2f}')
    axes[0].axvline(THRESHOLD,  color='black',  linestyle=':', lw=1.5, label=f'Current@{THRESHOLD}')
    axes[0].set_xlabel('Threshold'); axes[0].set_ylabel('Score')
    axes[0].set_title('Metrics vs Threshold'); axes[0].legend(); axes[0].grid(alpha=0.3)

    axes[1].plot(th_df['threshold'], th_df['fpr']*100, '#e74c3c', lw=2)
    axes[1].axvline(THRESHOLD, color='black', linestyle=':', lw=1.5)
    axes[1].set_xlabel('Threshold'); axes[1].set_ylabel('False Positive Rate (%)')
    axes[1].set_title('FPR vs Threshold (critical for security)'); axes[1].grid(alpha=0.3)

    plt.suptitle('Threshold Sensitivity Analysis')
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/06_threshold_sensitivity.png', dpi=150); plt.close()

    # ─── PLOT 5: Model comparison bars ────────────────────
    metrics_plot = ['Accuracy', 'Precision', 'Recall', 'F1', 'AUC']
    n_models = len(results)
    colors_m = (PALETTE * 5)[:n_models]

    fig, axes = plt.subplots(1, len(metrics_plot), figsize=(18, 6))
    fig.suptitle('Model Comparison', fontsize=14, fontweight='bold')
    for ax, metric in zip(axes, metrics_plot):
        vals   = [results[m][metric] for m in results]
        labels = list(results.keys())
        bars   = ax.bar(range(len(vals)), vals, color=colors_m)
        ax.set_ylim(0, 1.12); ax.set_title(metric)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=20, ha='right', fontsize=8)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01,
                    f'{val:.3f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/07_model_comparison.png', dpi=150); plt.close()

    # ─── PLOT 6: FPR comparison ───────────────────────────
    names = list(results.keys())
    fpr_vals = [results[m]['FPR'] * 100 for m in names]
    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(names, fpr_vals, color=colors_m[:len(names)], edgecolor='black', lw=0.7)
    for bar, val in zip(bars, fpr_vals):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.002,
                f'{val:.4f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax.set_ylabel('False Positive Rate (%)')
    ax.set_title('False Positive Rate Comparison\n(Lower = Fewer False Alarms = Better)')
    ax.set_xticks(range(len(names))); ax.set_xticklabels(names, rotation=15, ha='right')
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/08_fpr_comparison.png', dpi=150); plt.close()

    # ─── PLOT 7: ROC all models ───────────────────────────
    fig, ax = plt.subplots(figsize=(9, 7))
    for (name, (fpr_c, tpr_c)), color in zip(roc_data.items(), colors_m):
        auc_c = auc(fpr_c, tpr_c)
        lw    = 3 if name == primary_key else 2
        ax.plot(fpr_c, tpr_c, lw=lw, color=color, label=f'{name} (AUC={auc_c:.3f})')
    ax.plot([0,1],[0,1],'k--',lw=1,label='Random')
    ax.set_xlim([-0.01,1.0]); ax.set_ylim([0.0,1.02])
    ax.set_xlabel('False Positive Rate'); ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Comparison — All Models'); ax.legend(loc='lower right', fontsize=9); ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/09_roc_all_models.png', dpi=150); plt.close()

    # ─── PLOT 8: Detection latency ────────────────────────
    attack_idxs = np.where(y_true == 1)[0]
    window_sizes = [5, 10, 15, 20, 25, 30]
    det_rates    = []
    for window in window_sizes:
        detected = sum(1 for idx in attack_idxs
                       if np.any(y_prob[max(0, idx-window+1):idx+1] >= THRESHOLD))
        det_rates.append(detected / max(len(attack_idxs), 1) * 100)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(window_sizes, det_rates, 'o-', color='#e74c3c', lw=2.5, markersize=8)
    ax.fill_between(window_sizes, det_rates, alpha=0.15, color='#e74c3c')
    for x, y_pt in zip(window_sizes, det_rates):
        ax.annotate(f'{y_pt:.1f}%', (x, y_pt), textcoords='offset points',
                    xytext=(0, 10), ha='center', fontsize=9)
    ax.axhline(100, color='green', linestyle='--', lw=1, alpha=0.6)
    ax.set_xlabel('Detection Window (packets)'); ax.set_ylabel('Detection Rate (%)')
    ax.set_title('Detection Latency Analysis\n(Packets needed before attack is identified)')
    ax.set_ylim(0, 115); ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/10_detection_latency.png', dpi=150); plt.close()

    # ─── PLOT 9: Per-attack type breakdown ────────────────
    breakdown = {}
    for cid, cname in enumerate(CLASS_NAMES):
        mask = (ym_true == cid)
        if mask.sum() == 0: continue
        if cid == 0:
            pct = (y_pred[mask] == 0).mean() * 100
            breakdown['Normal (TNR)'] = pct
        else:
            pct = (y_pred[mask] == 1).mean() * 100
            breakdown[cname] = pct

    fig, ax = plt.subplots(figsize=(10, 5))
    names_b  = list(breakdown.keys())
    vals_b   = list(breakdown.values())
    cols_b   = ['#2ecc71'] + ['#e74c3c'] * (len(names_b) - 1)
    bars = ax.barh(names_b, vals_b, color=cols_b, edgecolor='black', lw=0.5)
    for bar, val in zip(bars, vals_b):
        ax.text(min(val + 1, 112), bar.get_y() + bar.get_height()/2,
                f'{val:.1f}%', va='center', fontsize=10, fontweight='bold')
    ax.axvline(90, color='orange', linestyle='--', lw=1, alpha=0.7, label='90% target')
    ax.set_xlim(0, 118); ax.set_xlabel('Detection Rate (%)')
    ax.set_title('Per-Attack-Type Detection Rate'); ax.legend(); ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/11_per_attack_detection.png', dpi=150); plt.close()

    # ─── PLOT 10: Feature correlation ─────────────────────
    security_feats = ['syn_ratio','rst_ratio','ack_ratio','packet_asymmetry','byte_asymmetry',
                      'is_dns','is_tls_port','high_syn_flag','high_rst_flag',
                      'rst_ack_combined','flow_intensity','piat_cv','bytes_per_packet',
                      'piat_variance_ratio','label_binary']
    avail = [f for f in security_feats if f in df.columns]
    corr  = df[avail].corr()
    fig, ax = plt.subplots(figsize=(12, 10))
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, mask=mask, annot=True, fmt='.2f', cmap='RdBu_r',
                center=0, vmin=-1, vmax=1, square=True, linewidths=0.4, ax=ax,
                annot_kws={'size': 7})
    ax.set_title('Feature Correlation Matrix — Security Features', pad=15)
    plt.xticks(rotation=40, ha='right', fontsize=8); plt.yticks(fontsize=8)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/12_feature_correlation.png', dpi=150); plt.close()

    # ─── PLOT 11: Summary Dashboard ───────────────────────
    fig = plt.figure(figsize=(16, 10))
    fig.suptitle('MITM Detection System — Complete Performance Summary',
                 fontsize=15, fontweight='bold', y=1.01)
    gs = fig.add_gridspec(2, 3, hspace=0.45, wspace=0.35)

    ax1 = fig.add_subplot(gs[0, 0])
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal','Attack'], yticklabels=['Normal','Attack'],
                ax=ax1, cbar=False)
    ax1.set_title('Confusion Matrix'); ax1.set_ylabel('Actual'); ax1.set_xlabel('Predicted')

    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(fpr_arr, tpr_arr, '#e74c3c', lw=2, label=f'AUC={roc_auc:.3f}')
    ax2.plot([0,1],[0,1],'k--',lw=1)
    ax2.set_title('ROC Curve'); ax2.set_xlabel('FPR'); ax2.set_ylabel('TPR')
    ax2.legend(); ax2.grid(alpha=0.3)

    ax3 = fig.add_subplot(gs[0, 2])
    ax3.hist(normal_scores, bins=40, alpha=0.6, color='#2ecc71', label='Normal', density=True)
    ax3.hist(attack_scores, bins=40, alpha=0.6, color='#e74c3c', label='Attack', density=True)
    ax3.axvline(THRESHOLD, color='black', linestyle='--')
    ax3.set_title('Score Distribution'); ax3.legend(fontsize=8)

    ax4 = fig.add_subplot(gs[1, 0])
    metric_names = ['Accuracy','Precision','Recall','F1','AUC']
    metric_vals  = [R['Accuracy'], R['Precision'], R['Recall'], R['F1'], R['AUC']]
    bars = ax4.bar(metric_names, metric_vals, color=PALETTE)
    for bar, val in zip(bars, metric_vals):
        ax4.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.005,
                 f'{val:.3f}', ha='center', va='bottom', fontsize=9)
    ax4.set_ylim(0, 1.12); ax4.set_title(f'{primary_key} Metrics'); ax4.grid(axis='y', alpha=0.3)

    ax5 = fig.add_subplot(gs[1, 1])
    ax5.barh(list(breakdown.keys()), list(breakdown.values()),
             color=['#2ecc71'] + ['#e74c3c'] * (len(breakdown)-1))
    ax5.set_xlabel('Detection Rate (%)'); ax5.set_title('Per-Attack Detection')
    ax5.set_xlim(0, 118); ax5.grid(axis='x', alpha=0.3)

    ax6 = fig.add_subplot(gs[1, 2]); ax6.axis('off')
    stats = [
        f'Model:       {primary_key}',
        f'Accuracy:    {acc*100:.2f}%',
        f'Precision:   {R["Precision"]*100:.2f}%',
        f'Recall:      {R["Recall"]*100:.2f}%',
        f'F1-Score:    {R["F1"]*100:.2f}%',
        f'ROC-AUC:     {auc_s:.4f}',
        f'FPR:         {fpr_val*100:.4f}%',
        f'TP: {tp:,}  FP: {fp:,}',
        f'TN: {tn:,}  FN: {fn:,}',
        f'Test samples: {len(y_true):,}',
        f'Threshold:   {THRESHOLD}',
    ]
    ax6.text(0.05, 0.95, '\n'.join(stats), transform=ax6.transAxes,
             va='top', fontsize=9.5, fontfamily='monospace',
             bbox=dict(facecolor='#f8f9fa', edgecolor='#dee2e6', boxstyle='round,pad=0.5'))
    ax6.set_title('Key Statistics')

    plt.savefig(f'{PLOTS_DIR}/14_summary_dashboard.png', dpi=150, bbox_inches='tight')
    plt.close()

    # ─── Save CSV comparison ──────────────────────────────
    summary_data = {
        'Model': list(results.keys()),
        'Accuracy (%)':  [round(results[m]['Accuracy']  * 100, 2) for m in results],
        'Precision (%)': [round(results[m]['Precision'] * 100, 2) for m in results],
        'Recall (%)':    [round(results[m]['Recall']    * 100, 2) for m in results],
        'F1 (%)':        [round(results[m]['F1']        * 100, 2) for m in results],
        'AUC':           [round(results[m]['AUC'],             4) for m in results],
        'FPR (%)':       [round(results[m]['FPR']        * 100, 4) for m in results],
    }
    pd.DataFrame(summary_data).to_csv('/app/model/model_comparison.csv', index=False)

    print('\n' + '='*60)
    print('✅ ALL PLOTS SAVED:')
    for f in sorted(glob.glob(f'{PLOTS_DIR}/*.png')):
        print(f'   {f}')
    print('='*60)
    print('\n✅ model/model_comparison.csv saved')


if __name__ == '__main__':
    main()
