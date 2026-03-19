"""
paper_plots.py
==============
Comprehensive paper-worthy evaluation metrics and visualisations
for "MITM Attack Detection in SDN via Flow-Level Monitoring"

Plots generated (saved to plots/):
  01. roc_all_models.png              — ROC curves for all models (overlay)
  02. pr_curves_all_models.png        — Precision-Recall curves (overlay)
  03. threshold_analysis.png          — Precision / Recall / F1 vs threshold
  04. confusion_matrix_dual.png       — Count + Normalised confusion matrix
  05. feature_correlation.png         — Feature correlation heatmap (25 features)
  06. class_distribution.png          — Per-dataset class distribution
  07. ablation_study.png              — CNN-only vs LSTM-only vs CNN+LSTM
  08. model_comparison_full.png       — All 5 metrics, all models (grouped bar)
  09. score_distribution_analysis.png — Histogram + CDF of prediction scores
  10. feature_importance_rank.png     — Top-20 RF feature importances
  11. metrics_radar.png               — Radar / spider chart of 5 metrics
  12. detection_latency_sim.png       — Detection rate vs packets observed
  13. metrics_summary.png             — Final test metric summary (bar)
  14. false_positive_rate.png         — FPR comparison (lower is better)

Run:
    python3 paper_plots.py
"""

import os, glob, warnings, time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import joblib
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import (
    Conv1D, BatchNormalization, MaxPooling1D, Dropout,
    LSTM, Dense, GlobalAveragePooling1D, Input
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_auc_score, roc_curve, auc,
    precision_recall_curve, average_precision_score,
    confusion_matrix
)
from imblearn.over_sampling import SMOTE

warnings.filterwarnings('ignore')
tf.get_logger().setLevel('ERROR')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# ── Reproducibility ────────────────────────────────────────
np.random.seed(42)
tf.random.set_seed(42)

# ── Publication-quality style ──────────────────────────────
plt.rcParams.update({
    'figure.dpi': 150,            # preview dpi; savefig uses 300
    'font.family': 'DejaVu Sans',
    'font.size': 11,
    'axes.titlesize': 13,
    'axes.labelsize': 12,
    'legend.fontsize': 10,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'axes.spines.top': False,
    'axes.spines.right': False,
})
PALETTE = ['#2E86AB', '#E84855', '#3BB273', '#F18F01', '#9B5DE5', '#00B4D8', '#FF6B6B']
SAVE_DIR = 'plots'
os.makedirs(SAVE_DIR, exist_ok=True)

BAR = '=' * 60


def banner(msg):
    print(f'\n{BAR}\n  {msg}\n{BAR}')


def savefig(name):
    path = os.path.join(SAVE_DIR, name)
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close('all')
    print(f'  ✓  {name}')


# ════════════════════════════════════════════════════════════
# 1.  LOAD & PREPARE DATA
# ════════════════════════════════════════════════════════════
banner('1/7  Loading datasets and model artefacts')


def _encode(val):
    v = str(val).lower()
    return 0 if any(x in v for x in ['normal', 'benign', 'background', '0.0', "'0'"]) else 1


def feature_engineering(df):
    df = df.copy()
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(0).replace([np.inf, -np.inf], 0)
    df['packet_asymmetry']    = (abs(df['src2dst_packets']  - df['dst2src_packets'])
                                 / (df['bidirectional_packets'] + 1))
    df['byte_asymmetry']      = (abs(df['src2dst_bytes']    - df['dst2src_bytes'])
                                 / (df['bidirectional_bytes']   + 1))
    df['bytes_per_packet']    = df['bidirectional_bytes']   / (df['bidirectional_packets'] + 1)
    df['src2dst_bpp']         = df['src2dst_bytes']         / (df['src2dst_packets']  + 1)
    df['dst2src_bpp']         = df['dst2src_bytes']         / (df['dst2src_packets']  + 1)
    df['duration_ratio']      = df['src2dst_duration_ms']   / (df['dst2src_duration_ms'] + 1)
    df['syn_ratio']           = df['bidirectional_syn_packets'] / (df['bidirectional_packets'] + 1)
    df['rst_ratio']           = df['bidirectional_rst_packets'] / (df['bidirectional_packets'] + 1)
    df['piat_variance_ratio'] = (df['bidirectional_stddev_piat_ms']
                                 / (df['bidirectional_mean_piat_ms'] + 1))
    df['ps_variance_ratio']   = (df['bidirectional_stddev_ps']
                                 / (df['bidirectional_mean_ps']      + 1))
    return df


# Load individual CSVs (for per-dataset chart)
files = sorted(glob.glob('dataset/*.csv'))
if not files:
    files = sorted(glob.glob('archive/*.csv'))
if not files:
    raise FileNotFoundError('No CSV files found in dataset/ or archive/')

dfs_individual = []
ds_names       = []
for f in files:
    try:
        tmp = pd.read_csv(f, low_memory=False)
        col = next((c for c in tmp.columns if c.lower() == 'label'), None)
        if col and col != 'Label':
            tmp.rename(columns={col: 'Label'}, inplace=True)
        dfs_individual.append(tmp)
        ds_names.append(os.path.basename(f).replace('.csv', ''))
        print(f'  Loaded  {os.path.basename(f):<50}  {tmp.shape}')
    except Exception as e:
        print(f'  Error loading {f}: {e}')

df = pd.concat(dfs_individual, ignore_index=True)
print(f'\n  Combined shape: {df.shape}')

# Normalise label
col = next((c for c in df.columns if c.lower() == 'label'), None)
if col and col != 'Label':
    df.rename(columns={col: 'Label'}, inplace=True)

df['Label'] = df['Label'].apply(_encode)
df = feature_engineering(df)

# Load saved artefacts
model    = tf.keras.models.load_model('model/mitm_model.h5')
scaler   = joblib.load('model/scaler.pkl')
features = joblib.load('model/selected_features.pkl')
saved_metrics = joblib.load('model/model_summary.pkl')

print(f'  Model loaded — expects {len(features)} features')

# Handle any categorical features the same way as training
for col in ['application_name', 'requested_server_name']:
    if col in features and col in df.columns:
        df[col] = pd.factorize(df[col])[0]

X_df = df.reindex(columns=features, fill_value=0)
X_raw = X_df.values
y     = df['Label'].values

print(f'  Class balance: Normal={( y==0).sum():,}  MITM={(y==1).sum():,}')

# Train / test split (matches train_model.py)
X_train_raw, X_test_raw, y_train, y_test = train_test_split(
    X_raw, y, test_size=0.2, stratify=y, random_state=42)

X_train_sc = scaler.transform(X_train_raw)
X_test_sc  = scaler.transform(X_test_raw)
X_test_cnn = X_test_sc.reshape(X_test_sc.shape[0], X_test_sc.shape[1], 1)

print(f'  Test set: {X_test_raw.shape[0]:,} samples')


# ════════════════════════════════════════════════════════════
# 2.  CNN+LSTM PREDICTIONS
# ════════════════════════════════════════════════════════════
banner('2/7  CNN+LSTM predictions')

y_prob_cnn = model.predict(X_test_cnn, batch_size=4096, verbose=0).flatten()
y_pred_cnn = (y_prob_cnn >= 0.5).astype(int)

cm_cnn = confusion_matrix(y_test, y_pred_cnn)
tn, fp, fn, tp = cm_cnn.ravel()

cnn_metrics = {
    'Accuracy':  accuracy_score(y_test, y_pred_cnn),
    'Precision': precision_score(y_test, y_pred_cnn, zero_division=0),
    'Recall':    recall_score(y_test, y_pred_cnn, zero_division=0),
    'F1-Score':  f1_score(y_test, y_pred_cnn, zero_division=0),
    'AUC':       roc_auc_score(y_test, y_prob_cnn),
}
print(f"  CNN+LSTM — Acc: {cnn_metrics['Accuracy']:.4f}  "
      f"F1: {cnn_metrics['F1-Score']:.4f}  AUC: {cnn_metrics['AUC']:.4f}")
print(f"  TP={tp:,}  TN={tn:,}  FP={fp:,}  FN={fn:,}")


# ════════════════════════════════════════════════════════════
# 3.  BASELINE MODELS  (properly scaled)
# ════════════════════════════════════════════════════════════
banner('3/7  Baseline models')

SAMPLE = min(50_000, len(X_train_sc))
rng_idx = np.random.choice(len(X_train_sc), SAMPLE, replace=False)
Xtr_sub = X_train_sc[rng_idx]
ytr_sub = y_train[rng_idx]

baselines = {
    'Logistic Regression': LogisticRegression(max_iter=500, C=1.0, random_state=42, n_jobs=-1),
    'Decision Tree':       DecisionTreeClassifier(max_depth=15, random_state=42),
    'Random Forest':       RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
    'MLP':                 MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=80,
                                         random_state=42, early_stopping=True, n_iter_no_change=5),
}

try:
    from xgboost import XGBClassifier
    baselines['XGBoost'] = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        use_label_encoder=False, eval_metric='logloss',
        random_state=42, n_jobs=-1, verbosity=0)
except ImportError:
    print('  XGBoost not installed — skipping.')

all_results = {'CNN+LSTM (Ours)': cnn_metrics}
all_probs   = {'CNN+LSTM (Ours)': y_prob_cnn}
train_times = {'CNN+LSTM (Ours)': None}

for name, clf in baselines.items():
    print(f'  {name:<25}', end='  ', flush=True)
    t0 = time.time()
    clf.fit(Xtr_sub, ytr_sub)
    elapsed = time.time() - t0
    train_times[name] = elapsed

    y_pred = clf.predict(X_test_sc)
    if hasattr(clf, 'predict_proba'):
        y_prob = clf.predict_proba(X_test_sc)[:, 1]
    else:
        raw = clf.decision_function(X_test_sc)
        y_prob = (raw - raw.min()) / (raw.ptp() + 1e-9)

    m = {
        'Accuracy':  accuracy_score(y_test, y_pred),
        'Precision': precision_score(y_test, y_pred, zero_division=0),
        'Recall':    recall_score(y_test, y_pred, zero_division=0),
        'F1-Score':  f1_score(y_test, y_pred, zero_division=0),
        'AUC':       roc_auc_score(y_test, y_prob),
    }
    all_results[name] = m
    all_probs[name]   = y_prob
    print(f'F1={m["F1-Score"]:.4f}  AUC={m["AUC"]:.4f}  ({elapsed:.1f}s)')


# ════════════════════════════════════════════════════════════
# 4.  ABLATION STUDY  (CNN-only · LSTM-only · CNN+LSTM)
# ════════════════════════════════════════════════════════════
banner('4/7  Ablation study')

AB_TRAIN = min(30_000, len(X_train_sc))
ab_idx  = np.random.choice(len(X_train_sc), AB_TRAIN, replace=False)
Xab_tr  = X_train_sc[ab_idx]
yab_tr  = y_train[ab_idx]

try:
    smote = SMOTE(k_neighbors=3, random_state=42)
    Xab_tr, yab_tr = smote.fit_resample(Xab_tr, yab_tr)
except Exception:
    pass

n_feat   = X_test_sc.shape[1]
Xab_3d   = Xab_tr.reshape(Xab_tr.shape[0], n_feat, 1)
Xtest_3d = X_test_sc.reshape(X_test_sc.shape[0], n_feat, 1)

_cb = [EarlyStopping(monitor='val_auc', patience=4,
                     restore_best_weights=True, mode='max')]

ablation_results = {}

# ── CNN-only ──
print('  Building CNN-only ...', end=' ', flush=True)
inp = Input(shape=(n_feat, 1))
x = Conv1D(64, 3, activation='relu', padding='same')(inp)
x = BatchNormalization()(x)
x = MaxPooling1D(2)(x)
x = Dropout(0.2)(x)
x = Conv1D(128, 3, activation='relu', padding='same')(x)
x = BatchNormalization()(x)
x = GlobalAveragePooling1D()(x)
x = Dropout(0.3)(x)
x = Dense(64, activation='relu')(x)
out = Dense(1, activation='sigmoid')(x)
cnn_only_m = Model(inp, out)
cnn_only_m.compile(Adam(0.001), 'binary_crossentropy',
                   metrics=[tf.keras.metrics.AUC(name='auc')])
t0 = time.time()
cnn_only_m.fit(Xab_3d, yab_tr, epochs=15, batch_size=256, verbose=0,
               validation_split=0.1, callbacks=_cb)
print(f'{time.time()-t0:.0f}s')
p = cnn_only_m.predict(Xtest_3d, verbose=0).flatten()
yp = (p >= 0.5).astype(int)
ablation_results['CNN Only'] = {
    'Accuracy': accuracy_score(y_test, yp),
    'F1-Score': f1_score(y_test, yp, zero_division=0),
    'AUC':      roc_auc_score(y_test, p),
    'Recall':   recall_score(y_test, yp, zero_division=0),
    'Precision':precision_score(y_test, yp, zero_division=0),
}

# ── LSTM-only ──
print('  Building LSTM-only ...', end=' ', flush=True)
inp2 = Input(shape=(n_feat, 1))
x2 = LSTM(64)(inp2)
x2 = Dropout(0.3)(x2)
x2 = Dense(64, activation='relu')(x2)
out2 = Dense(1, activation='sigmoid')(x2)
lstm_only_m = Model(inp2, out2)
lstm_only_m.compile(Adam(0.001), 'binary_crossentropy',
                    metrics=[tf.keras.metrics.AUC(name='auc')])
t0 = time.time()
lstm_only_m.fit(Xab_3d, yab_tr, epochs=15, batch_size=256, verbose=0,
                validation_split=0.1, callbacks=_cb)
print(f'{time.time()-t0:.0f}s')
p2 = lstm_only_m.predict(Xtest_3d, verbose=0).flatten()
yp2 = (p2 >= 0.5).astype(int)
ablation_results['LSTM Only'] = {
    'Accuracy': accuracy_score(y_test, yp2),
    'F1-Score': f1_score(y_test, yp2, zero_division=0),
    'AUC':      roc_auc_score(y_test, p2),
    'Recall':   recall_score(y_test, yp2, zero_division=0),
    'Precision':precision_score(y_test, yp2, zero_division=0),
}

# ── Full CNN+LSTM (saved, trained on full data) ──
ablation_results['CNN+LSTM\n(Full Train)'] = {
    'Accuracy': cnn_metrics['Accuracy'],
    'F1-Score': cnn_metrics['F1-Score'],
    'AUC':      cnn_metrics['AUC'],
    'Recall':   cnn_metrics['Recall'],
    'Precision':cnn_metrics['Precision'],
}
print('  Ablation complete.')


# ════════════════════════════════════════════════════════════
# 5.  FEATURE IMPORTANCE  (Random Forest)
# ════════════════════════════════════════════════════════════
banner('5/7  Feature importance (RF)')

fi_n = min(30_000, len(X_train_sc))
fi_idx = np.random.choice(len(X_train_sc), fi_n, replace=False)
rf_fi = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
rf_fi.fit(X_train_sc[fi_idx], y_train[fi_idx])
importances = rf_fi.feature_importances_
fi_order = np.argsort(importances)[::-1]
print('  RF feature importances computed.')


# ════════════════════════════════════════════════════════════
# 6.  GENERATE ALL PLOTS
# ════════════════════════════════════════════════════════════
banner('6/7  Generating plots')

# Sort model order for consistent display
_MODEL_ORDER = (
    ['Logistic Regression', 'Decision Tree', 'Random Forest', 'MLP']
    + ([k for k in all_results if k not in
        ['Logistic Regression','Decision Tree','Random Forest','MLP','CNN+LSTM (Ours)']])
    + ['CNN+LSTM (Ours)']
)
model_order = [m for m in _MODEL_ORDER if m in all_results]


# ── Plot 01: ROC Curves (all models) ──────────────────────
fig, ax = plt.subplots(figsize=(8, 6))
for name, color in zip(model_order, PALETTE):
    fpr_r, tpr_r, _ = roc_curve(y_test, all_probs[name])
    ra = auc(fpr_r, tpr_r)
    lw = 2.5 if 'CNN+LSTM' in name else 1.5
    ls = '-'  if 'CNN+LSTM' in name else '--'
    ax.plot(fpr_r, tpr_r, color=color, lw=lw, ls=ls,
            label=f'{name}  (AUC={ra:.4f})')
ax.plot([0,1],[0,1], 'k:', lw=1, label='Random (AUC=0.5000)')
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — All Models')
ax.legend(loc='lower right', fontsize=9)
ax.grid(alpha=0.25)
fig.tight_layout()
savefig('roc_all_models.png')


# ── Plot 02: Precision-Recall Curves ──────────────────────
fig, ax = plt.subplots(figsize=(8, 6))
for name, color in zip(model_order, PALETTE):
    prec_v, rec_v, _ = precision_recall_curve(y_test, all_probs[name])
    ap = average_precision_score(y_test, all_probs[name])
    lw = 2.5 if 'CNN+LSTM' in name else 1.5
    ax.plot(rec_v, prec_v, color=color, lw=lw,
            label=f'{name}  (AP={ap:.4f})')
base_ap = y_test.mean()
ax.axhline(base_ap, color='gray', ls=':', lw=1,
           label=f'Random baseline (AP={base_ap:.4f})')
ax.set_xlabel('Recall')
ax.set_ylabel('Precision')
ax.set_title('Precision-Recall Curves — All Models')
ax.legend(loc='upper right', fontsize=9)
ax.grid(alpha=0.25)
fig.tight_layout()
savefig('pr_curves_all_models.png')


# ── Plot 03: Threshold Analysis ───────────────────────────
thresholds = np.linspace(0.01, 0.99, 300)
precs_t, recs_t, f1s_t = [], [], []
for t in thresholds:
    yp_t = (y_prob_cnn >= t).astype(int)
    precs_t.append(precision_score(y_test, yp_t, zero_division=0))
    recs_t.append(recall_score(y_test, yp_t, zero_division=0))
    f1s_t.append(f1_score(y_test, yp_t, zero_division=0))

best_t_idx = np.argmax(f1s_t)
best_t     = thresholds[best_t_idx]

fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(thresholds, precs_t, color=PALETTE[0], lw=2, label='Precision')
ax.plot(thresholds, recs_t,  color=PALETTE[1], lw=2, label='Recall')
ax.plot(thresholds, f1s_t,   color=PALETTE[2], lw=2.5, label='F1-Score')
ax.axvline(best_t, color='gray',  ls='--', lw=1.5,
           label=f'Optimal threshold = {best_t:.2f}')
ax.axvline(0.50,   color='black', ls=':',  lw=1.2,
           label='Default threshold = 0.50')
ax.set_xlabel('Decision Threshold')
ax.set_ylabel('Score')
ax.set_title('Precision / Recall / F1 vs Decision Threshold — CNN+LSTM')
ax.legend(loc='center left')
ax.set_xlim(0, 1)
ax.set_ylim(0, 1.05)
ax.grid(alpha=0.25)
fig.tight_layout()
savefig('threshold_analysis.png')


# ── Plot 04: Dual Confusion Matrix ────────────────────────
cm_norm = cm_cnn.astype(float) / cm_cnn.sum(axis=1, keepdims=True)
fig, axes = plt.subplots(1, 2, figsize=(13, 5))
for ax_i, (data, fmt, title) in zip(
        axes, [(cm_cnn, 'd', 'Raw Counts'),
               (cm_norm, '.3f', 'Normalised (Row %)')]):
    sns.heatmap(data, annot=True, fmt=fmt, cmap='Blues', ax=ax_i,
                xticklabels=['Normal', 'MITM'],
                yticklabels=['Normal', 'MITM'],
                linewidths=0.5, linecolor='#cccccc',
                cbar_kws={'shrink': 0.8})
    ax_i.set_title(f'Confusion Matrix — {title}', pad=10)
    ax_i.set_xlabel('Predicted Label')
    ax_i.set_ylabel('True Label')
fig.suptitle('CNN+LSTM Detection Performance  '
             f'(Acc={cnn_metrics["Accuracy"]:.4f}  '
             f'F1={cnn_metrics["F1-Score"]:.4f})',
             fontsize=13, y=1.02)
fig.tight_layout()
savefig('confusion_matrix_dual.png')


# ── Plot 05: Feature Correlation Heatmap ─────────────────
n_corr = min(8000, len(X_raw))
corr_idx = np.random.choice(len(X_raw), n_corr, replace=False)
feat_df  = pd.DataFrame(X_raw[corr_idx], columns=features)
corr_mat = feat_df.corr()
mask_tri = np.triu(np.ones_like(corr_mat, dtype=bool))

fig, ax = plt.subplots(figsize=(14, 12))
sns.heatmap(corr_mat, mask=mask_tri, cmap='RdBu_r', center=0,
            square=True, linewidths=0.3, ax=ax,
            vmin=-1, vmax=1,
            cbar_kws={'label': 'Pearson r', 'shrink': 0.65})
ax.set_title('Feature Correlation Matrix (Selected 25 Features)', pad=12)
ax.tick_params(axis='x', rotation=45, labelsize=8)
ax.tick_params(axis='y', rotation=0,  labelsize=8)
fig.tight_layout()
savefig('feature_correlation.png')


# ── Plot 06: Per-dataset Class Distribution ───────────────
n_ds = len(dfs_individual)
fig, axes = plt.subplots(1, n_ds, figsize=(4.5*n_ds, 5), sharey=False)
if n_ds == 1:
    axes = [axes]

for ax_i, (sub_df, name) in zip(axes, zip(dfs_individual, ds_names)):
    sub_df = sub_df.copy()
    lc = next((c for c in sub_df.columns if c.lower() == 'label'), None)
    if lc:
        sub_df.rename(columns={lc: 'Label'}, inplace=True)
    if 'Label' not in sub_df.columns:
        continue
    sub_df['Label'] = sub_df['Label'].apply(
        lambda v: 'Normal'
        if any(x in str(v).lower() for x in ['normal', 'benign', '0'])
        else 'MITM')
    counts = sub_df['Label'].value_counts()
    bar_c  = [PALETTE[2] if l == 'Normal' else PALETTE[1] for l in counts.index]
    bars   = ax_i.bar(counts.index, counts.values,
                      color=bar_c, edgecolor='white', linewidth=0.5)
    for bar, val in zip(bars, counts.values):
        ax_i.text(bar.get_x() + bar.get_width()/2,
                  bar.get_height() + counts.max()*0.01,
                  f'{val:,}', ha='center', va='bottom', fontsize=9)
    ax_i.set_title(name[:28], fontsize=9)
    ax_i.set_xlabel('Class')
    if ax_i is axes[0]:
        ax_i.set_ylabel('Samples')
    ax_i.grid(axis='y', alpha=0.25)

handles = [mpatches.Patch(color=PALETTE[2], label='Normal'),
           mpatches.Patch(color=PALETTE[1], label='MITM')]
fig.legend(handles=handles, loc='upper right', fontsize=10)
fig.suptitle('Class Distribution per Dataset', fontsize=13)
fig.tight_layout()
savefig('class_distribution.png')


# ── Plot 07: Ablation Study ───────────────────────────────
ab_names   = list(ablation_results.keys())
ab_metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
ab_colors  = [PALETTE[0], PALETTE[1], PALETTE[2]]

fig, axes = plt.subplots(1, len(ab_metrics), figsize=(16, 5))
for ax_i, metric in zip(axes, ab_metrics):
    vals = [ablation_results[n][metric] for n in ab_names]
    bars = ax_i.bar(ab_names, vals, color=ab_colors,
                    edgecolor='white', linewidth=0.5)
    lo = max(0, min(vals) - 0.05)
    ax_i.set_ylim(lo, min(1.12, max(vals) + 0.08))
    ax_i.set_title(metric)
    ax_i.set_xticklabels(ab_names, rotation=12, fontsize=9)
    ax_i.grid(axis='y', alpha=0.25)
    for bar, val in zip(bars, vals):
        ax_i.text(bar.get_x() + bar.get_width()/2,
                  bar.get_height() + 0.004,
                  f'{val:.4f}', ha='center', va='bottom',
                  fontsize=8, fontweight='bold')

fig.suptitle('Ablation Study: CNN-only  vs  LSTM-only  vs  CNN+LSTM',
             fontsize=13)
fig.tight_layout()
savefig('ablation_study.png')


# ── Plot 08: Comprehensive Model Comparison (grouped bar) ─
metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
n_models  = len(model_order)
n_met     = len(metric_names)
x_pos     = np.arange(n_met)
width     = 0.72 / n_models
offsets   = (np.arange(n_models) - (n_models-1)/2) * width

fig, ax = plt.subplots(figsize=(15, 7))
for i, (name, color) in enumerate(zip(model_order, PALETTE)):
    vals = [all_results[name][m] for m in metric_names]
    ax.bar(x_pos + offsets[i], vals, width * 0.92,
           label=name, color=color, edgecolor='white', linewidth=0.4)

# Annotate CNN+LSTM bars
cnn_i = model_order.index('CNN+LSTM (Ours)')
for j, m in enumerate(metric_names):
    val = all_results['CNN+LSTM (Ours)'][m]
    ax.text(x_pos[j] + offsets[cnn_i], val + 0.018,
            f'{val:.3f}', ha='center', va='bottom',
            fontsize=8, fontweight='bold', color=PALETTE[cnn_i])

ax.set_xticks(x_pos)
ax.set_xticklabels(metric_names)
ax.set_ylim(0, 1.22)
ax.set_ylabel('Score')
ax.set_title('Comprehensive Model Comparison — MITM Detection in SDN')
ax.legend(loc='upper right', fontsize=9, ncol=2)
ax.grid(axis='y', alpha=0.25)
fig.tight_layout()
savefig('model_comparison_full.png')


# ── Plot 09: Score Distribution + CDF ────────────────────
fig, axes = plt.subplots(1, 2, figsize=(13, 5))

ax_l = axes[0]
bins = np.linspace(0, 1, 60)
ax_l.hist(y_prob_cnn[y_test==0], bins=bins, alpha=0.65,
          color=PALETTE[2], label='Normal', density=True)
ax_l.hist(y_prob_cnn[y_test==1], bins=bins, alpha=0.65,
          color=PALETTE[1], label='MITM',   density=True)
ax_l.axvline(0.5, color='black', ls='--', lw=1.5, label='Threshold=0.50')
ax_l.set_xlabel('Prediction Probability')
ax_l.set_ylabel('Density')
ax_l.set_title('Score Distribution (Density Histogram)')
ax_l.legend()
ax_l.grid(alpha=0.25)

ax_r = axes[1]
for lbl, color, name in [(0, PALETTE[2], 'Normal'), (1, PALETTE[1], 'MITM')]:
    p_sorted = np.sort(y_prob_cnn[y_test == lbl])
    cdf_vals = np.arange(1, len(p_sorted)+1) / len(p_sorted)
    ax_r.plot(p_sorted, cdf_vals, color=color, lw=2, label=name)
ax_r.axvline(0.5, color='black', ls='--', lw=1.5, label='Threshold=0.50')
ax_r.set_xlabel('Prediction Probability')
ax_r.set_ylabel('CDF')
ax_r.set_title('Cumulative Distribution of Scores')
ax_r.legend()
ax_r.grid(alpha=0.25)

fig.suptitle('CNN+LSTM Prediction Score Analysis', fontsize=13)
fig.tight_layout()
savefig('score_distribution_analysis.png')


# ── Plot 10: Feature Importance ───────────────────────────
N_SHOW = min(20, len(features))
top_n  = fi_order[:N_SHOW]
top_importances = importances[top_n]
top_names       = [features[i] for i in top_n]

# Sort ascending for horizontal bar (largest at top)
order = np.argsort(top_importances)
fig, ax = plt.subplots(figsize=(10, 8))
colors_fi = plt.cm.RdYlGn(np.linspace(0.25, 0.85, N_SHOW))
ax.barh(range(N_SHOW), top_importances[order],
        color=colors_fi, edgecolor='white', linewidth=0.4)
ax.set_yticks(range(N_SHOW))
ax.set_yticklabels([top_names[i] for i in order], fontsize=9)
ax.set_xlabel('Mean Decrease in Impurity')
ax.set_title('Top-20 Feature Importances (Random Forest)')
ax.grid(axis='x', alpha=0.25)
fig.tight_layout()
savefig('feature_importance_rank.png')


# ── Plot 11: Radar / Spider Chart ─────────────────────────
radar_names   = [m for m in model_order if m in all_results]
radar_metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
angles = np.linspace(0, 2*np.pi, len(radar_metrics), endpoint=False).tolist()
angles += angles[:1]

fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
ax.set_theta_offset(np.pi / 2)
ax.set_theta_direction(-1)
ax.set_xticks(angles[:-1])
ax.set_xticklabels(radar_metrics, fontsize=11)
ax.set_ylim(0.5, 1.05)
ax.set_yticks([0.6, 0.7, 0.8, 0.9, 1.0])
ax.set_yticklabels(['0.6','0.7','0.8','0.9','1.0'], fontsize=8)
ax.grid(alpha=0.3)

for name, color in zip(radar_names, PALETTE):
    vals  = [all_results[name][m] for m in radar_metrics] + [all_results[name][radar_metrics[0]]]
    lw    = 2.5 if 'CNN+LSTM' in name else 1.5
    alpha = 0.15 if 'CNN+LSTM' in name else 0.05
    ax.plot(angles, vals, color=color, lw=lw, label=name)
    ax.fill(angles, vals, alpha=alpha, color=color)

ax.set_title('Performance Radar Chart — All Models', pad=18, fontsize=13)
ax.legend(loc='upper right', bbox_to_anchor=(1.45, 1.15), fontsize=9)
fig.tight_layout()
savefig('metrics_radar.png')


# ── Plot 12: Detection Latency Simulation ─────────────────
# Model receives flow features. Early in a flow, temporal stats
# (PIAT mean/std, byte counts) are unreliable — we simulate this
# by adding proportional Gaussian noise to MITM-class test samples.
attack_samples = X_test_cnn[(y_test == 1)]
pkt_counts  = [1, 3, 5, 10, 15, 20, 30, 50, 100]
det_rates   = []
fp_rates    = []

normal_samples = X_test_cnn[(y_test == 0)][:len(attack_samples)]

for n_pkt in pkt_counts:
    noise_std = max(0.0, (1.0 - n_pkt / 50.0)) * 0.6
    Xn_attack = attack_samples + np.random.normal(0, noise_std, attack_samples.shape)
    Xn_normal = normal_samples + np.random.normal(0, noise_std * 0.3, normal_samples.shape)

    p_att = model.predict(Xn_attack, verbose=0).flatten()
    p_nor = model.predict(Xn_normal, verbose=0).flatten()

    det_rates.append((p_att >= 0.5).mean())
    fp_rates.append((p_nor >= 0.5).mean())

fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(pkt_counts, det_rates, 'o-', color=PALETTE[0], lw=2.5, ms=7,
        label='Detection Rate (MITM)')
ax.plot(pkt_counts, fp_rates,  's--', color=PALETTE[1], lw=2.0, ms=6,
        label='False Positive Rate (Normal)')
ax.axhline(0.95, color=PALETTE[2], ls='--', lw=1.5, label='95% Detection')
ax.axvline(20,   color='gray',     ls=':',  lw=1.5,
           label='Controller trigger (20 pkts)')
ax.fill_between(pkt_counts, det_rates, alpha=0.12, color=PALETTE[0])
ax.set_xlabel('Packets Observed per Flow')
ax.set_ylabel('Rate')
ax.set_title('Detection Rate vs Packets Observed (CNN+LSTM)')
ax.set_ylim(-0.05, 1.12)
ax.legend(loc='lower right')
ax.grid(alpha=0.25)
fig.tight_layout()
savefig('detection_latency_sim.png')


# ── Plot 13: Test Metrics Summary Bar ─────────────────────
metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
metric_vals   = [cnn_metrics[k] for k in metric_labels]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(metric_labels, metric_vals,
              color=PALETTE[:len(metric_labels)],
              edgecolor='white', linewidth=0.5, width=0.55)
for bar, val in zip(bars, metric_vals):
    ax.text(bar.get_x() + bar.get_width()/2,
            bar.get_height() + 0.004,
            f'{val:.4f}', ha='center', va='bottom',
            fontsize=12, fontweight='bold')
ax.set_ylim(max(0, min(metric_vals)-0.05), 1.08)
ax.set_ylabel('Score')
ax.set_title('CNN+LSTM Final Test Metrics Summary')
ax.grid(axis='y', alpha=0.25)
fig.tight_layout()
savefig('metrics_summary.png')


# ── Plot 14: FPR Comparison ───────────────────────────────
fpr_dict = {}
for name in model_order:
    yp = (all_probs[name] >= 0.5).astype(int)
    _cm = confusion_matrix(y_test, yp)
    _tn, _fp, _fn, _tp = _cm.ravel()
    fpr_dict[name] = _fp / (_fp + _tn) * 100

names_fpr = list(fpr_dict.keys())
vals_fpr  = [fpr_dict[n] for n in names_fpr]
bar_c_fpr = [PALETTE[2] if 'CNN+LSTM' in n else PALETTE[1] for n in names_fpr]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.bar(names_fpr, vals_fpr,
              color=bar_c_fpr, edgecolor='white', linewidth=0.5)
for bar, val in zip(bars, vals_fpr):
    ax.text(bar.get_x() + bar.get_width()/2,
            bar.get_height() + 0.005,
            f'{val:.3f}%', ha='center', va='bottom',
            fontsize=10, fontweight='bold')
ax.set_xticklabels(names_fpr, rotation=20, ha='right')
ax.set_ylabel('False Positive Rate (%)')
ax.set_title('False Positive Rate Comparison  (Lower = Better)')
ax.grid(axis='y', alpha=0.25)
handles_fpr = [
    mpatches.Patch(color=PALETTE[1], label='Baseline Models'),
    mpatches.Patch(color=PALETTE[2], label='CNN+LSTM (Ours)'),
]
ax.legend(handles=handles_fpr)
fig.tight_layout()
savefig('false_positive_rate.png')


# ════════════════════════════════════════════════════════════
# 7.  SUMMARY TABLE
# ════════════════════════════════════════════════════════════
banner('7/7  Results summary')

print(f"\n{'Model':<25} {'Accuracy':>10} {'Precision':>10} "
      f"{'Recall':>10} {'F1-Score':>10} {'AUC':>10}")
print('-' * 75)
for name in model_order:
    m   = all_results[name]
    tag = '  ◀ (ours)' if 'CNN+LSTM' in name else ''
    print(f"{name:<25} {m['Accuracy']:>10.4f} {m['Precision']:>10.4f} "
          f"{m['Recall']:>10.4f} {m['F1-Score']:>10.4f} {m['AUC']:>10.4f}{tag}")

print('\n--- Ablation Study ---')
for name, m in ablation_results.items():
    clean = name.replace('\n', ' ')
    print(f"  {clean:<22} Acc={m['Accuracy']:.4f}  "
          f"F1={m['F1-Score']:.4f}  AUC={m['AUC']:.4f}")

print(f'\n{"="*60}')
print('  14 paper-quality plots saved to plots/')
print(f'{"="*60}\n')
