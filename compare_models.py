"""
compare_models.py
=================
Trains and compares multiple classifiers against the saved CNN+LSTM model
on an equal footing (same train/test split, same StandardScaler).

Models evaluated:
  1. Logistic Regression
  2. Decision Tree
  3. Random Forest
  4. MLP
  5. XGBoost          (if installed)
  6. CNN+LSTM (ours)

Outputs:
  plots/model_comparison.png        — grouped-bar Accuracy / F1 / AUC
  plots/roc_all_models.png          — ROC overlay (all models)
  plots/pr_curves_all_models.png    — Precision-Recall overlay
"""

import os, glob, time, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import joblib
import tensorflow as tf
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

warnings.filterwarnings('ignore')
tf.get_logger().setLevel('ERROR')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
np.random.seed(42)
tf.random.set_seed(42)

PALETTE  = ['#2E86AB', '#E84855', '#3BB273', '#F18F01', '#9B5DE5', '#00B4D8']
SAVE_DIR = 'plots'
os.makedirs(SAVE_DIR, exist_ok=True)

# ── helpers ────────────────────────────────────────────────

def encode(lbl):
    v = str(lbl).lower()
    return 0 if any(x in v for x in ['normal', 'benign', 'background', '0.0']) else 1

def feature_engineering(df):
    df = df.copy()
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(0).replace([np.inf, -np.inf], 0)
    df['packet_asymmetry']    = abs(df['src2dst_packets']  - df['dst2src_packets'])  / (df['bidirectional_packets'] + 1)
    df['byte_asymmetry']      = abs(df['src2dst_bytes']    - df['dst2src_bytes'])    / (df['bidirectional_bytes']   + 1)
    df['bytes_per_packet']    = df['bidirectional_bytes']  / (df['bidirectional_packets'] + 1)
    df['src2dst_bpp']         = df['src2dst_bytes']        / (df['src2dst_packets']  + 1)
    df['dst2src_bpp']         = df['dst2src_bytes']        / (df['dst2src_packets']  + 1)
    df['duration_ratio']      = df['src2dst_duration_ms']  / (df['dst2src_duration_ms'] + 1)
    df['syn_ratio']           = df['bidirectional_syn_packets'] / (df['bidirectional_packets'] + 1)
    df['rst_ratio']           = df['bidirectional_rst_packets'] / (df['bidirectional_packets'] + 1)
    df['piat_variance_ratio'] = df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + 1)
    df['ps_variance_ratio']   = df['bidirectional_stddev_ps']      / (df['bidirectional_mean_ps']      + 1)
    return df

def evaluate(y_true, y_pred, y_prob):
    return {
        'Accuracy':  accuracy_score(y_true, y_pred),
        'Precision': precision_score(y_true, y_pred, zero_division=0),
        'Recall':    recall_score(y_true, y_pred, zero_division=0),
        'F1-Score':  f1_score(y_true, y_pred, zero_division=0),
        'AUC':       roc_auc_score(y_true, y_prob),
    }

def savefig(name):
    p = os.path.join(SAVE_DIR, name)
    plt.savefig(p, dpi=300, bbox_inches='tight')
    plt.close('all')
    print(f'  ✓  {p}')

# ── Load data ──────────────────────────────────────────────
print('Loading datasets...')
files = glob.glob('dataset/*.csv') or glob.glob('archive/*.csv')
dfs   = []
for f in files:
    try:
        dfs.append(pd.read_csv(f, low_memory=False))
    except Exception as e:
        print(f'  Error: {f}: {e}')

df = pd.concat(dfs, ignore_index=True)
lc = next((c for c in df.columns if c.lower() == 'label'), None)
if lc and lc != 'Label':
    df.rename(columns={lc: 'Label'}, inplace=True)

df['Label'] = df['Label'].apply(encode)
df          = feature_engineering(df)

# Load feature list
features_path = 'model/selected_features.pkl'
if not os.path.exists(features_path):
    raise FileNotFoundError(f'Run train_model.py first — {features_path} not found.')

features = joblib.load(features_path)

for col in ['application_name', 'requested_server_name']:
    if col in features and col in df.columns:
        df[col] = pd.factorize(df[col])[0]

X = df.reindex(columns=features, fill_value=0).values
y = df['Label'].values

print(f'Total samples: {len(X):,}   MITM={y.sum():,}   Normal={(y==0).sum():,}')

# ── Train / test split ─────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

# Use the saved scaler (fitted on training data in train_model.py)
scaler       = joblib.load('model/scaler.pkl')
X_train_sc   = scaler.transform(X_train)
X_test_sc    = scaler.transform(X_test)

print(f'Train: {len(X_train):,}   Test: {len(X_test):,}')

# ── Baseline models (all receive scaled data) ─────────────
SAMPLE = min(50_000, len(X_train_sc))
idx    = np.random.choice(len(X_train_sc), SAMPLE, replace=False)
Xtr    = X_train_sc[idx]
ytr    = y_train[idx]

baselines = {
    'Logistic Regression': LogisticRegression(max_iter=500, C=1.0,
                                               random_state=42, n_jobs=-1),
    'Decision Tree':       DecisionTreeClassifier(max_depth=15, random_state=42),
    'Random Forest':       RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                                   random_state=42),
    'MLP':                 MLPClassifier(hidden_layer_sizes=(128, 64),
                                          max_iter=80, random_state=42,
                                          early_stopping=True),
}

try:
    from xgboost import XGBClassifier
    baselines['XGBoost'] = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        use_label_encoder=False, eval_metric='logloss',
        random_state=42, n_jobs=-1, verbosity=0)
except ImportError:
    pass

results      = {}
all_probs    = {}
train_times  = {}

print('\nTraining baseline models...')
for name, clf in baselines.items():
    print(f'  {name:<25}', end='  ', flush=True)
    t0 = time.time()
    clf.fit(Xtr, ytr)
    elapsed = time.time() - t0
    train_times[name] = elapsed

    y_pred = clf.predict(X_test_sc)
    y_prob = (clf.predict_proba(X_test_sc)[:, 1]
              if hasattr(clf, 'predict_proba')
              else clf.decision_function(X_test_sc))
    if not hasattr(clf, 'predict_proba'):
        y_prob = (y_prob - y_prob.min()) / (y_prob.ptp() + 1e-9)

    results[name]   = evaluate(y_test, y_pred, y_prob)
    all_probs[name] = y_prob
    print(f'F1={results[name]["F1-Score"]:.4f}  ({elapsed:.1f}s)')

# ── CNN+LSTM ───────────────────────────────────────────────
print('  CNN+LSTM (loading saved model)...', end='  ', flush=True)
cnn_model  = tf.keras.models.load_model('model/mitm_model.h5')
X_test_cnn = X_test_sc.reshape(X_test_sc.shape[0], X_test_sc.shape[1], 1)
t0         = time.time()
y_prob_cnn = cnn_model.predict(X_test_cnn, batch_size=4096, verbose=0).flatten()
y_pred_cnn = (y_prob_cnn >= 0.5).astype(int)
print(f'{time.time()-t0:.1f}s')

results['CNN+LSTM (Ours)']   = evaluate(y_test, y_pred_cnn, y_prob_cnn)
all_probs['CNN+LSTM (Ours)'] = y_prob_cnn

# ── Print table ────────────────────────────────────────────
print('\n' + '='*80)
print(f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} "
      f"{'Recall':>10} {'F1-Score':>10} {'AUC':>10}")
print('-'*80)
for name, m in results.items():
    tag = '  ◀ (ours)' if 'CNN+LSTM' in name else ''
    print(f"{name:<25} {m['Accuracy']:>10.4f} {m['Precision']:>10.4f} "
          f"{m['Recall']:>10.4f} {m['F1-Score']:>10.4f} {m['AUC']:>10.4f}{tag}")
print('='*80)

# ── Plot 1: Grouped-bar comparison ────────────────────────
model_names  = list(results.keys())
metric_names = ['Accuracy', 'F1-Score', 'AUC']
n_models  = len(model_names)
n_met     = len(metric_names)
x_pos     = np.arange(n_met)
width     = 0.70 / n_models
offsets   = (np.arange(n_models) - (n_models-1)/2) * width

fig, ax = plt.subplots(figsize=(13, 6))
for i, (name, color) in enumerate(zip(model_names, PALETTE)):
    vals = [results[name][m] for m in metric_names]
    ax.bar(x_pos + offsets[i], vals, width * 0.92,
           label=name, color=color, edgecolor='white', linewidth=0.4)

# Annotate CNN+LSTM
ci = model_names.index('CNN+LSTM (Ours)')
for j, m in enumerate(metric_names):
    val = results['CNN+LSTM (Ours)'][m]
    ax.text(x_pos[j] + offsets[ci], val + 0.018,
            f'{val:.3f}', ha='center', va='bottom',
            fontsize=9, fontweight='bold', color=PALETTE[ci])

ax.set_xticks(x_pos)
ax.set_xticklabels(metric_names, fontsize=12)
ax.set_ylim(0, 1.20)
ax.set_ylabel('Score')
ax.set_title('Model Comparison — Accuracy, F1-Score, AUC')
ax.legend(loc='upper right', fontsize=9, ncol=2)
ax.grid(axis='y', alpha=0.25)
fig.tight_layout()
savefig('model_comparison.png')

# ── Plot 2: ROC overlay ───────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 6))
for name, color in zip(model_names, PALETTE):
    fpr_v, tpr_v, _ = roc_curve(y_test, all_probs[name])
    ra = auc(fpr_v, tpr_v)
    lw = 2.5 if 'CNN+LSTM' in name else 1.5
    ls = '-'  if 'CNN+LSTM' in name else '--'
    ax.plot(fpr_v, tpr_v, color=color, lw=lw, ls=ls,
            label=f'{name}  (AUC={ra:.4f})')
ax.plot([0,1],[0,1], 'k:', lw=1, label='Random (AUC=0.5000)')
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — All Models')
ax.legend(loc='lower right', fontsize=9)
ax.grid(alpha=0.25)
fig.tight_layout()
savefig('roc_all_models.png')

# ── Plot 3: PR curves overlay ─────────────────────────────
fig, ax = plt.subplots(figsize=(8, 6))
for name, color in zip(model_names, PALETTE):
    pr_p, pr_r, _ = precision_recall_curve(y_test, all_probs[name])
    ap = average_precision_score(y_test, all_probs[name])
    lw = 2.5 if 'CNN+LSTM' in name else 1.5
    ax.plot(pr_r, pr_p, color=color, lw=lw,
            label=f'{name}  (AP={ap:.4f})')
ax.axhline(y_test.mean(), color='gray', ls=':', lw=1,
           label=f'Baseline (AP={y_test.mean():.4f})')
ax.set_xlabel('Recall')
ax.set_ylabel('Precision')
ax.set_title('Precision-Recall Curves — All Models')
ax.legend(loc='upper right', fontsize=9)
ax.grid(alpha=0.25)
fig.tight_layout()
savefig('pr_curves_all_models.png')

print('\nDone. Saved 3 comparison plots to plots/')
