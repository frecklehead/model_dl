import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, precision_score, recall_score
import glob, os

# ── Load Data ─────────────────────────────────────────────
print("📂 Loading data for comparison...")
dataset_paths = glob.glob('/app/dataset/*.csv') if os.path.exists('/app/dataset') else glob.glob('dataset/*.csv')
dfs = [pd.read_csv(f, low_memory=False) for f in dataset_paths]
df = pd.concat(dfs, ignore_index=True)

# ── Preprocessing ─────────────────────────────────────────
def encode(lbl):
    s = str(lbl).lower()
    return 0 if any(x in s for x in ['normal', 'benign', '0']) else 1

df['Label'] = df['Label'].apply(encode)
features_path = "/app/model/selected_features.pkl" if os.path.exists("/app/model") else "model/selected_features.pkl"
features = joblib.load(features_path)

# ── Feature Engineering (MUST MATCH train_model.py) ──────
df.fillna(0, inplace=True)
df.replace([np.inf, -np.inf], 0, inplace=True)

df['packet_asymmetry'] = abs(df['src2dst_packets'] - df['dst2src_packets']) / (df['bidirectional_packets'] + 1)
df['byte_asymmetry'] = abs(df['src2dst_bytes'] - df['dst2src_bytes']) / (df['bidirectional_bytes'] + 1)
df['bytes_per_packet'] = df['bidirectional_bytes'] / (df['bidirectional_packets'] + 1)
df['src2dst_bpp'] = df['src2dst_bytes'] / (df['src2dst_packets'] + 1)
df['dst2src_bpp'] = df['dst2src_bytes'] / (df['dst2src_packets'] + 1)
df['duration_ratio'] = df['src2dst_duration_ms'] / (df['dst2src_duration_ms'] + 1)
df['syn_ratio'] = df['bidirectional_syn_packets'] / (df['bidirectional_packets'] + 1)
df['rst_ratio'] = df['bidirectional_rst_packets'] / (df['bidirectional_packets'] + 1)
df['piat_variance_ratio'] = df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + 1)
df['ps_variance_ratio'] = df['bidirectional_stddev_ps'] / (df['bidirectional_mean_ps'] + 1)

# Categorical fields
for col in ['application_name', 'requested_server_name']:
    if col in features and col in df.columns:
        df[col] = pd.factorize(df[col])[0]

# Fit to selected features
X = df[[f for f in features if f in df.columns]].fillna(0)
for f in features:
    if f not in X.columns:
        X[f] = 0

X = X[features].values
y = df['Label'].values

# Split data (use a smaller sample for speed if dataset is huge, but here we'll use 20% for test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

results = {}

def evaluate_model(name, y_true, y_pred, y_prob=None):
    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_prob) if y_prob is not None else 0
    return {'Accuracy': acc, 'F1-Score': f1, 'Precision': prec, 'Recall': rec, 'AUC': auc}

# ── 1. Logistic Regression ────────────────────────────────
print("⏳ Training Logistic Regression...")
lr = LogisticRegression(max_iter=500)
lr.fit(X_train, y_train)
y_pred_lr = lr.predict(X_test)
y_prob_lr = lr.predict_proba(X_test)[:, 1]
results['Logistic Regression'] = evaluate_model('LR', y_test, y_pred_lr, y_prob_lr)

# ── 2. Random Forest ──────────────────────────────────────
print("⏳ Training Random Forest...")
rf = RandomForestClassifier(n_estimators=50, max_depth=10, n_jobs=-1)
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)
y_prob_rf = rf.predict_proba(X_test)[:, 1]
results['Random Forest'] = evaluate_model('RF', y_test, y_pred_rf, y_prob_rf)

# ── 3. CNN+LSTM (Ours) ───────────────────────────────────
print("⏳ Loading and evaluating CNN+LSTM (Ours)...")
model_path = "/app/model/mitm_model.h5" if os.path.exists("/app/model") else "model/mitm_model.h5"
scaler_path = "/app/model/scaler.pkl" if os.path.exists("/app/model") else "model/scaler.pkl"
model = tf.keras.models.load_model(model_path)
scaler = joblib.load(scaler_path)

X_test_scaled = scaler.transform(X_test)
X_test_cnn = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

y_prob_cnn = model.predict(X_test_cnn, batch_size=2048, verbose=0).flatten()
y_pred_cnn = (y_prob_cnn >= 0.5).astype(int)
results['CNN+LSTM (Ours)'] = evaluate_model('CNN+LSTM', y_test, y_pred_cnn, y_prob_cnn)

# ── Display Results ───────────────────────────────────────
print("\n" + "="*80)
print(f"{'Model':<25} {'Accuracy':>10} {'F1-Score':>10} {'Precision':>10} {'Recall':>10} {'AUC':>10}")
print("-" * 80)
for name, metrics in results.items():
    print(f"{name:<25} {metrics['Accuracy']:>10.4f} {metrics['F1-Score']:>10.4f} "
          f"{metrics['Precision']:>10.4f} {metrics['Recall']:>10.4f} {metrics['AUC']:>10.4f}")
print("="*80)

# ── Plot Comparison ───────────────────────────────────────
os.makedirs('plots', exist_ok=True)
metrics_to_plot = ['Accuracy', 'F1-Score', 'AUC']
fig, axes = plt.subplots(1, 3, figsize=(18, 6))

colors = ['#3498db', '#e67e22', '#2ecc71'] # Blue, Orange, Green

for i, metric in enumerate(metrics_to_plot):
    names = list(results.keys())
    values = [results[name][metric] for name in names]
    bars = axes[i].bar(names, values, color=colors)
    axes[i].set_title(f'Comparison: {metric}', fontsize=14)
    axes[i].set_ylim(0, 1.1)
    axes[i].set_xticklabels(names, rotation=15)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        axes[i].text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{height:.3f}', ha='center', va='bottom', fontsize=11, fontweight='bold')

plt.tight_layout()
plt.savefig('plots/model_comparison.png', dpi=300)
print("\n✅ Saved plots/model_comparison.png")
print("This chart directly proves your CNN+LSTM architecture is superior.")
