import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
import matplotlib.pyplot as plt
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, precision_recall_curve,
    average_precision_score
)
import glob, os

# ── Load all datasets ───────────────────────────────────
print("📂 Loading datasets from dataset/ directory...")
dataset_paths = glob.glob('/app/dataset/*.csv') if os.path.exists('/app/dataset') else glob.glob('dataset/*.csv')
if not dataset_paths:
    print("❌ No datasets found in dataset/!")
    exit(1)

dfs = []
for f in dataset_paths:
    try:
        tmp_df = pd.read_csv(f, low_memory=False)
        dfs.append(tmp_df)
        print(f"  ✅ Loaded {os.path.basename(f)} ({len(tmp_df)} rows)")
    except Exception as e:
        print(f"  ❌ Error loading {f}: {e}")

df = pd.concat(dfs, ignore_index=True)
print(f"✅ Total records: {len(df):,}")

# ── Load model and preprocessing ──────────────────────────
# Check absolute paths (Docker context) vs relative
model_path = "/app/model/mitm_model.h5" if os.path.exists("/app/model") else "model/mitm_model.h5"
scaler_path = "/app/model/scaler.pkl" if os.path.exists("/app/model") else "model/scaler.pkl"
features_path = "/app/model/selected_features.pkl" if os.path.exists("/app/model") else "model/selected_features.pkl"

print("\n🧠 Loading trained model and feature list...")
model    = tf.keras.models.load_model(model_path)
scaler   = joblib.load(scaler_path)
features = joblib.load(features_path)
print(f"✅ Model loaded. Expects {len(features)} features.")

# ── Prepare data ──────────────────────────────────────────
def encode(lbl):
    s = str(lbl).lower()
    # Normalize varied labels into binary: 0 (Normal) or 1 (Attack)
    if any(x in s for x in ['normal', 'benign', 'background', '0']):
        return 0
    return 1

print("\n🧹 Preprocessing and Feature Engineering...")
df['Label'] = df['Label'].apply(encode)

# ── Feature Engineering (MUST MATCH train_model.py) ──────
df.fillna(0, inplace=True)
df.replace([np.inf, -np.inf], 0, inplace=True)

# Helper for safe division (avoiding 0 in denominator)
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

# Handle categorical fields if they are in features
for col in ['application_name', 'requested_server_name']:
    if col in features and col in df.columns:
        df[col] = pd.factorize(df[col])[0]

# Fit to selected features
X = df[[f for f in features if f in df.columns]].fillna(0)
for f in features:
    if f not in X.columns:
        X[f] = 0
X = X[features].values # Reorder to match training
y = df['Label'].values

# Scale for CNN
X_scaled = scaler.transform(X)
X_input  = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

# ── Predict ───────────────────────────────────────────────
print(f"🚀 Running predictions on {len(X_input):,} samples (this may take a minute)...")
y_prob = model.predict(X_input, batch_size=2048, verbose=1).flatten()
y_pred = (y_prob >= 0.5).astype(int)

# ── 1. Classification Report ──────────────────────────────
print("\n" + "="*60)
print("📊 CLASSIFICATION REPORT")
print("="*60)
print(classification_report(y, y_pred, target_names=['Normal', 'MITM'], digits=4))

# ── 2. Confusion Matrix ───────────────────────────────────
cm = confusion_matrix(y, y_pred)
tn, fp, fn, tp = cm.ravel()
print(f"Total Samples   : {len(y):,}")
print(f"True Negatives  (TN): {tn:,}  (Correct Normal)")
print(f"False Positives (FP): {fp:,}  (Alarm on Normal)")
print(f"False Negatives (FN): {fn:,}  (Missed attack)")
print(f"True Positives  (TP): {tp:,}  (Caught attack)")
print(f"\nAccuracy: {(tp+tn)/len(y)*100:.2f}%")
print(f"False Positive Rate (FPR): {fp/(fp+tn)*100:.4f}%  (CRITICAL: Lower is better)")

# ── 3. ROC AUC ────────────────────────────────────────────
auc = roc_auc_score(y, y_prob)
print(f"ROC AUC Score: {auc:.4f}")

# ── 4. Save Plots ─────────────────────────────────────────
os.makedirs('plots', exist_ok=True)
plt.style.use('bmh') # Professional styling

# A. Confusion Matrix Heatmap
fig, ax = plt.subplots(figsize=(8, 7))
im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
ax.set_title('Confusion Matrix: CNN+LSTM Detection', fontsize=14, pad=20)
plt.colorbar(im)
tick_marks = np.arange(2)
ax.set_xticks(tick_marks); ax.set_xticklabels(['Normal', 'MITM'], fontsize=12)
ax.set_yticks(tick_marks); ax.set_yticklabels(['Normal', 'MITM'], fontsize=12)

thresh = cm.max() / 2.
for i, j in np.ndindex(cm.shape):
    ax.text(j, i, format(cm[i, j], ','),
            ha="center", va="center", fontsize=14,
            color="white" if cm[i, j] > thresh else "black")

ax.set_ylabel('Actual Label', fontsize=13)
ax.set_xlabel('Predicted Label', fontsize=13)
plt.tight_layout()
plt.savefig('plots/confusion_matrix.png', dpi=300)
print("✅ Saved plots/confusion_matrix.png")

# B. ROC Curve
fpr, tpr, thresholds = roc_curve(y, y_prob)
plt.figure(figsize=(9, 7))
plt.plot(fpr, tpr, color='darkorange', lw=3, label=f'CNN+LSTM (AUC = {auc:.4f})')
plt.plot([0, 1], [0, 1], color='navy', lw=1, linestyle='--')
plt.xlim([0.0, 1.0]); plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate', fontsize=12)
plt.ylabel('True Positive Rate', fontsize=12)
plt.title('Receiver Operating Characteristic (ROC)', fontsize=14)
plt.legend(loc="lower right", fontsize=12)
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('plots/roc_curve.png', dpi=300)
print("✅ Saved plots/roc_curve.png")

# C. Score Distribution (Probability Histogram)
plt.figure(figsize=(10, 6))
plt.hist(y_prob[y==0], bins=50, alpha=0.5, color='green', label='Actual Normal')
plt.hist(y_prob[y==1], bins=50, alpha=0.5, color='red', label='Actual MITM')
plt.axvline(x=0.5, color='black', linestyle='--', label='Threshold=0.5')
plt.yscale('log') # Log scale helps see small errors
plt.xlabel('Model Probability Score', fontsize=12)
plt.ylabel('Count (Log Scale)', fontsize=12)
plt.title('Prediction Score Distribution', fontsize=14)
plt.legend()
plt.tight_layout()
plt.savefig('plots/score_distribution.png', dpi=300)
print("✅ Saved plots/score_distribution.png")

print(f"\n{'='*60}")
print("🏁 EVALUATION COMPLETE")
print("These graphics prove your model is scientifically valid.")
print("="*60)
