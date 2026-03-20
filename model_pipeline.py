import os, glob, warnings, joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    matthews_corrcoef
)

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Conv1D, BatchNormalization, MaxPooling1D, Dropout,
    Bidirectional, LSTM, Dense, GlobalAveragePooling1D,
    MultiHeadAttention, LayerNormalization, Add
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.regularizers import l2

warnings.filterwarnings('ignore')
os.makedirs('model', exist_ok=True)
os.makedirs('plots', exist_ok=True)
np.random.seed(42)
tf.random.set_seed(42)

# Publication-quality plot style
plt.rcParams.update({
    'figure.dpi': 150,
    'font.family': 'DejaVu Sans',
    'font.size': 11,
    'axes.titlesize': 13,
    'axes.labelsize': 11,
    'axes.spines.top': False,
    'axes.spines.right': False,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'legend.framealpha': 0.8,
})
COLORS = {'train': '#2196F3', 'val': '#FF5722', 'normal': '#4CAF50', 'attack': '#F44336'}

print('Environment ready. TF version:', tf.__version__)

all_files = glob.glob('dataset/*.csv')
df_list = []
for f in all_files:
    temp = pd.read_csv(f, low_memory=False)
    # Normalize the label column name
    lbl_col = next((c for c in temp.columns if c.lower() == 'label'), None)
    if lbl_col and lbl_col != 'Label':
        temp.rename(columns={lbl_col: 'Label'}, inplace=True)
    df_list.append(temp)
    print(f'  Loaded {os.path.basename(f)}: {temp.shape[0]:,} rows, {temp.shape[1]} cols')

df = pd.concat(df_list, axis=0, ignore_index=True)
print(f'\nTotal merged: {df.shape[0]:,} rows x {df.shape[1]} columns')

# Plot initial label distribution
fig, ax = plt.subplots(figsize=(7, 4))
counts = df['Label'].value_counts()
bars = ax.bar(counts.index, counts.values, color=[COLORS['normal'], COLORS['attack']], edgecolor='white', linewidth=0.8)
for bar, val in zip(bars, counts.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 500, f'{val:,}', ha='center', fontweight='bold')
ax.set_title('Label Distribution — Merged Dataset')
ax.set_ylabel('Flow Count')
ax.set_xlabel('Label')
plt.tight_layout()
plt.savefig('plots/01_label_distribution.png', bbox_inches='tight')
plt.show()
print('Class balance ratio:', round(counts.min()/counts.max(), 3))

# These columns are identifiers or meta-fields, not flow features
cols_to_drop = [
    'id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'dst_ip', 'dst_mac', 'dst_oui',
    'vlan_id', 'tunnel_id', 'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms',
    'src2dst_first_seen_ms', 'src2dst_last_seen_ms', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
    'user_agent', 'content_type', 'requested_server_name', 'client_fingerprint',
    'server_fingerprint', 'application_name', 'application_category_name',
    'application_is_guessed', 'application_confidence'
]
existing_drops = [c for c in cols_to_drop if c in df.columns]
df.drop(columns=existing_drops, inplace=True)
print(f'Dropped {len(existing_drops)} non-feature columns. Remaining: {df.shape[1]} columns')

def encode_label(val):
    v = str(val).strip().lower()
    return 0 if v in ['normal', 'benign', '0', '0.0'] else 1

df['Label'] = df['Label'].apply(encode_label)
label_counts = df['Label'].value_counts()
print('Binary class distribution:')
print(f'  Normal (0): {label_counts.get(0, 0):,}')
print(f'  MITM   (1): {label_counts.get(1, 0):,}')
print(f'  Imbalance ratio: {label_counts.min()/label_counts.max():.3f}')

df.replace([np.inf, -np.inf], np.nan, inplace=True)
missing_before = df.isnull().sum().sum()
df.fillna(0, inplace=True)
print(f'Resolved {missing_before:,} missing/infinite values (filled with 0)')

eps = 1  # avoid division by zero
df['packet_asymmetry']   = np.abs(df['src2dst_packets'] - df['dst2src_packets']) / (df['bidirectional_packets'] + eps)
df['byte_asymmetry']     = np.abs(df['src2dst_bytes'] - df['dst2src_bytes']) / (df['bidirectional_bytes'] + eps)
df['bytes_per_packet']   = df['bidirectional_bytes'] / (df['bidirectional_packets'] + eps)
df['src2dst_bpp']        = df['src2dst_bytes'] / (df['src2dst_packets'] + eps)
df['dst2src_bpp']        = df['dst2src_bytes'] / (df['dst2src_packets'] + eps)
df['duration_ratio']     = df['src2dst_duration_ms'] / (df['dst2src_duration_ms'] + eps)
df['syn_ratio']          = df['bidirectional_syn_packets'] / (df['bidirectional_packets'] + eps)
df['rst_ratio']          = df['bidirectional_rst_packets'] / (df['bidirectional_packets'] + eps)
df['piat_variance_ratio']= df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + eps)
df['ps_variance_ratio']  = df['bidirectional_stddev_ps'] / (df['bidirectional_mean_ps'] + eps)

# Clip extreme engineered values to prevent outlier dominance
eng_feats = ['packet_asymmetry','byte_asymmetry','bytes_per_packet','src2dst_bpp',
             'dst2src_bpp','duration_ratio','syn_ratio','rst_ratio','piat_variance_ratio','ps_variance_ratio']
for col in eng_feats:
    df[col] = df[col].clip(lower=df[col].quantile(0.01), upper=df[col].quantile(0.99))

print(f'Engineered {len(eng_feats)} MITM-specific features. Dataset shape: {df.shape}')

X_fs = df.drop('Label', axis=1)
y_fs = df['Label']

# Convert object columns to numeric, drop if fully non-numeric
X_fs = X_fs.apply(pd.to_numeric, errors='coerce').fillna(0)

sample_size = min(50000, len(df))
X_samp, _, y_samp, _ = train_test_split(X_fs, y_fs, train_size=sample_size, stratify=y_fs, random_state=42)

print(f'Running RF-RFE on {sample_size:,} samples...')
rf = RandomForestClassifier(n_jobs=-1, n_estimators=100, random_state=42, class_weight='balanced')
rfe = RFE(estimator=rf, n_features_to_select=25, step=5)
rfe.fit(X_samp, y_samp)

selected_features = X_fs.columns[rfe.support_].tolist()
joblib.dump(selected_features, 'model/selected_features.pkl')
print(f'Selected {len(selected_features)} features. Saved to model/selected_features.pkl')

# Publication-quality feature importance plot
importances = rfe.estimator_.feature_importances_
feat_imp = pd.Series(importances, index=selected_features).sort_values(ascending=True)

fig, ax = plt.subplots(figsize=(9, 7))
colors = plt.cm.RdYlGn(np.linspace(0.2, 0.9, len(feat_imp)))
bars = ax.barh(feat_imp.index, feat_imp.values, color=colors, edgecolor='white', linewidth=0.5)
ax.set_xlabel('Feature Importance (Gini)')
ax.set_title('Top 25 Selected Features — RF-RFE Importance')
ax.axvline(feat_imp.mean(), color='navy', linestyle='--', alpha=0.6, label=f'Mean = {feat_imp.mean():.4f}')
ax.legend()
plt.tight_layout()
plt.savefig('plots/02_feature_importance.png', bbox_inches='tight')
plt.show()

# Narrow dataset to selected features only
df = df[selected_features + ['Label']]

X = df.drop('Label', axis=1).values
y = df['Label'].values

# 70 / 10 / 20 stratified split
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
X_val, X_test, y_val, y_test   = train_test_split(X_temp, y_temp, test_size=0.667, stratify=y_temp, random_state=42)

print(f'Train: {X_train.shape[0]:,} | Val: {X_val.shape[0]:,} | Test: {X_test.shape[0]:,}')

# Standardize — fit ONLY on training data
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_val_s   = scaler.transform(X_val)
X_test_s  = scaler.transform(X_test)
joblib.dump(scaler, 'model/scaler.pkl')

# Compute class weights — this replaces SMOTE
weights = compute_class_weight('balanced', classes=np.array([0, 1]), y=y_train)
class_weight_dict = {0: weights[0], 1: weights[1]}
print(f'Class weights: Normal={weights[0]:.4f}, MITM={weights[1]:.4f}')

# Reshape for CNN input: (samples, timesteps=n_features, channels=1)
n_feat = X_train_s.shape[1]
X_train_c = X_train_s.reshape(-1, n_feat, 1)
X_val_c   = X_val_s.reshape(-1, n_feat, 1)
X_test_c  = X_test_s.reshape(-1, n_feat, 1)

# Class distribution plot
fig, axes = plt.subplots(1, 3, figsize=(12, 4))
for ax, split_y, title in zip(axes, [y_train, y_val, y_test], ['Train (70%)', 'Validation (10%)', 'Test (20%)']):
    vals, cnts = np.unique(split_y, return_counts=True)
    ax.bar(['Normal', 'MITM'], cnts, color=[COLORS['normal'], COLORS['attack']], edgecolor='white')
    for i, c in enumerate(cnts):
        ax.text(i, c + 100, f'{c:,}', ha='center', fontsize=9, fontweight='bold')
    ax.set_title(title)
    ax.set_ylabel('Count')
plt.suptitle('Class Distribution Across Splits', fontsize=13, fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig('plots/03_split_distributions.png', bbox_inches='tight')
plt.show()

def build_model(n_features, l2_reg=1e-4):
    inp = Input(shape=(n_features, 1), name='input')

    # --- CNN Block 1 ---
    x = Conv1D(64, kernel_size=3, padding='same', activation='relu',
               kernel_regularizer=l2(l2_reg), name='conv1')(inp)
    x = BatchNormalization(name='bn1')(x)
    x = MaxPooling1D(2, name='pool1')(x)
    x = Dropout(0.15, name='drop1')(x)

    # --- CNN Block 2 ---
    x = Conv1D(128, kernel_size=3, padding='same', activation='relu',
               kernel_regularizer=l2(l2_reg), name='conv2')(x)
    x = BatchNormalization(name='bn2')(x)
    x = MaxPooling1D(2, name='pool2')(x)
    x = Dropout(0.15, name='drop2')(x)

    # --- Bidirectional LSTM ---
    x = Bidirectional(LSTM(64, return_sequences=True, dropout=0.1, recurrent_dropout=0.0),
                       name='bilstm')(x)
    x = Dropout(0.20, name='drop3')(x)

    # --- Multi-Head Self-Attention (residual) ---
    attn_out = MultiHeadAttention(num_heads=2, key_dim=32, name='mha')(x, x)
    x = Add(name='res_add')([x, attn_out])         # residual connection
    x = LayerNormalization(name='layer_norm')(x)

    # --- Global Average Pooling ---
    x = GlobalAveragePooling1D(name='gap')(x)

    # --- Dense Classifier ---
    x = Dense(64, activation='relu', kernel_regularizer=l2(l2_reg), name='dense1')(x)
    x = BatchNormalization(name='bn3')(x)
    x = Dropout(0.20, name='drop4')(x)
    x = Dense(32, activation='relu', kernel_regularizer=l2(l2_reg), name='dense2')(x)
    x = Dropout(0.15, name='drop5')(x)
    out = Dense(1, activation='sigmoid', name='output')(x)

    model = Model(inputs=inp, outputs=out, name='MITM_CNN_BiLSTM_Attention')
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', tf.keras.metrics.AUC(name='auc'),
                 tf.keras.metrics.Precision(name='precision'),
                 tf.keras.metrics.Recall(name='recall')]
    )
    return model

model = build_model(n_feat)
model.summary()

callbacks = [
    EarlyStopping(
        monitor='val_loss',      # monitor val_loss — most stable signal
        patience=7,
        restore_best_weights=True,
        verbose=1
    ),
    ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=3,
        min_lr=1e-6,
        verbose=1
    ),
    ModelCheckpoint(
        'model/best_checkpoint.h5',
        monitor='val_auc',
        save_best_only=True,
        mode='max',
        verbose=0
    )
]

history = model.fit(
    X_train_c, y_train,
    validation_data=(X_val_c, y_val),
    epochs=50,
    batch_size=512,
    class_weight=class_weight_dict,   # handles imbalance without synthetic data
    callbacks=callbacks,
    verbose=1
)

# Predictions at threshold 0.5 (standard for binary classification)
y_prob = model.predict(X_test_c, verbose=0).flatten()
y_pred = (y_prob >= 0.5).astype(int)

# Core metrics
acc   = accuracy_score(y_test, y_pred)
prec  = precision_score(y_test, y_pred)
rec   = recall_score(y_test, y_pred)
f1    = f1_score(y_test, y_pred)
mcc   = matthews_corrcoef(y_test, y_pred)
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
ap    = average_precision_score(y_test, y_prob)

print('=' * 52)
print('         TEST SET PERFORMANCE METRICS')
print('=' * 52)
print(f'  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)')
print(f'  Precision : {prec:.4f}')
print(f'  Recall    : {rec:.4f}')
print(f'  F1-Score  : {f1:.4f}')
print(f'  ROC-AUC   : {roc_auc:.4f}')
print(f'  Avg Prec  : {ap:.4f}  (PR-AUC)')
print(f'  MCC       : {mcc:.4f}  (Matthews Corr. Coef.)')
print('=' * 52)
print()
print('Classification Report:')
print(classification_report(y_test, y_pred, target_names=['Normal', 'MITM']))

# ================================================================
# FIGURE 1: Training History (Accuracy + Loss + AUC)
# ================================================================
hist = history.history
epochs_ran = len(hist['loss'])

def smooth(values, weight=0.6):
    """Exponential moving average smoothing for noisy training curves."""
    smoothed, last = [], values[0]
    for v in values:
        last = last * weight + (1 - weight) * v
        smoothed.append(last)
    return smoothed

fig, axes = plt.subplots(1, 3, figsize=(15, 5))
ep = range(1, epochs_ran + 1)

for ax, metric, ylabel, title in zip(
    axes,
    [('accuracy', 'val_accuracy'), ('loss', 'val_loss'), ('auc', 'val_auc')],
    ['Accuracy', 'Loss', 'AUC'],
    ['Model Accuracy', 'Model Loss', 'Model AUC']
):
    tr_key, vl_key = metric
    tr_raw = hist[tr_key]
    vl_raw = hist[vl_key]
    ax.plot(ep, tr_raw, alpha=0.25, color=COLORS['train'])
    ax.plot(ep, vl_raw, alpha=0.25, color=COLORS['val'])
    ax.plot(ep, smooth(tr_raw), color=COLORS['train'], linewidth=2, label='Train')
    ax.plot(ep, smooth(vl_raw), color=COLORS['val'], linewidth=2, label='Val')
    best_ep = np.argmin(hist['val_loss']) + 1
    ax.axvline(best_ep, color='gray', linestyle=':', alpha=0.7, label=f'Best epoch={best_ep}')
    ax.set_title(title, fontweight='bold')
    ax.set_xlabel('Epoch')
    ax.set_ylabel(ylabel)
    ax.legend(fontsize=9)

plt.suptitle('Training History — CNN + BiLSTM + Attention', fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig('plots/04_training_history.png', bbox_inches='tight')
plt.show()

# ================================================================
# FIGURE 2: Confusion Matrix (counts + row-normalized percentages)
# ================================================================
cm = confusion_matrix(y_test, y_pred)
cm_norm = cm.astype('float') / cm.sum(axis=1, keepdims=True)

fig, axes = plt.subplots(1, 2, figsize=(12, 5))
for ax, data, fmt, title in zip(
    axes,
    [cm, cm_norm],
    ['d', '.2%'],
    ['Confusion Matrix (Counts)', 'Confusion Matrix (Row-Normalized %)']
):
    sns.heatmap(
        data, annot=True, fmt=fmt, cmap='Blues' if fmt == 'd' else 'YlOrRd',
        xticklabels=['Normal', 'MITM'],
        yticklabels=['Normal', 'MITM'],
        linewidths=0.5, linecolor='white',
        ax=ax, cbar=True,
        annot_kws={'size': 13, 'weight': 'bold'}
    )
    ax.set_title(title, fontweight='bold')
    ax.set_ylabel('True Label')
    ax.set_xlabel('Predicted Label')

plt.suptitle('Confusion Matrix Analysis', fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig('plots/05_confusion_matrix.png', bbox_inches='tight')
plt.show()

# ================================================================
# FIGURE 3: ROC Curve + Precision-Recall Curve
# ================================================================
prec_curve, rec_curve, _ = precision_recall_curve(y_test, y_prob)

fig, axes = plt.subplots(1, 2, figsize=(13, 5))

# ROC curve
axes[0].plot(fpr, tpr, color='#1565C0', linewidth=2.5, label=f'CNN+BiLSTM+Attn (AUC = {roc_auc:.4f})')
axes[0].fill_between(fpr, tpr, alpha=0.1, color='#1565C0')
axes[0].plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
axes[0].set_xlim([-0.01, 1.0])
axes[0].set_ylim([0.0, 1.02])
axes[0].set_xlabel('False Positive Rate')
axes[0].set_ylabel('True Positive Rate')
axes[0].set_title('Receiver Operating Characteristic (ROC)', fontweight='bold')
axes[0].legend(loc='lower right')

# PR curve
axes[1].plot(rec_curve, prec_curve, color='#C62828', linewidth=2.5, label=f'CNN+BiLSTM+Attn (AP = {ap:.4f})')
axes[1].fill_between(rec_curve, prec_curve, alpha=0.1, color='#C62828')
baseline = y_test.sum() / len(y_test)
axes[1].axhline(baseline, color='k', linestyle='--', linewidth=1, label=f'No-skill baseline ({baseline:.3f})')
axes[1].set_xlim([0.0, 1.0])
axes[1].set_ylim([0.0, 1.02])
axes[1].set_xlabel('Recall')
axes[1].set_ylabel('Precision')
axes[1].set_title('Precision-Recall Curve', fontweight='bold')
axes[1].legend(loc='lower left')

plt.suptitle('Model Discrimination Curves', fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig('plots/06_roc_pr_curves.png', bbox_inches='tight')
plt.show()

# ================================================================
# FIGURE 4: Score Distribution (Predicted Probability Histogram)
# ================================================================
fig, ax = plt.subplots(figsize=(9, 5))
ax.hist(y_prob[y_test == 0], bins=60, alpha=0.65, color=COLORS['normal'], label='Normal (0)', density=True)
ax.hist(y_prob[y_test == 1], bins=60, alpha=0.65, color=COLORS['attack'], label='MITM (1)', density=True)
ax.axvline(0.5, color='navy', linestyle='--', linewidth=1.5, label='Decision threshold = 0.5')
ax.set_xlabel('Predicted Probability (P[MITM])')
ax.set_ylabel('Density')
ax.set_title('Predicted Score Distribution by True Class', fontweight='bold')
ax.legend()
plt.tight_layout()
plt.savefig('plots/07_score_distribution.png', bbox_inches='tight')
plt.show()

# ================================================================
# FIGURE 5: Summary Metrics Bar Chart
# ================================================================
metrics_names  = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC', 'PR-AUC', 'MCC']
metrics_values = [acc, prec, rec, f1, roc_auc, ap, (mcc + 1) / 2]  # MCC scaled [0,1] for display
raw_values     = [acc, prec, rec, f1, roc_auc, ap, mcc]

fig, ax = plt.subplots(figsize=(10, 5))
bar_colors = plt.cm.RdYlGn([v for v in metrics_values])
bars = ax.bar(metrics_names, metrics_values, color=bar_colors, edgecolor='white', linewidth=0.8)
for bar, raw in zip(bars, raw_values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
            f'{raw:.4f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
ax.set_ylim(0, 1.12)
ax.set_ylabel('Score')
ax.set_title('Test Set Performance Summary — CNN + BiLSTM + Attention', fontweight='bold')
ax.axhline(0.95, color='navy', linestyle=':', alpha=0.5, label='0.95 reference')
ax.legend()
plt.tight_layout()
plt.savefig('plots/08_metrics_summary.png', bbox_inches='tight')
plt.show()
print('All plots saved to plots/ directory.')

from sklearn.utils.class_weight import compute_class_weight

# Use the full feature-selected dataset for CV
X_cv = df.drop('Label', axis=1).apply(pd.to_numeric, errors='coerce').fillna(0).values
y_cv = df['Label'].values

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = {'accuracy': [], 'f1': [], 'auc': [], 'mcc': []}

for fold, (tr_idx, vl_idx) in enumerate(skf.split(X_cv, y_cv)):
    X_tr, X_vl = X_cv[tr_idx], X_cv[vl_idx]
    y_tr, y_vl = y_cv[tr_idx], y_cv[vl_idx]

    sc = StandardScaler()
    X_tr = sc.fit_transform(X_tr).reshape(-1, n_feat, 1)
    X_vl = sc.transform(X_vl).reshape(-1, n_feat, 1)

    w = compute_class_weight('balanced', classes=np.array([0, 1]), y=y_tr)
    cw = {0: w[0], 1: w[1]}

    m = build_model(n_feat)
    m.fit(X_tr, y_tr, epochs=20, batch_size=512, class_weight=cw,
          validation_data=(X_vl, y_vl),
          callbacks=[EarlyStopping(monitor='val_loss', patience=4, restore_best_weights=True)],
          verbose=0)

    prob = m.predict(X_vl, verbose=0).flatten()
    pred = (prob >= 0.5).astype(int)

    cv_results['accuracy'].append(accuracy_score(y_vl, pred))
    cv_results['f1'].append(f1_score(y_vl, pred))
    cv_results['auc'].append(auc(*roc_curve(y_vl, prob)[:2]))
    cv_results['mcc'].append(matthews_corrcoef(y_vl, pred))
    print(f'  Fold {fold+1}: Acc={cv_results["accuracy"][-1]:.4f}  F1={cv_results["f1"][-1]:.4f}  AUC={cv_results["auc"][-1]:.4f}  MCC={cv_results["mcc"][-1]:.4f}')

print('\n5-Fold Cross-Validation Summary:')
print(f'{"Metric":<12}  {"Mean":>8}  {"Std":>8}')
print('-' * 32)
for k, v in cv_results.items():
    print(f'{k:<12}  {np.mean(v):>8.4f}  {np.std(v):>8.4f}')

# Box plot of CV results
fig, ax = plt.subplots(figsize=(8, 5))
bp = ax.boxplot([cv_results[k] for k in cv_results], labels=['Accuracy', 'F1-Score', 'ROC-AUC', 'MCC'],
                patch_artist=True, notch=False)
colors_cv = ['#2196F3', '#4CAF50', '#FF9800', '#9C27B0']
for patch, color in zip(bp['boxes'], colors_cv):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)
ax.set_ylim(0.8, 1.02)
ax.set_ylabel('Score')
ax.set_title('5-Fold Cross-Validation Results', fontweight='bold')
plt.tight_layout()
plt.savefig('plots/09_cross_validation.png', bbox_inches='tight')
plt.show()

model.save('model/mitm_model.h5')

# Save final metrics for reference
results = {
    'accuracy': float(acc), 'precision': float(prec), 'recall': float(rec),
    'f1': float(f1), 'roc_auc': float(roc_auc), 'pr_auc': float(ap), 'mcc': float(mcc),
    'cv_accuracy_mean': float(np.mean(cv_results['accuracy'])),
    'cv_accuracy_std': float(np.std(cv_results['accuracy'])),
    'cv_f1_mean': float(np.mean(cv_results['f1'])),
    'cv_f1_std': float(np.std(cv_results['f1'])),
    'cv_auc_mean': float(np.mean(cv_results['auc'])),
    'cv_auc_std': float(np.std(cv_results['auc'])),
}
import json
with open('model/results.json', 'w') as fp:
    json.dump(results, fp, indent=2)

print('Pipeline complete!')
print('Saved:')
print('  model/mitm_model.h5         <- Trained CNN+BiLSTM+Attention model')
print('  model/scaler.pkl            <- StandardScaler (apply before inference)')
print('  model/selected_features.pkl <- List of 25 selected feature names')
print('  model/results.json          <- Full metrics summary')
print('  plots/                      <- All 9 publication-ready figures')
