"""
CNN-BiLSTM-Attention trainer for MITM detection.

Matches the architecture described in the thesis (Sections 4-5):
    Conv1D -> Conv1D -> BiLSTM -> Multi-Head Self-Attention -> Dense -> Sigmoid

Outputs (all under model/):
    mitm_model.h5             -- trained Keras model
    scaler.pkl                -- fitted StandardScaler (train only)
    selected_features.pkl     -- list of 25 selected feature names
    feature_importances.pkl   -- {feature: importance} from RF-RFE
    history.json              -- per-epoch metrics
    test_predictions.npz      -- y_test, y_pred_prob (for plotting)
    metrics.json              -- final test-set metrics
"""

import os
import glob
import json
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)
from imblearn.over_sampling import SMOTE
from tensorflow.keras import layers, Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

SEED = 42
np.random.seed(SEED)
tf.random.set_seed(SEED)

DATASET_DIR = "dataset"
MODEL_DIR = "model"
os.makedirs(MODEL_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# 1. Load + merge datasets
# ---------------------------------------------------------------------------
def load_data():
    files = sorted(glob.glob(os.path.join(DATASET_DIR, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSV files in {DATASET_DIR}/")
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        frames.append(df)
        print(f"  loaded {os.path.basename(f):<45} shape={df.shape}")
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# 2. Preprocess
# ---------------------------------------------------------------------------
DROP_COLS = [
    "id", "expiration_id", "src_ip", "src_mac", "src_oui",
    "dst_ip", "dst_mac", "dst_oui", "vlan_id", "tunnel_id",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms", "src2dst_last_seen_ms",
    "dst2src_first_seen_ms", "dst2src_last_seen_ms",
    "user_agent", "content_type", "requested_server_name",
    "client_fingerprint", "server_fingerprint",
    "application_name", "application_category_name",
    "application_is_guessed", "application_confidence",
]


def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    if "Label" not in df.columns:
        for c in df.columns:
            if c.lower() == "label":
                df = df.rename(columns={c: "Label"})
                break
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns])

    df["Label"] = df["Label"].astype(str).str.lower()
    df["Label"] = df["Label"].apply(
        lambda v: 0 if v in {"normal", "benign", "0", "0.0"} else 1
    )

    df = df.fillna(0).replace([np.inf, -np.inf], 0)

    # Engineered features
    df["packet_asymmetry"] = (df["src2dst_packets"] - df["dst2src_packets"]).abs() / (df["bidirectional_packets"] + 1)
    df["byte_asymmetry"] = (df["src2dst_bytes"] - df["dst2src_bytes"]).abs() / (df["bidirectional_bytes"] + 1)
    df["bytes_per_packet"] = df["bidirectional_bytes"] / (df["bidirectional_packets"] + 1)
    df["src2dst_bpp"] = df["src2dst_bytes"] / (df["src2dst_packets"] + 1)
    df["dst2src_bpp"] = df["dst2src_bytes"] / (df["dst2src_packets"] + 1)
    df["duration_ratio"] = df["src2dst_duration_ms"] / (df["dst2src_duration_ms"] + 1)
    df["syn_ratio"] = df["bidirectional_syn_packets"] / (df["bidirectional_packets"] + 1)
    df["rst_ratio"] = df["bidirectional_rst_packets"] / (df["bidirectional_packets"] + 1)
    df["piat_variance_ratio"] = df["bidirectional_stddev_piat_ms"] / (df["bidirectional_mean_piat_ms"] + 1)
    df["ps_variance_ratio"] = df["bidirectional_stddev_ps"] / (df["bidirectional_mean_ps"] + 1)

    # Keep only numeric columns + Label
    keep = df.select_dtypes(include=[np.number]).columns.tolist()
    if "Label" not in keep:
        keep.append("Label")
    return df[keep]


# ---------------------------------------------------------------------------
# 3. RF-RFE feature selection
# ---------------------------------------------------------------------------
def select_features(df: pd.DataFrame, n_features: int = 25):
    X = df.drop(columns=["Label"])
    y = df["Label"]
    sample_n = min(50000, len(df))
    X_s, _, y_s, _ = train_test_split(X, y, train_size=sample_n,
                                       stratify=y, random_state=SEED)
    rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=SEED)
    rfe = RFE(estimator=rf, n_features_to_select=n_features, step=2)
    rfe.fit(X_s, y_s)
    selected = X.columns[rfe.support_].tolist()
    importances = dict(zip(selected, rfe.estimator_.feature_importances_))
    return selected, importances


# ---------------------------------------------------------------------------
# 4. CNN-BiLSTM-Attention model
# ---------------------------------------------------------------------------
def build_model(n_features: int) -> Model:
    """
    Architecture (matches thesis Sections 4 + 5):
      Input (n_features, 1)
        -> Conv1D(64) -> BN -> MaxPool -> Dropout
        -> Conv1D(128) -> BN -> MaxPool -> Dropout
        -> Bidirectional(LSTM(64, return_sequences=True))
        -> MultiHeadAttention (self-attention, 4 heads)
        -> LayerNorm + residual
        -> GlobalAveragePooling1D
        -> Dense(64) -> BN -> Dropout
        -> Dense(1, sigmoid)
    """
    inp = layers.Input(shape=(n_features, 1), name="flow_input")

    x = layers.Conv1D(64, 3, padding="same", activation="relu")(inp)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(pool_size=2)(x)
    x = layers.Dropout(0.2)(x)

    x = layers.Conv1D(128, 3, padding="same", activation="relu")(x)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(pool_size=2)(x)
    x = layers.Dropout(0.2)(x)

    x = layers.Bidirectional(
        layers.LSTM(64, return_sequences=True), name="bilstm"
    )(x)

    attn = layers.MultiHeadAttention(num_heads=4, key_dim=32, name="self_attention")(x, x)
    x = layers.Add(name="attn_residual")([x, attn])
    x = layers.LayerNormalization(name="attn_norm")(x)
    x = layers.GlobalAveragePooling1D(name="pool")(x)

    x = layers.Dense(64, activation="relu")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.3)(x)
    out = layers.Dense(1, activation="sigmoid", name="output")(x)

    model = Model(inp, out, name="CNN_BiLSTM_Attention")
    model.compile(
        optimizer=Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
            tf.keras.metrics.AUC(name="auc"),
        ],
    )
    return model


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main():
    print("\n=== LOAD + PREPROCESS ===")
    df = load_data()
    print(f"  raw merged shape: {df.shape}")
    df = preprocess(df)
    print(f"  after preprocess: {df.shape}")
    print(f"  class balance: {df['Label'].value_counts().to_dict()}")

    print("\n=== RF-RFE FEATURE SELECTION ===")
    selected, importances = select_features(df, n_features=25)
    print(f"  selected {len(selected)} features")
    joblib.dump(selected, os.path.join(MODEL_DIR, "selected_features.pkl"))
    joblib.dump(importances, os.path.join(MODEL_DIR, "feature_importances.pkl"))
    df = df[selected + ["Label"]]

    print("\n=== SPLIT 70/10/20 ===")
    X = df.drop(columns=["Label"])
    y = df["Label"]
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30,
                                                 stratify=y, random_state=SEED)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=2/3,
                                                  stratify=y_tmp, random_state=SEED)
    print(f"  train={X_tr.shape}  val={X_val.shape}  test={X_te.shape}")

    print("\n=== SCALE ===")
    scaler = StandardScaler()
    X_tr_s  = scaler.fit_transform(X_tr)
    X_val_s = scaler.transform(X_val)
    X_te_s  = scaler.transform(X_te)
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    print("\n=== SMOTE (train only) ===")
    print(f"  before: {pd.Series(y_tr).value_counts().to_dict()}")
    smote = SMOTE(k_neighbors=5, random_state=SEED)
    X_tr_bal, y_tr_bal = smote.fit_resample(X_tr_s, y_tr)
    print(f"  after : {pd.Series(y_tr_bal).value_counts().to_dict()}")

    n_feat = X_tr_bal.shape[1]
    X_tr_cnn = X_tr_bal.reshape(-1, n_feat, 1)
    X_val_cnn = X_val_s.reshape(-1, n_feat, 1)
    X_te_cnn  = X_te_s.reshape(-1, n_feat, 1)

    print("\n=== BUILD MODEL ===")
    model = build_model(n_feat)
    model.summary()

    print("\n=== TRAIN ===")
    callbacks = [
        EarlyStopping(monitor="val_auc", mode="max", patience=7,
                       restore_best_weights=True),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=3,
                           min_lr=1e-5),
    ]
    history = model.fit(
        X_tr_cnn, y_tr_bal,
        validation_data=(X_val_cnn, y_val),
        epochs=25, batch_size=256,
        callbacks=callbacks, verbose=2,
    )

    print("\n=== TEST EVALUATION ===")
    y_prob = model.predict(X_te_cnn, batch_size=512, verbose=0).ravel()
    y_pred = (y_prob >= 0.5).astype(int)

    metrics = {
        "accuracy":  accuracy_score(y_te, y_pred),
        "precision": precision_score(y_te, y_pred),
        "recall":    recall_score(y_te, y_pred),
        "f1":        f1_score(y_te, y_pred),
        "auc":       roc_auc_score(y_te, y_prob),
    }
    cm = confusion_matrix(y_te, y_pred)
    tn, fp, fn, tp = cm.ravel()
    metrics["fpr"] = fp / (fp + tn) if (fp + tn) else 0.0
    metrics["tnr"] = tn / (tn + fp) if (tn + fp) else 0.0
    metrics["confusion_matrix"] = {"tn": int(tn), "fp": int(fp),
                                    "fn": int(fn), "tp": int(tp)}

    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"  {k:>10}: {v:.4f}")
    print("\n", classification_report(y_te, y_pred,
                                       target_names=["Normal", "MITM"]))

    print("\n=== SAVE ARTEFACTS ===")
    model.save(os.path.join(MODEL_DIR, "mitm_model.h5"))
    with open(os.path.join(MODEL_DIR, "history.json"), "w") as f:
        json.dump({k: [float(x) for x in v] for k, v in history.history.items()}, f, indent=2)
    np.savez(os.path.join(MODEL_DIR, "test_predictions.npz"),
              y_test=y_te.to_numpy(), y_prob=y_prob)
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    np.savez(os.path.join(MODEL_DIR, "test_features.npz"),
              X_test=X_te_s, y_test=y_te.to_numpy())
    print("  done.")


if __name__ == "__main__":
    main()
