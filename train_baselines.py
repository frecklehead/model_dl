"""
Train baseline classifiers on the same train/test split as the deep model.

Outputs:
    model/baseline_metrics.json   -- per-baseline accuracy/precision/recall/F1/AUC
    model/baseline_probs.npz      -- probability arrays for ROC overlay
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix,
)
import glob

SEED = 42
np.random.seed(SEED)

# Match preprocessing from train_model.py
import importlib.util
spec = importlib.util.spec_from_file_location("trainmod", "train_model.py")
trainmod = importlib.util.module_from_spec(spec); spec.loader.exec_module(trainmod)


def main():
    df = trainmod.load_data()
    df = trainmod.preprocess(df)
    selected = joblib.load("model/selected_features.pkl")
    df = df[selected + ["Label"]]

    X, y = df.drop(columns=["Label"]), df["Label"]
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30,
                                                 stratify=y, random_state=SEED)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=2/3,
                                                  stratify=y_tmp, random_state=SEED)

    scaler = joblib.load("model/scaler.pkl")
    X_tr_s = scaler.transform(X_tr)
    X_te_s = scaler.transform(X_te)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=400, n_jobs=-1,
                                                   random_state=SEED),
        "Decision Tree":       DecisionTreeClassifier(max_depth=15,
                                                       random_state=SEED),
        "Random Forest":       RandomForestClassifier(n_estimators=100,
                                                       n_jobs=-1,
                                                       random_state=SEED),
        "MLP":                 MLPClassifier(hidden_layer_sizes=(128, 64),
                                              max_iter=60, early_stopping=True,
                                              random_state=SEED),
    }

    out_metrics, out_probs = {}, {}
    for name, mdl in models.items():
        print(f"  fitting {name} ...")
        mdl.fit(X_tr_s, y_tr)
        prob = mdl.predict_proba(X_te_s)[:, 1]
        pred = (prob >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
        m = {
            "accuracy":  accuracy_score(y_te, pred),
            "precision": precision_score(y_te, pred),
            "recall":    recall_score(y_te, pred),
            "f1":        f1_score(y_te, pred),
            "auc":       roc_auc_score(y_te, prob),
            "fpr":       fp / (fp + tn) if (fp + tn) else 0.0,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp),
                                  "fn": int(fn), "tp": int(tp)},
        }
        for k, v in m.items():
            if isinstance(v, float):
                print(f"     {k:>9}: {v:.4f}")
        out_metrics[name] = m
        out_probs[name] = prob

    with open("model/baseline_metrics.json", "w") as f:
        json.dump(out_metrics, f, indent=2)
    np.savez("model/baseline_probs.npz", **out_probs)
    print("saved baselines -> model/baseline_metrics.json, baseline_probs.npz")


if __name__ == "__main__":
    main()
