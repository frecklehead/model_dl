"""
Generate all evaluation plots for the CNN-BiLSTM-Attention MITM detector.

Reads from model/ (history.json, metrics.json, test_predictions.npz,
selected_features.pkl, feature_importances.pkl, test_features.npz) and
writes a clean numbered set of figures into plots/.

Run after train_model.py and (optionally) train_baselines.py.
"""

import os
import json
import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, roc_curve, auc as sk_auc,
    precision_recall_curve, average_precision_score,
    precision_score, recall_score, f1_score,
)

MODEL_DIR = "model"
PLOTS_DIR = "plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

plt.rcParams.update({
    "figure.dpi": 110,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "font.size": 11,
})


def load_all():
    with open(os.path.join(MODEL_DIR, "history.json")) as f:
        history = json.load(f)
    with open(os.path.join(MODEL_DIR, "metrics.json")) as f:
        metrics = json.load(f)
    preds = np.load(os.path.join(MODEL_DIR, "test_predictions.npz"))
    y_test, y_prob = preds["y_test"], preds["y_prob"]
    selected = joblib.load(os.path.join(MODEL_DIR, "selected_features.pkl"))
    importances = joblib.load(os.path.join(MODEL_DIR, "feature_importances.pkl"))
    return history, metrics, y_test, y_prob, selected, importances


# ---------------------------------------------------------------------------
# 01  label distribution
# ---------------------------------------------------------------------------
def plot_label_distribution(y_test):
    fig, ax = plt.subplots(figsize=(6, 4))
    counts = np.bincount(y_test.astype(int))
    bars = ax.bar(["Normal", "MITM"], counts,
                  color=["#3b82f6", "#dc2626"], edgecolor="black")
    for b, c in zip(bars, counts):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + max(counts) * 0.01,
                f"{c:,}", ha="center", fontsize=11, fontweight="bold")
    ax.set_ylabel("Number of flows")
    ax.set_title("Test-set class distribution")
    fig.savefig(os.path.join(PLOTS_DIR, "01_label_distribution.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 02  feature importance
# ---------------------------------------------------------------------------
def plot_feature_importance(importances):
    items = sorted(importances.items(), key=lambda kv: kv[1])
    names = [k for k, _ in items]
    vals  = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.barh(range(len(names)), vals, color="#0ea5e9", edgecolor="black")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel("Importance (Random Forest gain)")
    ax.set_title("RF-RFE selected features (ranked)")
    fig.savefig(os.path.join(PLOTS_DIR, "02_feature_importance.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 03  training history (loss + accuracy + AUC)
# ---------------------------------------------------------------------------
def plot_training_history(history):
    epochs = range(1, len(history["loss"]) + 1)
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5))

    axes[0].plot(epochs, history["loss"], "-o", label="train", color="#1f77b4")
    axes[0].plot(epochs, history["val_loss"], "-s", label="val", color="#d62728")
    axes[0].set_title("Loss");      axes[0].set_xlabel("Epoch"); axes[0].set_ylabel("BCE loss")
    axes[0].legend(); axes[0].grid(alpha=.3)

    axes[1].plot(epochs, history["accuracy"], "-o", label="train", color="#1f77b4")
    axes[1].plot(epochs, history["val_accuracy"], "-s", label="val", color="#d62728")
    axes[1].set_title("Accuracy");  axes[1].set_xlabel("Epoch"); axes[1].set_ylabel("Accuracy")
    axes[1].legend(); axes[1].grid(alpha=.3)

    axes[2].plot(epochs, history["auc"], "-o", label="train", color="#1f77b4")
    axes[2].plot(epochs, history["val_auc"], "-s", label="val", color="#d62728")
    axes[2].set_title("ROC-AUC");   axes[2].set_xlabel("Epoch"); axes[2].set_ylabel("AUC")
    axes[2].legend(); axes[2].grid(alpha=.3)

    fig.suptitle("CNN-BiLSTM-Attention — Training history", fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(PLOTS_DIR, "03_training_history.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 04  confusion matrix (raw + normalised)
# ---------------------------------------------------------------------------
def plot_confusion_matrix(y_test, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_test, y_pred)
    cmn = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal", "MITM"], yticklabels=["Normal", "MITM"],
                ax=axes[0], cbar=False)
    axes[0].set_title("Confusion matrix (counts)")
    axes[0].set_xlabel("Predicted"); axes[0].set_ylabel("True")

    sns.heatmap(cmn, annot=True, fmt=".3f", cmap="Blues", vmin=0, vmax=1,
                xticklabels=["Normal", "MITM"], yticklabels=["Normal", "MITM"],
                ax=axes[1], cbar=False)
    axes[1].set_title("Confusion matrix (row-normalised)")
    axes[1].set_xlabel("Predicted"); axes[1].set_ylabel("True")

    fig.tight_layout()
    fig.savefig(os.path.join(PLOTS_DIR, "04_confusion_matrix.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 05  ROC curve
# ---------------------------------------------------------------------------
def plot_roc(y_test, y_prob):
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    a = sk_auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, color="#d62728", lw=2.2,
            label=f"CNN-BiLSTM-Attn (AUC = {a:.4f})")
    ax.plot([0, 1], [0, 1], "--", color="grey", lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Receiver Operating Characteristic")
    ax.legend(loc="lower right"); ax.grid(alpha=.3)
    fig.savefig(os.path.join(PLOTS_DIR, "05_roc_curve.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 06  Precision-Recall curve
# ---------------------------------------------------------------------------
def plot_pr(y_test, y_prob):
    p, r, _ = precision_recall_curve(y_test, y_prob)
    ap = average_precision_score(y_test, y_prob)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(r, p, color="#2563eb", lw=2.2,
            label=f"CNN-BiLSTM-Attn (AP = {ap:.4f})")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall curve")
    ax.legend(loc="lower left"); ax.grid(alpha=.3)
    fig.savefig(os.path.join(PLOTS_DIR, "06_pr_curve.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 07  Score distribution
# ---------------------------------------------------------------------------
def plot_score_distribution(y_test, y_prob):
    benign = y_prob[y_test == 0]
    attack = y_prob[y_test == 1]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    axes[0].hist(benign, bins=50, alpha=.7, color="#3b82f6", label="Normal")
    axes[0].hist(attack, bins=50, alpha=.7, color="#dc2626", label="MITM")
    axes[0].axvline(0.5, ls="--", color="black", label="threshold = 0.5")
    axes[0].set_title("Score distribution (linear)")
    axes[0].set_xlabel("Predicted score"); axes[0].set_ylabel("Count")
    axes[0].legend()

    axes[1].hist(benign, bins=50, alpha=.7, color="#3b82f6", label="Normal")
    axes[1].hist(attack, bins=50, alpha=.7, color="#dc2626", label="MITM")
    axes[1].axvline(0.5, ls="--", color="black", label="threshold = 0.5")
    axes[1].set_yscale("log")
    axes[1].set_title("Score distribution (log scale)")
    axes[1].set_xlabel("Predicted score"); axes[1].set_ylabel("Count (log)")
    axes[1].legend()

    fig.tight_layout()
    fig.savefig(os.path.join(PLOTS_DIR, "07_score_distribution.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 08  Threshold sensitivity
# ---------------------------------------------------------------------------
def plot_threshold_sensitivity(y_test, y_prob):
    thresholds = np.linspace(0.05, 0.95, 19)
    P, R, F, FPR = [], [], [], []
    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        P.append(precision_score(y_test, y_pred, zero_division=0))
        R.append(recall_score(y_test, y_pred, zero_division=0))
        F.append(f1_score(y_test, y_pred, zero_division=0))
        tn, fp, _, _ = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
        FPR.append(fp / (fp + tn) if (fp + tn) else 0)

    fig, ax = plt.subplots(figsize=(8.5, 5))
    ax.plot(thresholds, P, "-o", label="Precision", color="#2563eb")
    ax.plot(thresholds, R, "-s", label="Recall",    color="#16a34a")
    ax.plot(thresholds, F, "-^", label="F1",        color="#dc2626")
    ax.plot(thresholds, FPR, "-d", label="FPR",     color="#9333ea")
    ax.axvline(0.5, ls="--", color="black", alpha=.6, label="operating point")
    ax.set_xlabel("Decision threshold"); ax.set_ylabel("Metric value")
    ax.set_title("Threshold sensitivity")
    ax.legend(); ax.grid(alpha=.3)
    fig.savefig(os.path.join(PLOTS_DIR, "08_threshold_sensitivity.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 09  Metrics summary bar chart
# ---------------------------------------------------------------------------
def plot_metrics_summary(metrics):
    keys = ["accuracy", "precision", "recall", "f1", "auc"]
    vals = [metrics[k] for k in keys]
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    bars = ax.bar([k.upper() for k in keys], vals,
                  color=["#1f77b4", "#2563eb", "#16a34a", "#dc2626", "#9333ea"],
                  edgecolor="black")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.005, f"{v:.4f}",
                ha="center", fontweight="bold", fontsize=10)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("CNN-BiLSTM-Attention — Test-set metrics")
    fig.savefig(os.path.join(PLOTS_DIR, "09_metrics_summary.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 10  Baseline comparison (if available)
# ---------------------------------------------------------------------------
def plot_baseline_comparison():
    path = os.path.join(MODEL_DIR, "baseline_metrics.json")
    if not os.path.exists(path):
        print("  (skipping 10_baseline_comparison — no baseline_metrics.json)")
        return
    with open(path) as f:
        baselines = json.load(f)
    with open(os.path.join(MODEL_DIR, "metrics.json")) as f:
        ours = json.load(f)
    baselines["CNN-BiLSTM-Attn (ours)"] = ours

    keys = ["accuracy", "precision", "recall", "f1", "auc"]
    names = list(baselines.keys())
    matrix = np.array([[baselines[m][k] for k in keys] for m in names])

    fig, ax = plt.subplots(figsize=(11, 5.5))
    x = np.arange(len(names))
    w = 0.16
    palette = ["#1f77b4", "#2563eb", "#16a34a", "#dc2626", "#9333ea"]
    for i, k in enumerate(keys):
        ax.bar(x + (i - 2) * w, matrix[:, i], w, label=k.upper(),
               color=palette[i], edgecolor="black")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=12, ha="right")
    ax.set_ylim(0, 1.05); ax.set_ylabel("Score")
    ax.set_title("Comparison with baseline classifiers (same 25 features)")
    ax.legend(ncol=5, fontsize=9); ax.grid(axis="y", alpha=.3)
    fig.savefig(os.path.join(PLOTS_DIR, "10_baseline_comparison.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# 11  ROC overlay across models (if available)
# ---------------------------------------------------------------------------
def plot_roc_overlay(y_test, y_prob):
    path = os.path.join(MODEL_DIR, "baseline_probs.npz")
    if not os.path.exists(path):
        print("  (skipping 11_roc_overlay — no baseline_probs.npz)")
        return
    probs = dict(np.load(path))
    fig, ax = plt.subplots(figsize=(7, 5.5))
    palette = plt.cm.tab10.colors
    for i, (name, p) in enumerate(probs.items()):
        fpr, tpr, _ = roc_curve(y_test, p)
        a = sk_auc(fpr, tpr)
        ax.plot(fpr, tpr, lw=1.7, color=palette[i % 10],
                label=f"{name} (AUC={a:.4f})")
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    a = sk_auc(fpr, tpr)
    ax.plot(fpr, tpr, lw=2.5, color="#dc2626",
            label=f"CNN-BiLSTM-Attn (AUC={a:.4f})")
    ax.plot([0, 1], [0, 1], "--", color="grey")
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC curves — all models")
    ax.legend(loc="lower right", fontsize=9); ax.grid(alpha=.3)
    fig.savefig(os.path.join(PLOTS_DIR, "11_roc_overlay.png"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    history, metrics, y_test, y_prob, selected, importances = load_all()
    print(f"loaded test_predictions: {len(y_test)} samples")
    print(f"final test metrics: {json.dumps({k: round(v, 4) for k,v in metrics.items() if isinstance(v, float)})}")

    plot_label_distribution(y_test);    print("  wrote 01_label_distribution.png")
    plot_feature_importance(importances); print("  wrote 02_feature_importance.png")
    plot_training_history(history);     print("  wrote 03_training_history.png")
    plot_confusion_matrix(y_test, y_prob); print("  wrote 04_confusion_matrix.png")
    plot_roc(y_test, y_prob);           print("  wrote 05_roc_curve.png")
    plot_pr(y_test, y_prob);            print("  wrote 06_pr_curve.png")
    plot_score_distribution(y_test, y_prob); print("  wrote 07_score_distribution.png")
    plot_threshold_sensitivity(y_test, y_prob); print("  wrote 08_threshold_sensitivity.png")
    plot_metrics_summary(metrics);      print("  wrote 09_metrics_summary.png")
    plot_baseline_comparison()
    plot_roc_overlay(y_test, y_prob)
    print("done.")


if __name__ == "__main__":
    main()
