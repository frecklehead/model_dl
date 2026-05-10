"""
MITM Attack Detection — Interactive Dashboard
===============================================
Launch:  streamlit run dashboard.py
"""

import os, glob
import numpy as np
import pandas as pd
import joblib
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import streamlit as st

# ── Page config ───────────────────────────────────────────
st.set_page_config(
    page_title="MITM Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS for a polished look ────────────────────────
st.markdown("""
<style>
    /* Hero metric cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #1e1e2f 0%, #2d2d44 100%);
        border: 1px solid #3a3a5c;
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 14px rgba(0,0,0,0.25);
    }
    div[data-testid="stMetric"] label {
        color: #a0a0c0 !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 2rem !important;
        font-weight: 700;
    }
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #0e1117;
    }
    /* Tab styling */
    button[data-baseweb="tab"] {
        font-size: 1rem !important;
        font-weight: 600 !important;
    }
</style>
""", unsafe_allow_html=True)

# ── Color palette ─────────────────────────────────────────
COLORS = {
    "primary": "#00d4aa",
    "danger":  "#ff4b6e",
    "warn":    "#ffb347",
    "info":    "#4fc3f7",
    "purple":  "#b388ff",
    "bg_dark": "#0e1117",
    "card":    "#1e1e2f",
}
MODEL_PALETTE = ['#00d4aa', '#ff4b6e', '#4fc3f7', '#ffb347', '#b388ff', '#ff8a65']


# ════════════════════════════════════════════════════════════
#                     DATA LOADING
# ════════════════════════════════════════════════════════════

@st.cache_data
def load_metrics():
    return joblib.load("model/model_summary.pkl")

@st.cache_data
def load_features():
    return joblib.load("model/selected_features.pkl")

@st.cache_data
def load_datasets():
    files = sorted(glob.glob("dataset/*.csv"))
    dfs = []
    meta = []
    for f in files:
        try:
            tmp = pd.read_csv(f, low_memory=False)
            dfs.append(tmp)
            meta.append({"file": os.path.basename(f), "rows": len(tmp)})
        except Exception:
            pass
    df = pd.concat(dfs, ignore_index=True)
    return df, meta

def encode(lbl):
    s = str(lbl).lower()
    return 0 if any(x in s for x in ['normal', 'benign', 'background', '0']) else 1

def feature_engineering(df):
    df = df.copy()
    num = df.select_dtypes(include=[np.number]).columns
    df[num] = df[num].fillna(0).replace([np.inf, -np.inf], 0)
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

@st.cache_data
def compute_predictions():
    """Load model, run inference, return all data needed for charts."""
    import tensorflow as tf
    tf.get_logger().setLevel('ERROR')

    df, meta = load_datasets()
    features = load_features()

    df['Label'] = df['Label'].apply(encode)
    df = feature_engineering(df)

    for col in ['application_name', 'requested_server_name']:
        if col in features and col in df.columns:
            df[col] = pd.factorize(df[col])[0]

    X = df.reindex(columns=features, fill_value=0).values
    y = df['Label'].values

    scaler = joblib.load("model/scaler.pkl")
    X_scaled = scaler.transform(X)
    X_cnn = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

    model = tf.keras.models.load_model("model/mitm_model.h5")
    y_prob = model.predict(X_cnn, batch_size=4096, verbose=0).flatten()
    y_pred = (y_prob >= 0.5).astype(int)

    return y, y_pred, y_prob, features, meta


# ════════════════════════════════════════════════════════════
#                     SIDEBAR
# ════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🛡️ MITM Detection")
    st.markdown("**CNN + LSTM Deep Learning**")
    st.markdown("Real-time Man-in-the-Middle attack detection using SDN flow features")
    st.markdown("---")
    st.markdown("#### Model Architecture")
    st.code("Conv1D(64) → Conv1D(128)\n→ LSTM(64) → Dense(64)\n→ Dense(1, sigmoid)", language="text")
    st.markdown("---")
    st.markdown("#### Attack Types Detected")
    st.markdown("""
    - **ARP Poisoning** — forged ARP replies
    - **SSL Stripping** — HTTPS downgrade
    - **Session Hijacking** — RST injection
    """)
    st.markdown("---")
    st.caption("Built with Streamlit + Plotly")


# ════════════════════════════════════════════════════════════
#                     HEADER
# ════════════════════════════════════════════════════════════

st.markdown("""
<div style="text-align:center; padding: 10px 0 5px 0;">
    <h1 style="margin-bottom:0; color:#00d4aa;">🛡️ MITM Attack Detection Dashboard</h1>
    <p style="color:#888; font-size:1.1rem; margin-top:5px;">
        CNN+LSTM Deep Learning Model — Performance Analysis & Evaluation
    </p>
</div>
""", unsafe_allow_html=True)

# ── Load data ─────────────────────────────────────────────
with st.spinner("Loading model and running inference..."):
    metrics = load_metrics()
    y_true, y_pred, y_prob, features, dataset_meta = compute_predictions()

from sklearn.metrics import (
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve, average_precision_score, roc_auc_score
)

cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()
fpr_arr, tpr_arr, _ = roc_curve(y_true, y_prob)
roc_auc = auc(fpr_arr, tpr_arr)
pr_precision, pr_recall, _ = precision_recall_curve(y_true, y_prob)
avg_prec = average_precision_score(y_true, y_prob)

# ════════════════════════════════════════════════════════════
#               HERO METRICS ROW
# ════════════════════════════════════════════════════════════

st.markdown("### Key Performance Metrics")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Accuracy",  f"{metrics['accuracy']*100:.2f}%")
c2.metric("Precision", f"{metrics['precision']*100:.2f}%")
c3.metric("Recall",    f"{metrics['recall']*100:.2f}%")
c4.metric("F1 Score",  f"{metrics['f1']*100:.2f}%")
c5.metric("ROC AUC",   f"{roc_auc:.4f}")

st.markdown("")

# ════════════════════════════════════════════════════════════
#               TABS
# ════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Confusion Matrix & ROC",
    "📈 Score Distribution",
    "🔬 Feature Analysis",
    "🗂️ Dataset Overview",
    "🏆 Model Summary",
])

# ── TAB 1: Confusion Matrix + ROC + PR ───────────────────
with tab1:
    col_a, col_b = st.columns(2)

    with col_a:
        # Confusion Matrix
        labels = ['Normal', 'MITM Attack']
        cm_text = [[f"TN<br><b>{tn:,}</b>", f"FP<br><b>{fp:,}</b>"],
                    [f"FN<br><b>{fn:,}</b>", f"TP<br><b>{tp:,}</b>"]]
        fig_cm = go.Figure(data=go.Heatmap(
            z=cm, x=labels, y=labels,
            colorscale=[[0, '#1a1a2e'], [0.5, '#16537e'], [1, '#00d4aa']],
            text=cm_text, texttemplate="%{text}",
            textfont=dict(size=16, color="white"),
            hovertemplate="Actual: %{y}<br>Predicted: %{x}<br>Count: %{z:,}<extra></extra>",
            showscale=False,
        ))
        fig_cm.update_layout(
            title=dict(text="Confusion Matrix", font=dict(size=18)),
            xaxis_title="Predicted Label",
            yaxis_title="Actual Label",
            yaxis=dict(autorange="reversed"),
            height=420,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_cm, use_container_width=True)

        # FPR callout
        fpr_val = fp / (fp + tn) * 100
        st.info(f"**False Positive Rate: {fpr_val:.4f}%** — Only {fp:,} false alarms out of {fp+tn:,} normal flows")

    with col_b:
        # ROC Curve
        fig_roc = go.Figure()
        fig_roc.add_trace(go.Scatter(
            x=fpr_arr, y=tpr_arr, mode='lines',
            name=f'CNN+LSTM (AUC = {roc_auc:.4f})',
            line=dict(color=COLORS["primary"], width=3),
            fill='tozeroy', fillcolor='rgba(0,212,170,0.1)',
        ))
        fig_roc.add_trace(go.Scatter(
            x=[0, 1], y=[0, 1], mode='lines',
            name='Random Baseline',
            line=dict(color='gray', width=1, dash='dash'),
        ))
        fig_roc.update_layout(
            title=dict(text="ROC Curve", font=dict(size=18)),
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate",
            height=420,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(x=0.55, y=0.05),
        )
        st.plotly_chart(fig_roc, use_container_width=True)

    # Precision-Recall Curve (full width)
    fig_pr = go.Figure()
    fig_pr.add_trace(go.Scatter(
        x=pr_recall, y=pr_precision, mode='lines',
        name=f'CNN+LSTM (AP = {avg_prec:.4f})',
        line=dict(color=COLORS["info"], width=3),
        fill='tozeroy', fillcolor='rgba(79,195,247,0.1)',
    ))
    baseline_pr = y_true.mean()
    fig_pr.add_trace(go.Scatter(
        x=[0, 1], y=[baseline_pr, baseline_pr], mode='lines',
        name=f'Baseline (AP = {baseline_pr:.4f})',
        line=dict(color='gray', width=1, dash='dash'),
    ))
    fig_pr.update_layout(
        title=dict(text="Precision-Recall Curve", font=dict(size=18)),
        xaxis_title="Recall",
        yaxis_title="Precision",
        height=350,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(x=0.02, y=0.05),
    )
    st.plotly_chart(fig_pr, use_container_width=True)


# ── TAB 2: Score Distribution ────────────────────────────
with tab2:
    col1, col2 = st.columns(2)

    with col1:
        # Histogram
        fig_hist = go.Figure()
        fig_hist.add_trace(go.Histogram(
            x=y_prob[y_true == 0], nbinsx=80, name="Normal",
            marker_color=COLORS["primary"], opacity=0.7,
        ))
        fig_hist.add_trace(go.Histogram(
            x=y_prob[y_true == 1], nbinsx=80, name="MITM Attack",
            marker_color=COLORS["danger"], opacity=0.7,
        ))
        fig_hist.add_vline(x=0.5, line_dash="dash", line_color="white",
                           annotation_text="Threshold = 0.5", annotation_font_color="white")
        fig_hist.update_layout(
            title="Prediction Score Distribution",
            xaxis_title="Model Confidence Score",
            yaxis_title="Count",
            yaxis_type="log",
            barmode="overlay",
            height=420,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    with col2:
        # Threshold analysis
        thresholds = np.arange(0.1, 0.95, 0.01)
        prec_t, rec_t, f1_t = [], [], []
        for t in thresholds:
            pred_t = (y_prob >= t).astype(int)
            tp_t = ((pred_t == 1) & (y_true == 1)).sum()
            fp_t = ((pred_t == 1) & (y_true == 0)).sum()
            fn_t = ((pred_t == 0) & (y_true == 1)).sum()
            p = tp_t / (tp_t + fp_t + 1e-9)
            r = tp_t / (tp_t + fn_t + 1e-9)
            prec_t.append(p)
            rec_t.append(r)
            f1_t.append(2 * p * r / (p + r + 1e-9))

        fig_thresh = go.Figure()
        fig_thresh.add_trace(go.Scatter(x=thresholds, y=prec_t, name="Precision",
                                         line=dict(color=COLORS["primary"], width=2)))
        fig_thresh.add_trace(go.Scatter(x=thresholds, y=rec_t, name="Recall",
                                         line=dict(color=COLORS["danger"], width=2)))
        fig_thresh.add_trace(go.Scatter(x=thresholds, y=f1_t, name="F1 Score",
                                         line=dict(color=COLORS["warn"], width=3)))
        fig_thresh.add_vline(x=0.5, line_dash="dash", line_color="white",
                              annotation_text="Current: 0.5")
        best_t = thresholds[np.argmax(f1_t)]
        fig_thresh.add_vline(x=best_t, line_dash="dot", line_color=COLORS["warn"],
                              annotation_text=f"Best F1: {best_t:.2f}")
        fig_thresh.update_layout(
            title="Threshold Sensitivity Analysis",
            xaxis_title="Decision Threshold",
            yaxis_title="Score",
            height=420,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_thresh, use_container_width=True)

    # Correct vs incorrect breakdown
    correct = (y_pred == y_true).sum()
    incorrect = (y_pred != y_true).sum()
    fig_pie = make_subplots(rows=1, cols=2, specs=[[{"type": "pie"}, {"type": "pie"}]],
                             subplot_titles=["Prediction Accuracy", "Error Breakdown"])
    fig_pie.add_trace(go.Pie(
        labels=["Correct", "Incorrect"],
        values=[correct, incorrect],
        marker=dict(colors=[COLORS["primary"], COLORS["danger"]]),
        hole=0.5,
        textinfo="percent+value",
        textfont=dict(size=14),
    ), row=1, col=1)
    fig_pie.add_trace(go.Pie(
        labels=["True Neg (TN)", "True Pos (TP)", "False Pos (FP)", "False Neg (FN)"],
        values=[tn, tp, fp, fn],
        marker=dict(colors=[COLORS["primary"], COLORS["info"], COLORS["warn"], COLORS["danger"]]),
        hole=0.5,
        textinfo="percent+label",
        textfont=dict(size=12),
    ), row=1, col=2)
    fig_pie.update_layout(
        height=380,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig_pie, use_container_width=True)


# ── TAB 3: Feature Analysis ──────────────────────────────
with tab3:
    st.markdown("#### Top 25 Selected Features (RF-RFE)")
    st.caption("Features selected via Recursive Feature Elimination with Random Forest")

    # Load dataset to compute feature importance on-the-fly
    @st.cache_data
    def compute_feature_importance():
        from sklearn.ensemble import RandomForestClassifier
        df, _ = load_datasets()
        feats = load_features()
        df['Label'] = df['Label'].apply(encode)
        df = feature_engineering(df)
        for col in ['application_name', 'requested_server_name']:
            if col in feats and col in df.columns:
                df[col] = pd.factorize(df[col])[0]
        X = df.reindex(columns=feats, fill_value=0).values
        y = df['Label'].values
        # Sample for speed
        n = min(30000, len(X))
        idx = np.random.choice(len(X), n, replace=False)
        rf = RandomForestClassifier(n_estimators=50, max_depth=10, n_jobs=-1, random_state=42)
        rf.fit(X[idx], y[idx])
        return dict(zip(feats, rf.feature_importances_))

    with st.spinner("Computing feature importance..."):
        imp = compute_feature_importance()

    sorted_feats = sorted(imp.items(), key=lambda x: x[1], reverse=True)
    names = [f[0] for f in sorted_feats]
    vals  = [f[1] for f in sorted_feats]

    fig_feat = go.Figure(go.Bar(
        x=vals, y=names, orientation='h',
        marker=dict(
            color=vals,
            colorscale=[[0, '#1a1a2e'], [0.3, '#16537e'], [0.6, '#00b4d8'], [1, '#00d4aa']],
        ),
        text=[f"{v:.4f}" for v in vals],
        textposition="outside",
        textfont=dict(size=11),
    ))
    fig_feat.update_layout(
        title="Feature Importance Ranking",
        xaxis_title="Importance Score",
        yaxis=dict(autorange="reversed"),
        height=max(500, len(names) * 26),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=200),
    )
    st.plotly_chart(fig_feat, use_container_width=True)

    # Feature correlation heatmap for top 10
    @st.cache_data
    def compute_correlation():
        df, _ = load_datasets()
        feats = load_features()
        df = feature_engineering(df)
        for col in ['application_name', 'requested_server_name']:
            if col in feats and col in df.columns:
                df[col] = pd.factorize(df[col])[0]
        top10 = [f[0] for f in sorted_feats[:10]]
        return df[top10].corr()

    with st.spinner("Computing correlations..."):
        corr = compute_correlation()

    fig_corr = go.Figure(go.Heatmap(
        z=corr.values, x=corr.columns, y=corr.columns,
        colorscale="RdBu_r", zmid=0,
        text=np.round(corr.values, 2),
        texttemplate="%{text}",
        textfont=dict(size=10),
    ))
    fig_corr.update_layout(
        title="Top 10 Feature Correlation Matrix",
        height=500,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig_corr, use_container_width=True)


# ── TAB 4: Dataset Overview ──────────────────────────────
with tab4:
    col_d1, col_d2 = st.columns(2)

    with col_d1:
        st.markdown("#### Dataset Sources")
        df_meta = pd.DataFrame(dataset_meta)
        df_meta.columns = ["Dataset File", "Records"]
        df_meta["Records"] = df_meta["Records"].apply(lambda x: f"{x:,}")
        st.dataframe(df_meta, use_container_width=True, hide_index=True)

        total = sum(d["rows"] for d in dataset_meta)
        st.success(f"**Total Records: {total:,}** across {len(dataset_meta)} datasets")

    with col_d2:
        # Dataset size pie
        fig_ds = go.Figure(go.Pie(
            labels=[d["file"].replace(".csv", "") for d in dataset_meta],
            values=[d["rows"] for d in dataset_meta],
            hole=0.45,
            marker=dict(colors=MODEL_PALETTE[:len(dataset_meta)]),
            textinfo="percent+label",
            textfont=dict(size=11),
        ))
        fig_ds.update_layout(
            title="Records per Dataset",
            height=400,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_ds, use_container_width=True)

    # Class distribution
    normal = (y_true == 0).sum()
    attack = (y_true == 1).sum()
    fig_class = go.Figure()
    fig_class.add_trace(go.Bar(
        x=["Normal Traffic", "MITM Attack"],
        y=[normal, attack],
        marker_color=[COLORS["primary"], COLORS["danger"]],
        text=[f"{normal:,}", f"{attack:,}"],
        textposition="outside",
        textfont=dict(size=16, color="white"),
        width=0.5,
    ))
    fig_class.update_layout(
        title="Class Distribution (After Label Encoding)",
        yaxis_title="Number of Samples",
        height=350,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig_class, use_container_width=True)


# ── TAB 5: Model Summary ─────────────────────────────────
with tab5:
    col_s1, col_s2 = st.columns([1, 1])

    with col_s1:
        st.markdown("#### CNN+LSTM Architecture")
        arch_data = [
            ["1", "Conv1D", "64 filters, kernel=3, ReLU, padding=same"],
            ["",  "BatchNorm + MaxPool(2) + Dropout(0.2)", ""],
            ["2", "Conv1D", "128 filters, kernel=3, ReLU, padding=same"],
            ["",  "BatchNorm + MaxPool(2) + Dropout(0.2)", ""],
            ["3", "LSTM", "64 units + Dropout(0.3)"],
            ["4", "Dense", "64 units, ReLU + BatchNorm + Dropout(0.2)"],
            ["5", "Dense (Output)", "1 unit, Sigmoid"],
        ]
        st.dataframe(
            pd.DataFrame(arch_data, columns=["Layer", "Type", "Config"]),
            use_container_width=True, hide_index=True,
        )

        st.markdown("#### Training Configuration")
        st.markdown(f"""
        | Parameter | Value |
        |-----------|-------|
        | Optimizer | Adam (lr=0.001) |
        | Loss | Binary Crossentropy |
        | Epochs | 20 (EarlyStopping) |
        | Batch Size | 256 |
        | Features | 25 (RF-RFE selected) |
        | Balancing | SMOTE |
        | Split | 70% Train / 10% Val / 20% Test |
        """)

    with col_s2:
        # Radar chart
        categories = ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'AUC']
        values = [metrics['accuracy'], metrics['precision'], metrics['recall'],
                  metrics['f1'], roc_auc]
        values_plot = values + [values[0]]  # close the polygon
        cats_plot = categories + [categories[0]]

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=values_plot, theta=cats_plot,
            fill='toself',
            fillcolor='rgba(0,212,170,0.2)',
            line=dict(color=COLORS["primary"], width=3),
            name='CNN+LSTM',
        ))
        # Add reference circle at 0.9
        ref = [0.9] * (len(categories) + 1)
        fig_radar.add_trace(go.Scatterpolar(
            r=ref, theta=cats_plot,
            line=dict(color='gray', width=1, dash='dash'),
            name='90% Reference',
        ))
        fig_radar.update_layout(
            title="Performance Radar",
            polar=dict(
                radialaxis=dict(visible=True, range=[0.8, 1.0]),
                bgcolor="rgba(0,0,0,0)",
            ),
            height=450,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    # Final summary metrics table
    st.markdown("---")
    st.markdown("#### Detailed Classification Report")
    report = classification_report(y_true, y_pred, target_names=['Normal', 'MITM Attack'], output_dict=True)
    report_df = pd.DataFrame(report).transpose()
    report_df = report_df.round(4)
    if 'support' in report_df.columns:
        report_df['support'] = report_df['support'].astype(int)
    st.dataframe(report_df, use_container_width=True)


# ── Footer ────────────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style="text-align:center; color:#555; font-size:0.85rem; padding-bottom:20px;">
    MITM Attack Detection System — CNN+LSTM Deep Learning Model<br>
    25 Features | 5 Datasets | Real-time SDN Detection
</div>
""", unsafe_allow_html=True)
