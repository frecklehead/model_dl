"""
Live MITM Attack Detection Dashboard
=====================================
Monitors the SDN controller output in real-time via /tmp/mitm_status.json
and /tmp/mitm_alerts.json written by my_controller.py.

Usage:
  Terminal 1:  ryu-manager my_controller.py
  Terminal 2:  sudo python3 run_demo.py
  Terminal 3:  streamlit run live_dashboard.py

The dashboard auto-refreshes every 2 seconds to show live detections.
"""

import json, os, time
import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

# ── Page config ───────────────────────────────────────────
st.set_page_config(
    page_title="MITM Live Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom styling ────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.4);
    }
    div[data-testid="stMetric"] label {
        color: #8b949e !important;
        font-size: 0.8rem !important;
        text-transform: uppercase;
        letter-spacing: 1.5px;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 2rem !important;
        font-weight: 700;
    }

    /* Alert card styling */
    .alert-card {
        background: linear-gradient(135deg, #2d1117 0%, #3d1a1a 100%);
        border: 1px solid #f8514966;
        border-left: 4px solid #f85149;
        border-radius: 8px;
        padding: 14px 18px;
        margin: 8px 0;
        font-family: 'JetBrains Mono', monospace;
    }
    .alert-card .alert-type {
        color: #f85149;
        font-weight: 700;
        font-size: 1rem;
    }
    .alert-card .alert-detail {
        color: #c9d1d9;
        font-size: 0.85rem;
        margin-top: 4px;
    }
    .alert-card .alert-meta {
        color: #8b949e;
        font-size: 0.75rem;
        margin-top: 6px;
    }

    /* Safe card */
    .safe-card {
        background: linear-gradient(135deg, #0d2818 0%, #132d1a 100%);
        border: 1px solid #3fb95066;
        border-left: 4px solid #3fb950;
        border-radius: 8px;
        padding: 18px 22px;
        margin: 8px 0;
        text-align: center;
    }
    .safe-card .safe-text {
        color: #3fb950;
        font-size: 1.3rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Blocked IP badge */
    .blocked-badge {
        display: inline-block;
        background: #f8514922;
        border: 1px solid #f85149;
        color: #f85149;
        padding: 4px 12px;
        border-radius: 20px;
        margin: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        font-weight: 600;
    }

    /* Status indicator */
    .status-dot {
        display: inline-block;
        width: 10px; height: 10px;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse 2s infinite;
    }
    .status-dot.live { background: #3fb950; }
    .status-dot.offline { background: #f85149; }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
    }

    section[data-testid="stSidebar"] { background: #0d1117; }
</style>
""", unsafe_allow_html=True)

COLORS = {
    "green":  "#3fb950",
    "red":    "#f85149",
    "yellow": "#d29922",
    "blue":   "#58a6ff",
    "purple": "#bc8cff",
    "cyan":   "#39d2c0",
    "gray":   "#8b949e",
}

ATTACK_COLORS = {
    "ARP POISONING":     "#f85149",
    "SSL STRIPPING":     "#d29922",
    "SESSION HIJACKING": "#bc8cff",
}

ATTACK_ICONS = {
    "ARP POISONING":     "🔴",
    "SSL STRIPPING":     "🟡",
    "SESSION HIJACKING": "🟣",
}

ATTACK_DESC = {
    "ARP POISONING":     "Forged ARP replies redirect victim traffic through attacker",
    "SSL STRIPPING":     "HTTPS downgraded to HTTP — credentials exposed in plaintext",
    "SESSION HIJACKING": "RST injection terminates legitimate session, attacker takes over",
}


# ── Load live data ────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = os.path.join(BASE_DIR, "mitm_status.json")
ALERTS_FILE = os.path.join(BASE_DIR, "mitm_alerts.json")

def load_status():
    """Read controller status from mitm_status.json (written by controller via /app volume)"""
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return None

def load_alerts():
    """Read alert log from mitm_alerts.json"""
    try:
        with open(ALERTS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


# ── Sidebar ───────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Live Detection")
    st.markdown("**SDN Controller Monitor**")
    st.markdown("---")

    refresh = st.slider("Refresh interval (sec)", 1, 10, 2)

    st.markdown("---")
    st.markdown("#### Detection Methods")
    st.markdown("""
    **ML Model** — CNN+LSTM
    scores each flow (threshold 0.5)

    **Rule-Based** — ARP conflict,
    SSL downgrade, RST spoof
    """)
    st.markdown("---")
    st.markdown("#### How to Run")
    st.code("# Terminal 1\nryu-manager my_controller.py\n\n# Terminal 2\nsudo python3 run_demo.py\n\n# Terminal 3\nstreamlit run live_dashboard.py", language="bash")
    st.markdown("---")

    if st.button("Clear Alert Log"):
        try:
            open(ALERTS_FILE, "w").write("[]")
            open(STATUS_FILE, "w").write("{}")
            st.success("Cleared!")
        except Exception:
            st.error("Could not clear logs")


# ── Auto-refresh ──────────────────────────────────────────
st_autorefresh = st.empty()

status = load_status()
alerts = load_alerts()
is_live = status is not None and "timestamp" in (status or {})

# ════════════════════════════════════════════════════════════
#                     HEADER
# ════════════════════════════════════════════════════════════

if is_live:
    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:12px; padding:10px 0;">
        <span class="status-dot live"></span>
        <h1 style="margin:0; color:#c9d1d9;">MITM Attack Detection — Live Monitor</h1>
        <span style="color:#8b949e; font-size:0.9rem; margin-left:auto;">
            Last update: {status.get('timestamp', '—')}
        </span>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:12px; padding:10px 0;">
        <span class="status-dot offline"></span>
        <h1 style="margin:0; color:#c9d1d9;">MITM Attack Detection — Live Monitor</h1>
        <span style="color:#f85149; font-size:0.9rem; margin-left:auto;">
            Controller not running — start ryu-manager my_controller.py
        </span>
    </div>
    """, unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════
#               STATUS METRICS
# ════════════════════════════════════════════════════════════

if is_live:
    attack_counts = status.get("attack_counts", {})
    total_attacks = sum(attack_counts.values())
    blocked = status.get("blocked_ips", [])

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Active Flows", status.get("active_flows", 0))
    c2.metric("Switches", status.get("switches", 0))
    c3.metric("ARP Table", status.get("arp_entries", 0))
    c4.metric("Total Attacks", total_attacks)
    c5.metric("Blocked IPs", len(blocked))

st.markdown("")

# ════════════════════════════════════════════════════════════
#               MAIN CONTENT
# ════════════════════════════════════════════════════════════

tab_live, tab_alerts, tab_flows, tab_analysis = st.tabs([
    "🔴 Live Detection",
    "📋 Alert Log",
    "🌐 Network Flows",
    "📊 Attack Analysis",
])


# ── TAB 1: Live Detection ────────────────────────────────
with tab_live:
    if not is_live and not alerts:
        st.markdown("""
        <div class="safe-card">
            <div class="safe-text">Waiting for Controller...</div>
            <p style="color:#8b949e; margin-top:8px;">
                Start the SDN controller and run the demo to see live detections
            </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Attack type summary cards
        col_arp, col_ssl, col_sess = st.columns(3)

        for col, atype in [(col_arp, "ARP POISONING"), (col_ssl, "SSL STRIPPING"), (col_sess, "SESSION HIJACKING")]:
            count = (status or {}).get("attack_counts", {}).get(atype, 0)
            color = ATTACK_COLORS[atype]
            icon = ATTACK_ICONS[atype]
            with col:
                if count > 0:
                    st.markdown(f"""
                    <div style="background:linear-gradient(135deg, {color}15, {color}08);
                                border:1px solid {color}66; border-radius:12px;
                                padding:20px; text-align:center;">
                        <div style="font-size:2.5rem;">{icon}</div>
                        <div style="color:{color}; font-size:1.1rem; font-weight:700;
                                    margin:8px 0;">{atype}</div>
                        <div style="color:white; font-size:2.2rem; font-weight:700;">{count}</div>
                        <div style="color:#8b949e; font-size:0.8rem; margin-top:4px;">
                            DETECTED
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style="background:#161b22; border:1px solid #30363d;
                                border-radius:12px; padding:20px; text-align:center;">
                        <div style="font-size:2.5rem; opacity:0.3;">{icon}</div>
                        <div style="color:#8b949e; font-size:1rem; font-weight:600;
                                    margin:8px 0;">{atype}</div>
                        <div style="color:#30363d; font-size:2.2rem; font-weight:700;">0</div>
                        <div style="color:#30363d; font-size:0.8rem; margin-top:4px;">
                            NO DETECTION
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Recent detections timeline
        detections = (status or {}).get("detections", []) or alerts
        if detections:
            st.markdown("#### Recent Detections")
            for det in reversed(detections[-10:]):
                atype = det.get("type") or det.get("attack_type", "UNKNOWN")
                color = ATTACK_COLORS.get(atype, "#8b949e")
                icon  = ATTACK_ICONS.get(atype, "⚪")
                desc  = ATTACK_DESC.get(atype, "")
                method = det.get("method", "")
                ip     = det.get("ip", "")
                mac    = det.get("mac", "")
                ts     = det.get("time") or det.get("timestamp", "")
                detail = det.get("detail", "")
                how    = det.get("how", "")

                st.markdown(f"""
                <div class="alert-card" style="border-left-color:{color}; border-color:{color}66;
                     background:linear-gradient(135deg, {color}08, {color}04);">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span class="alert-type" style="color:{color};">
                            {icon} {atype}
                        </span>
                        <span style="color:#8b949e; font-size:0.8rem;">{ts}</span>
                    </div>
                    <div class="alert-detail">{desc}</div>
                    <div class="alert-meta">
                        Method: <b>{method}</b> &nbsp;|&nbsp;
                        IP: <b>{ip}</b> &nbsp;|&nbsp;
                        MAC: <b>{mac}</b>
                    </div>
                    <div style="color:#6e7681; font-size:0.75rem; margin-top:4px;">
                        {how or detail}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="safe-card">
                <div class="safe-text">Network Secure — No Attacks Detected</div>
            </div>
            """, unsafe_allow_html=True)

        # Blocked IPs section
        blocked = (status or {}).get("blocked_ips", [])
        if blocked:
            st.markdown("#### Blocked IPs")
            badges = " ".join(f'<span class="blocked-badge">{ip}</span>' for ip in blocked)
            st.markdown(f"<div>{badges}</div>", unsafe_allow_html=True)


# ── TAB 2: Alert Log ─────────────────────────────────────
with tab_alerts:
    if alerts:
        st.markdown("#### Full Alert History")
        df_alerts = pd.DataFrame(alerts)
        # Rename columns for display
        rename_map = {}
        if "attack_type" in df_alerts.columns:
            rename_map["attack_type"] = "Attack Type"
        if "type" in df_alerts.columns:
            rename_map["type"] = "Attack Type"
        if "timestamp" in df_alerts.columns:
            rename_map["timestamp"] = "Time"
        if "time" in df_alerts.columns:
            rename_map["time"] = "Time"
        rename_map.update({"method": "Method", "ip": "IP", "mac": "MAC",
                           "detail": "Detail", "how": "How"})
        df_alerts = df_alerts.rename(columns=rename_map)

        st.dataframe(df_alerts, use_container_width=True, hide_index=True, height=400)

        # Download button
        csv = df_alerts.to_csv(index=False)
        st.download_button("Download Alert Log (CSV)", csv, "mitm_alerts.csv", "text/csv")
    else:
        st.info("No alerts recorded yet. Run the demo to generate detections.")


# ── TAB 3: Network Flows ─────────────────────────────────
with tab_flows:
    if is_live and status.get("flows"):
        flows = status["flows"]
        df_flows = pd.DataFrame(flows)

        # Color-code by ML score
        st.markdown("#### Active Network Flows")
        st.caption("Flows with ML score >= 0.5 are flagged as malicious")

        col_f1, col_f2 = st.columns([2, 1])

        with col_f1:
            # Flow table with highlighting
            display_df = df_flows[["src_ip", "dst_ip", "src_port", "dst_port",
                                    "protocol", "packets", "s2d_bytes", "d2s_bytes",
                                    "score", "is_mitm"]].copy()
            display_df.columns = ["Source IP", "Dest IP", "Src Port", "Dst Port",
                                   "Proto", "Packets", "Bytes Out", "Bytes In",
                                   "ML Score", "MITM?"]
            display_df["MITM?"] = display_df["MITM?"].map({True: "YES", False: ""})
            st.dataframe(display_df, use_container_width=True, hide_index=True, height=400)

        with col_f2:
            # ML score distribution of active flows
            scores = df_flows["score"].values
            fig_score = go.Figure()
            fig_score.add_trace(go.Histogram(
                x=scores[scores < 0.5], nbinsx=20, name="Normal",
                marker_color=COLORS["green"], opacity=0.8,
            ))
            fig_score.add_trace(go.Histogram(
                x=scores[scores >= 0.5], nbinsx=20, name="Malicious",
                marker_color=COLORS["red"], opacity=0.8,
            ))
            fig_score.add_vline(x=0.5, line_dash="dash", line_color="white",
                                 annotation_text="Threshold")
            fig_score.update_layout(
                title="Flow ML Scores",
                xaxis_title="Score", yaxis_title="Count",
                height=350, template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                barmode="overlay",
            )
            st.plotly_chart(fig_score, use_container_width=True)

            # Traffic volume by IP
            if len(df_flows) > 0:
                ip_traffic = df_flows.groupby("src_ip").agg(
                    total_bytes=("s2d_bytes", "sum"),
                    flows=("src_ip", "count"),
                ).reset_index().sort_values("total_bytes", ascending=False).head(10)

                fig_traffic = go.Figure(go.Bar(
                    x=ip_traffic["total_bytes"],
                    y=ip_traffic["src_ip"],
                    orientation='h',
                    marker_color=COLORS["cyan"],
                    text=ip_traffic["total_bytes"].apply(lambda x: f"{x:,}"),
                    textposition="outside",
                ))
                fig_traffic.update_layout(
                    title="Traffic by Source IP (bytes)",
                    height=300, template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    yaxis=dict(autorange="reversed"),
                    margin=dict(l=100),
                )
                st.plotly_chart(fig_traffic, use_container_width=True)
    else:
        st.info("No active flows. Controller is not running or no traffic yet.")


# ── TAB 4: Attack Analysis ───────────────────────────────
with tab_analysis:
    all_detections = alerts or (status or {}).get("detections", [])

    if all_detections:
        col_a1, col_a2 = st.columns(2)

        with col_a1:
            # Attack type distribution pie
            type_key = "attack_type" if "attack_type" in all_detections[0] else "type"
            attack_types = [d.get(type_key, "UNKNOWN") for d in all_detections]
            type_counts = pd.Series(attack_types).value_counts()

            fig_pie = go.Figure(go.Pie(
                labels=type_counts.index,
                values=type_counts.values,
                hole=0.5,
                marker=dict(colors=[ATTACK_COLORS.get(t, "#8b949e") for t in type_counts.index]),
                textinfo="label+value",
                textfont=dict(size=14, color="white"),
            ))
            fig_pie.update_layout(
                title="Attacks by Type",
                height=400, template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_a2:
            # Detection method distribution
            methods = [d.get("method", "UNKNOWN") for d in all_detections]
            method_counts = pd.Series(methods).value_counts()

            fig_method = go.Figure(go.Bar(
                x=method_counts.values,
                y=method_counts.index,
                orientation='h',
                marker_color=[COLORS["blue"] if "ML" in m else COLORS["yellow"]
                              for m in method_counts.index],
                text=method_counts.values,
                textposition="outside",
                textfont=dict(size=14),
            ))
            fig_method.update_layout(
                title="Detections by Method",
                xaxis_title="Count",
                height=400, template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(autorange="reversed"),
                margin=dict(l=250),
            )
            st.plotly_chart(fig_method, use_container_width=True)

        # Attack timeline
        st.markdown("#### Attack Timeline")
        timeline_data = []
        for i, d in enumerate(all_detections):
            atype = d.get(type_key, "UNKNOWN")
            timeline_data.append({
                "index": i + 1,
                "type": atype,
                "time": d.get("time") or d.get("timestamp", ""),
                "ip": d.get("ip", ""),
                "method": d.get("method", ""),
            })
        df_timeline = pd.DataFrame(timeline_data)

        fig_tl = go.Figure()
        for atype in df_timeline["type"].unique():
            subset = df_timeline[df_timeline["type"] == atype]
            fig_tl.add_trace(go.Scatter(
                x=subset["index"], y=subset["type"],
                mode="markers+text",
                marker=dict(size=18, color=ATTACK_COLORS.get(atype, "#8b949e"),
                            symbol="diamond"),
                text=subset["ip"],
                textposition="top center",
                textfont=dict(size=10, color="#c9d1d9"),
                name=atype,
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Time: %{customdata[0]}<br>"
                    "IP: %{customdata[1]}<br>"
                    "Method: %{customdata[2]}<extra></extra>"
                ),
                customdata=subset[["time", "ip", "method"]].values,
            ))
        fig_tl.update_layout(
            title="Detection Sequence",
            xaxis_title="Detection Order",
            yaxis_title="Attack Type",
            height=300, template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
        )
        st.plotly_chart(fig_tl, use_container_width=True)

        # Targeted IPs
        st.markdown("#### Targeted / Attacker IPs")
        ip_counts = pd.Series([d.get("ip", "") for d in all_detections]).value_counts()
        fig_ips = go.Figure(go.Bar(
            x=ip_counts.index, y=ip_counts.values,
            marker_color=COLORS["red"],
            text=ip_counts.values,
            textposition="outside",
            textfont=dict(size=14),
        ))
        fig_ips.update_layout(
            yaxis_title="Times Flagged",
            height=300, template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_ips, use_container_width=True)

    else:
        st.info("No attack data to analyze yet. Run the demo to generate detections.")


# ── Footer ────────────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style="text-align:center; color:#30363d; font-size:0.8rem; padding-bottom:20px;">
    MITM Detection System — CNN+LSTM + SDN (Ryu + Mininet) — Live Monitoring Dashboard
</div>
""", unsafe_allow_html=True)

# Auto-refresh using st.rerun
time.sleep(refresh)
st.rerun()
