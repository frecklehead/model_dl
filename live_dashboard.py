"""
Live MITM Attack Detection Dashboard
=====================================
Monitors the SDN controller output in real time via mitm_status.json
and mitm_alerts.json written by my_controller.py.

Usage:
  Terminal 1:  ryu-manager my_controller.py
  Terminal 2:  sudo python3 run_demo.py
  Terminal 3:  streamlit run live_dashboard.py

The dashboard auto-refreshes to show live detections.

UI REFACTOR NOTES
-----------------
All changes below are purely presentation-layer. Detection logic, file contracts,
and data models are unchanged from the original live_dashboard.py.

Design direction: precision-industrial cybersecurity product.
- IBM Plex Mono for data/numbers, IBM Plex Sans for UI chrome
- 8px base spacing grid, 4-point corner radii, single-pixel borders
- Deep navy dark mode; near-white light mode with cool-slate tints
- Color language: cyan = neutral/info, amber = warning, crimson = danger, emerald = safe
- Plotly charts share a single theming helper for visual cohesion
- CSS custom properties + color-mix() for theme-stable hover/active states
"""

import html
import json
import os
import re
import time
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st


# ──────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="MITM Watch — live dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = os.path.join(BASE_DIR, "mitm_status.json")
ALERTS_FILE = os.path.join(BASE_DIR, "mitm_alerts.json")
ATTACK_TYPES = ["ARP POISONING", "SSL STRIPPING", "SESSION HIJACKING"]


# ──────────────────────────────────────────────────────────────────────────────
# DESIGN TOKENS  (UI-only — no logic impact)
# ──────────────────────────────────────────────────────────────────────────────
def theme_tokens(mode: str) -> dict:
    """
    Return a complete set of design tokens for the requested theme.
    Every colour referenced in CSS or Plotly is derived from this dict so the
    two themes stay perfectly balanced rather than being a simple inversion.
    """
    if mode == "Dark":
        return {
            "mode": "Dark",
            # Backgrounds
            "bg":        "#080c14",
            "surface":   "#0d1220",
            "surface_2": "#111826",
            "surface_3": "#16202e",
            "surface_4": "#1b2840",
            # Borders
            "border":      "#1e2e44",
            "border_soft": "#162034",
            "border_hi":   "#2a3f5c",
            # Text
            "text":    "#e8edf5",
            "text_2":  "#99aabb",
            "text_3":  "#566680",
            "mono":    "#7ec8e3",          # cyan-tinted mono values
            # Semantic
            "accent":  "#38bdf8",          # sky-400
            "emerald": "#34d399",          # emerald-400
            "crimson": "#f87171",          # red-400
            "amber":   "#fbbf24",          # amber-400
            "violet":  "#a78bfa",          # violet-400
            "cyan":    "#22d3ee",          # cyan-400
            # Semantic backgrounds (subtle tints)
            "emerald_bg": "#061a13",
            "crimson_bg": "#1a0808",
            "amber_bg":   "#1a1200",
            "violet_bg":  "#110d1a",
            "accent_bg":  "#061524",
            # Chart
            "plot_bg":    "rgba(0,0,0,0)",
            "plot_grid":  "#14202e",
            "plot_zero":  "#1e2e40",
            "plot_line":  "#1e2e44",
            # Gradients
            "grad_header":  "linear-gradient(135deg,#0d1220 0%,#0a1628 100%)",
            "grad_safe":    "linear-gradient(135deg,rgba(52,211,153,.07) 0%,rgba(56,189,248,.04) 100%)",
            "grad_danger":  "linear-gradient(135deg,rgba(248,113,113,.09) 0%,rgba(167,139,250,.05) 100%)",
            "grad_accent":  "linear-gradient(135deg,rgba(56,189,248,.10) 0%,rgba(34,211,238,.05) 100%)",
            # Shadows
            "shadow_sm": "0 1px 3px rgba(0,0,0,.5)",
            "shadow_md": "0 4px 16px rgba(0,0,0,.45)",
        }
    # Light mode — cool slate palette, NOT a simple darkmode inversion
    return {
        "mode": "Light",
        "bg":        "#f4f6fa",
        "surface":   "#ffffff",
        "surface_2": "#f0f3f8",
        "surface_3": "#e8edf5",
        "surface_4": "#dde4ef",
        "border":      "#d4dce9",
        "border_soft": "#e4eaf3",
        "border_hi":   "#bbc8db",
        "text":    "#0d1825",
        "text_2":  "#4a5f78",
        "text_3":  "#7a8fa6",
        "mono":    "#0060a0",
        "accent":  "#0284c7",
        "emerald": "#059669",
        "crimson": "#dc2626",
        "amber":   "#d97706",
        "violet":  "#7c3aed",
        "cyan":    "#0891b2",
        "emerald_bg": "#ecfdf5",
        "crimson_bg": "#fef2f2",
        "amber_bg":   "#fffbeb",
        "violet_bg":  "#f5f3ff",
        "accent_bg":  "#f0f9ff",
        "plot_bg":    "rgba(0,0,0,0)",
        "plot_grid":  "#e8eef6",
        "plot_zero":  "#d0dae8",
        "plot_line":  "#d4dce9",
        "grad_header":  "linear-gradient(135deg,#ffffff 0%,#f4f7fc 100%)",
        "grad_safe":    "linear-gradient(135deg,rgba(5,150,105,.07) 0%,rgba(2,132,199,.04) 100%)",
        "grad_danger":  "linear-gradient(135deg,rgba(220,38,38,.07) 0%,rgba(124,58,237,.04) 100%)",
        "grad_accent":  "linear-gradient(135deg,rgba(2,132,199,.08) 0%,rgba(8,145,178,.04) 100%)",
        "shadow_sm": "0 1px 3px rgba(15,23,42,.07)",
        "shadow_md": "0 4px 16px rgba(15,23,42,.10)",
    }


# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS  (UI-only — IBM Plex fonts, 8px grid, custom component styles)
# ──────────────────────────────────────────────────────────────────────────────
def build_css(t: dict) -> str:
    """
    Inject a single <style> block that overrides Streamlit defaults.
    All values reference CSS custom properties derived from the theme tokens
    dict so both themes are driven by one stylesheet.
    """
    return f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

  /* ── Tokens ─────────────────────────────────────────────── */
  :root {{
    --bg:          {t["bg"]};
    --surface:     {t["surface"]};
    --surface-2:   {t["surface_2"]};
    --surface-3:   {t["surface_3"]};
    --surface-4:   {t["surface_4"]};
    --border:      {t["border"]};
    --border-soft: {t["border_soft"]};
    --border-hi:   {t["border_hi"]};
    --text:        {t["text"]};
    --text-2:      {t["text_2"]};
    --text-3:      {t["text_3"]};
    --mono:        {t["mono"]};
    --accent:      {t["accent"]};
    --emerald:     {t["emerald"]};
    --crimson:     {t["crimson"]};
    --amber:       {t["amber"]};
    --violet:      {t["violet"]};
    --cyan:        {t["cyan"]};
    --shadow-sm:   {t["shadow_sm"]};
    --shadow-md:   {t["shadow_md"]};
    --r:           4px;
  }}

  /* ── Base ───────────────────────────────────────────────── */
  html, body, [class*="css"], .stApp {{
    font-family: 'IBM Plex Sans', -apple-system, sans-serif !important;
    background: var(--bg) !important;
    color: var(--text) !important;
    font-size: 14px;
    line-height: 1.5;
  }}

  .main .block-container {{
    max-width: 1480px;
    padding: 24px 32px 40px;
  }}

  /* ── Headings ───────────────────────────────────────────── */
  h1,h2,h3,h4 {{ color: var(--text) !important; letter-spacing: -.01em; }}
  h3 {{
    font-size: 13px !important;
    font-weight: 600 !important;
    letter-spacing: .06em !important;
    text-transform: uppercase !important;
    color: var(--text-3) !important;
    margin: 24px 0 10px !important;
  }}
  hr {{ border-color: var(--border-soft) !important; margin: 16px 0 !important; }}

    /* ── Sidebar shell ──────────────────────────────────────── */
    section[data-testid="stSidebar"] {{
        background: var(--surface) !important;
        border-right: 1px solid var(--border-soft) !important;
        width: 264px !important;
    }}
    section[data-testid="stSidebar"] * {{ color: var(--text-2); font-size: 13px; }}
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3,
    section[data-testid="stSidebar"] strong {{ color: var(--text) !important; }}

    /* ── Sidebar branding ────────────────────────────────────── */
    .sb-brand {{
        padding: 20px 18px 16px;
        border-bottom: 1px solid var(--border-soft);
    }}
    .sb-brand-row {{
        display: flex; align-items: center; gap: 10px; margin-bottom: 4px;
    }}
    .sb-icon {{
        width: 28px; height: 28px; display: grid; place-items: center;
        background: {t["grad_accent"]}; border: 1px solid var(--border);
        border-radius: var(--r); font-size: 14px; flex-shrink: 0;
    }}
    .sb-name {{
        font-size: 13px; font-weight: 700; color: var(--text); letter-spacing: -.01em;
    }}
    .sb-caption {{
        font-size: 11px; color: var(--text-3);
        font-family: 'IBM Plex Mono', monospace; line-height: 1.5;
    }}

    /* ── Sidebar group label ─────────────────────────────────── */
    .sb-group-label {{
        font-size: 10px; font-weight: 700; letter-spacing: .10em;
        text-transform: uppercase; color: var(--text-3);
        margin: 16px 0 10px; display: flex; align-items: center; gap: 6px;
    }}
    .sb-group-label::after {{
        content: ""; flex: 1; height: 1px; background: var(--border-soft);
    }}
    .sb-divider {{
        height: 1px; background: var(--border-soft); margin: 12px 0;
    }}

    /* ── Attack type chip rows ───────────────────────────────── */
    .atk-chips {{ display: flex; flex-direction: column; gap: 5px; }}
    .atk-chip {{
        display: flex; align-items: center; gap: 8px;
        padding: 8px 10px;
        border: 1px solid var(--border-soft); border-radius: var(--r);
        background: var(--surface-2);
        transition: border-color .15s, background .15s;
    }}
    .atk-chip.active {{
        background: var(--chip-bg); border-color: var(--chip-border);
    }}
    .atk-chip-dot {{
        width: 7px; height: 7px; border-radius: 50%;
        background: var(--chip-color); flex-shrink: 0;
    }}
    .atk-chip.inactive .atk-chip-dot {{ opacity: .25; }}
    .atk-chip-label {{
        font-size: 11px; font-weight: 600; letter-spacing: .05em;
        text-transform: uppercase; color: var(--text-2); flex: 1;
    }}
    .atk-chip.inactive .atk-chip-label {{ color: var(--text-3); }}
    .atk-chip-count {{
        font-family: 'IBM Plex Mono', monospace;
        font-size: 12px; font-weight: 600;
        color: var(--chip-color);
    }}
    .atk-chip.inactive .atk-chip-count {{ color: var(--text-3); }}
    .atk-chip-check {{ font-size: 10px; color: var(--chip-color); opacity: 0; transition: opacity .15s; }}
    .atk-chip.active .atk-chip-check {{ opacity: 1; }}

    /* ── Refresh row ─────────────────────────────────────────── */
    .refresh-row {{
        display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;
    }}
    .refresh-label {{
        font-size: 11px; font-weight: 600; letter-spacing: .04em;
        text-transform: uppercase; color: var(--text-3);
    }}
    .refresh-val {{
        font-family: 'IBM Plex Mono', monospace; font-size: 11px; font-weight: 600;
        color: var(--accent); background: {t["accent_bg"]};
        border: 1px solid {t["border_soft"]}; border-radius: 2px; padding: 1px 6px;
    }}

    /* ── Detection method list ───────────────────────────────── */
    .method-list {{ display: flex; flex-direction: column; gap: 5px; }}
    .method-row {{
        display: flex; align-items: flex-start; gap: 8px; padding: 7px 10px;
        border: 1px solid var(--border-soft); border-radius: var(--r);
        background: var(--surface-2);
    }}
    .method-pip {{
        width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; margin-top: 5px;
    }}
    .method-text {{
        font-size: 11px; color: var(--text-3);
        font-family: 'IBM Plex Mono', monospace; line-height: 1.5;
    }}
    .method-tag {{
        font-size: 10px; font-weight: 600; color: var(--text-2);
        display: block; margin-bottom: 1px; letter-spacing: .04em;
        text-transform: uppercase;
    }}

    /* ── Sidebar multiselect overrides ──────────────────────── */
    section[data-testid="stSidebar"] [data-baseweb="select"] {{
        background: var(--surface-2) !important;
        border-color: var(--border-soft) !important;
        border-radius: var(--r) !important;
        font-size: 12px !important;
    }}
    section[data-testid="stSidebar"] [data-baseweb="select"]:focus-within {{
        border-color: var(--accent) !important;
    }}
    section[data-testid="stSidebar"] [data-baseweb="tag"] {{
        background: var(--surface-3) !important;
        border: 1px solid var(--border) !important;
        border-radius: 2px !important;
        font-family: 'IBM Plex Mono', monospace !important;
        font-size: 10px !important; color: var(--text-2) !important;
        padding: 2px 6px !important;
    }}

    /* ── Clear log danger button ─────────────────────────────── */
    .sb-danger button {{
        width: 100% !important;
        border-color: var(--border-soft) !important;
        background: var(--surface-2) !important;
        color: var(--crimson) !important;
        font-size: 12px !important; font-weight: 500 !important;
    }}
    .sb-danger button:hover {{
        border-color: var(--crimson) !important;
        background: {t["crimson_bg"]} !important;
    }}

  /* ── Dashboard header ───────────────────────────────────── */
  .dash-header {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 0 0 20px;
    border-bottom: 1px solid var(--border-soft);
    margin-bottom: 24px;
  }}
  .dash-shield {{
    width: 36px; height: 36px;
    display: grid; place-items: center;
    background: {t["grad_accent"]};
    border: 1px solid var(--border);
    border-radius: var(--r);
    font-size: 18px;
    flex-shrink: 0;
  }}
  .dash-title {{
    font-size: 18px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: -.02em;
    line-height: 1.2;
  }}
  .dash-sub {{
    font-size: 12px;
    color: var(--text-3);
    margin-top: 2px;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .dash-status {{
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    color: var(--text-3);
    white-space: nowrap;
    background: var(--surface-2);
    border: 1px solid var(--border-soft);
    border-radius: 999px;
    padding: 5px 12px;
  }}
  .dot {{
    width: 7px; height: 7px;
    border-radius: 50%;
    display: inline-block;
    flex-shrink: 0;
  }}
  .dot.live {{
    background: var(--emerald);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--emerald) 20%, transparent);
    animation: blink 2.6s ease-in-out infinite;
  }}
  .dot.offline {{ background: var(--crimson); }}
  @keyframes blink {{
    0%,100% {{ opacity:1; transform:scale(1); }}
    50%      {{ opacity:.55; transform:scale(.8); }}
  }}

  /* ── Metric grid ────────────────────────────────────────── */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }}
  .kpi {{
    background: var(--surface);
    border: 1px solid var(--border-soft);
    border-radius: var(--r);
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
    transition: border-color .18s, transform .18s, box-shadow .18s;
    cursor: default;
  }}
  .kpi:hover {{
    border-color: var(--border-hi);
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
  }}
  .kpi::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--kpi-accent, var(--accent));
    border-radius: var(--r) var(--r) 0 0;
  }}
  .kpi-label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .07em;
    text-transform: uppercase;
    color: var(--text-3);
  }}
  .kpi-value {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 28px;
    font-weight: 600;
    color: var(--text);
    line-height: 1.1;
    margin: 10px 0 6px;
    letter-spacing: -.02em;
  }}
  .kpi-note {{
    font-size: 11px;
    color: var(--text-3);
    font-family: 'IBM Plex Mono', monospace;
  }}

  /* ── Attack type cards ──────────────────────────────────── */
  .attack-row {{
    display: grid;
    grid-template-columns: repeat(3,1fr);
    gap: 12px;
    margin-bottom: 24px;
  }}
  .atk {{
    background: var(--surface);
    border: 1px solid var(--border-soft);
    border-radius: var(--r);
    padding: 20px;
    transition: border-color .18s, transform .18s, box-shadow .18s;
  }}
  .atk:hover {{
    border-color: var(--border-hi);
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
  }}
  .atk.hot {{ background: var(--atk-bg); border-color: var(--atk-border); }}
  .atk-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
  }}
  .atk-pip {{
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--atk-color);
    flex-shrink: 0;
  }}
  .atk-name {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .07em;
    text-transform: uppercase;
    color: var(--text-3);
  }}
  .atk-count {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 40px;
    font-weight: 600;
    color: var(--text);
    line-height: 1;
    letter-spacing: -.03em;
  }}
  .atk-count.hot {{ color: var(--atk-color); }}
  .atk-status {{
    margin-top: 8px;
    font-size: 12px;
    color: var(--text-3);
  }}

  /* ── Alert cards ────────────────────────────────────────── */
  .alert {{
    background: var(--surface);
    border: 1px solid var(--border-soft);
    border-left: 3px solid var(--al-color);
    border-radius: var(--r);
    padding: 14px 16px;
    margin: 8px 0;
    transition: border-right-color .15s, background .15s;
  }}
  .alert:hover {{ background: var(--surface-2); border-color: var(--border-hi); border-left-color: var(--al-color); }}
  .alert-top {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }}
  .alert-type {{
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--al-color);
  }}
  .alert-ts {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    color: var(--text-3);
    white-space: nowrap;
    padding-top: 1px;
  }}
  .alert-desc {{
    font-size: 12px;
    color: var(--text-2);
    margin-top: 3px;
    line-height: 1.5;
  }}
  .alert-pills {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 10px;
  }}
  .pill {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 22px;
    border: 1px solid var(--border-soft);
    border-radius: 2px;
    padding: 0 8px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    color: var(--text-3);
    background: var(--surface-2);
  }}
  .pill-label {{ color: var(--text-3); font-weight: 400; margin-right: 2px; }}
  .pill-val   {{ color: var(--text-2); font-weight: 500; }}
  .alert-how {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    color: var(--text-3);
    margin-top: 8px;
    line-height: 1.6;
  }}

  /* ── Blocked IP badges ──────────────────────────────────── */
  .blocked-wrap {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }}
  .blocked-badge {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 26px;
    border: 1px solid color-mix(in srgb, var(--crimson) 30%, transparent);
    border-radius: 2px;
    padding: 0 10px;
    background: {t["crimson_bg"]};
    color: var(--crimson);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    font-weight: 500;
  }}
  .blocked-dot {{
    width: 5px; height: 5px;
    border-radius: 50%;
    background: var(--crimson);
  }}

  /* ── State cards ────────────────────────────────────────── */
  .state-card {{
    background: {t["grad_safe"]};
    border: 1px solid var(--border-soft);
    border-radius: var(--r);
    padding: 28px 32px;
    text-align: center;
    margin: 8px 0 16px;
  }}
  .state-card.warn {{ background: {t["grad_danger"]}; }}
  .state-title {{ font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 4px; }}
  .state-sub   {{ font-size: 12px; color: var(--text-3); font-family: 'IBM Plex Mono', monospace; }}

  /* ── Skeleton loaders ───────────────────────────────────── */
  .skeleton {{
    background: var(--surface-2);
    border: 1px solid var(--border-soft);
    border-radius: var(--r);
    min-height: 92px;
    overflow: hidden;
    position: relative;
  }}
  .skeleton::after {{
    content: "";
    position: absolute; inset: 0;
    transform: translateX(-100%);
    background: linear-gradient(90deg,transparent,color-mix(in srgb,var(--text) 5%,transparent),transparent);
    animation: shimmer 1.4s infinite;
  }}
  @keyframes shimmer {{ 100% {{ transform: translateX(100%); }} }}
  .skel-row {{ display: grid; grid-template-columns: repeat(5,1fr); gap: 12px; margin-bottom: 24px; }}

  /* ── Streamlit component overrides ─────────────────────── */
  div[data-testid="stMetric"] {{
    background: var(--surface);
    border: 1px solid var(--border-soft);
    border-radius: var(--r);
    padding: 14px 16px;
  }}

  button[data-baseweb="tab"] {{
    min-height: 34px !important;
    border-radius: var(--r) !important;
    padding: 6px 14px !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    color: var(--text-3) !important;
    transition: color .15s !important;
  }}
  button[data-baseweb="tab"][aria-selected="true"] {{
    color: var(--text) !important;
    background: var(--surface-2) !important;
    border: 1px solid var(--border-soft) !important;
  }}
  div[data-baseweb="tab-highlight"] {{ display: none !important; }}
  div[data-baseweb="tab-border"]    {{ display: none !important; }}

  div[data-testid="stDataFrame"] {{
    border: 1px solid var(--border-soft) !important;
    border-radius: var(--r) !important;
    overflow: hidden;
    background: var(--surface);
  }}

  .stTextInput input {{
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 12px !important;
    background: var(--surface) !important;
    border-color: var(--border-soft) !important;
    border-radius: var(--r) !important;
    color: var(--text) !important;
  }}
  .stTextInput input:focus {{ border-color: var(--accent) !important; box-shadow: 0 0 0 2px color-mix(in srgb,var(--accent) 18%,transparent) !important; }}

  .stMultiSelect [data-baseweb="select"],
  .stSelectbox  [data-baseweb="select"] {{
    background: var(--surface) !important;
    border-color: var(--border-soft) !important;
    border-radius: var(--r) !important;
    color: var(--text) !important;
  }}

  .stButton > button,
  .stDownloadButton > button {{
    border-radius: var(--r) !important;
    border: 1px solid var(--border-soft) !important;
    background: var(--surface-2) !important;
    color: var(--text-2) !important;
    font-size: 12px !important;
    font-weight: 500 !important;
    min-height: 32px;
    transition: border-color .15s, color .15s;
  }}
  .stButton > button:hover,
  .stDownloadButton > button:hover {{
    border-color: var(--accent) !important;
    color: var(--accent) !important;
  }}

  .stAlert {{
    border-radius: var(--r) !important;
    border: 1px solid var(--border-soft) !important;
    background: var(--surface-2) !important;
    color: var(--text-2) !important;
    font-size: 13px !important;
  }}

  /* ── Sidebar run commands ───────────────────────────────── */
  .stCode code {{
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 11px !important;
    background: var(--surface-3) !important;
    color: var(--mono) !important;
    border-radius: var(--r) !important;
    border: 1px solid var(--border-soft) !important;
  }}

  /* ── Section label ──────────────────────────────────────── */
  .section-label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-3);
    margin: 20px 0 10px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .section-label::after {{
    content: "";
    flex: 1;
    height: 1px;
    background: var(--border-soft);
  }}

  /* ── Footer ─────────────────────────────────────────────── */
  .dash-footer {{
    border-top: 1px solid var(--border-soft);
    margin-top: 32px;
    padding-top: 14px;
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    color: var(--text-3);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }}

  /* ── Responsive ─────────────────────────────────────────── */
  @media (max-width: 1024px) {{
    .kpi-grid, .attack-row {{ grid-template-columns: repeat(2,1fr); }}
    .dash-status {{ display: none; }}
  }}
  @media (max-width: 640px) {{
    .main .block-container {{ padding: 16px; }}
    .kpi-grid, .attack-row {{ grid-template-columns: 1fr; }}
  }}
</style>
"""


# ──────────────────────────────────────────────────────────────────────────────
# DATA HELPERS  (unchanged from original)
# ──────────────────────────────────────────────────────────────────────────────
def load_status():
    try:
        with open(STATUS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_alerts():
    try:
        with open(ALERTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def esc(v):
    return html.escape("" if v is None else str(v))


def attack_key(rec):
    return rec.get("attack_type") or rec.get("type") or "UNKNOWN"


def parse_time(v):
    if not v:
        return pd.NaT
    for fmt in ("%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            p = datetime.strptime(str(v), fmt)
            if fmt == "%H:%M:%S":
                now = datetime.now()
                p = p.replace(year=now.year, month=now.month, day=now.day)
            return p
        except ValueError:
            pass
    return pd.to_datetime(v, errors="coerce")


def extract_score(text):
    m = re.search(r"(?:ML\s+)?score\s*=\s*([0-9]*\.?[0-9]+)", str(text), re.IGNORECASE)
    return float(m.group(1)) if m else np.nan


def records_to_df(records):
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    rename_map = {
        "attack_type": "Attack Type", "type": "Attack Type",
        "timestamp": "Time",         "time": "Time",
        "method": "Method",           "ip": "IP",
        "mac": "MAC",                 "detail": "Detail",
        "how": "How",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})
    for col, default in [("Attack Type", "UNKNOWN"), ("Time", ""), ("IP", "")]:
        if col not in df.columns:
            df[col] = default
    df["Score"] = df["Detail"].apply(extract_score) if "Detail" in df.columns else np.nan
    df["_parsed_time"] = df["Time"].apply(parse_time)
    return df


def filter_by_search(df, q):
    if df.empty or not q:
        return df
    mask = df.astype(str).apply(lambda c: c.str.contains(q, case=False, na=False)).any(axis=1)
    return df[mask]


# ──────────────────────────────────────────────────────────────────────────────
# HTML COMPONENT BUILDERS  (UI-only helpers)
# ──────────────────────────────────────────────────────────────────────────────
def kpi_card(label, value, note, accent):
    return f"""
    <div class="kpi" style="--kpi-accent:{accent};">
        <div class="kpi-label">{esc(label)}</div>
        <div class="kpi-value">{esc(value)}</div>
        <div class="kpi-note">{esc(note)}</div>
    </div>"""


def state_card(title, sub, warn=False):
    cls = "state-card warn" if warn else "state-card"
    return f"""
    <div class="{cls}">
        <div class="state-title">{esc(title)}</div>
        <div class="state-sub">{esc(sub)}</div>
    </div>"""


def section_label(text):
    return f'<div class="section-label">{esc(text)}</div>'


# Attack description lookup (unchanged logic)
_ATTACK_DESC = {
    "ARP POISONING":    "Someone forged ARP replies and tried to reroute traffic through their own machine.",
    "SSL STRIPPING":    "HTTPS traffic got downgraded, or behaved oddly around TLS.",
    "SESSION HIJACKING": "RST/ACK pattern looked like someone trying to take over a session.",
}


def alert_card_html(rec, t, colors):
    atype  = attack_key(rec)
    color  = colors.get(atype, t["text_3"])
    method = rec.get("method", "")
    ip     = rec.get("ip", "")
    mac    = rec.get("mac", "")
    ts     = rec.get("time") or rec.get("timestamp", "")
    how    = rec.get("how", "") or rec.get("detail", "")
    desc   = _ATTACK_DESC.get(atype, "Detection reported by the SDN controller.")

    score = extract_score(rec.get("detail", ""))
    if np.isnan(score):
        score_pill = ""
    else:
        score_color = t["crimson"] if score >= 0.5 else t["emerald"]
        score_pill = (
            f'<span class="pill" style="border-color:color-mix(in srgb,{score_color} 35%,{t["border_soft"]});'
            f'background:color-mix(in srgb,{score_color} 8%,{t["surface_2"]});">'
            f'<span class="pill-label">ML score</span>'
            f'<span class="pill-val" style="color:{score_color};font-weight:600;">{score:.4f}</span>'
            f'</span>'
        )

    pills = (
        score_pill
        + f'<span class="pill"><span class="pill-label">method</span><span class="pill-val">{esc(method or "—")}</span></span>'
        f'<span class="pill"><span class="pill-label">src</span><span class="pill-val">{esc(ip or "—")}</span></span>'
        f'<span class="pill"><span class="pill-label">mac</span><span class="pill-val">{esc(mac or "—")}</span></span>'
    )
    how_row = f'<div class="alert-how">{esc(how)}</div>' if how else ""

    return f"""
    <div class="alert" style="--al-color:{color};">
        <div class="alert-top">
            <div>
                <div class="alert-type">{esc(atype)}</div>
                <div class="alert-desc">{esc(desc)}</div>
            </div>
            <div class="alert-ts">{esc(ts)}</div>
        </div>
        <div class="alert-pills">{pills}</div>
        {how_row}
    </div>"""


# ──────────────────────────────────────────────────────────────────────────────
# PLOTLY CHART HELPERS  (refactored aesthetics; logic unchanged)
# ──────────────────────────────────────────────────────────────────────────────
def _chart_base(fig, t, title="", h=340, margin=None, showlegend=True):
    """Apply shared Plotly styling so all charts feel like a cohesive system."""
    fig.update_layout(
        title=dict(
            text=title,
            font=dict(size=13, color=t["text_2"],
                      family="IBM Plex Sans, sans-serif"),
            x=0.0, pad=dict(b=4),
        ),
        height=h,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="IBM Plex Mono, monospace", color=t["text_3"], size=11),
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02,
            xanchor="right", x=1,
            font=dict(size=11, color=t["text_3"]),
            bgcolor="rgba(0,0,0,0)",
        ),
        margin=margin or dict(t=48, b=40, l=48, r=16),
        showlegend=showlegend,
    )
    axis_style = dict(
        gridcolor=t["plot_grid"],
        zerolinecolor=t["plot_zero"],
        linecolor=t["plot_line"],
        tickfont=dict(color=t["text_3"], size=11),
        title_font=dict(color=t["text_3"], size=11),
        ticklen=0,
    )
    fig.update_xaxes(**axis_style)
    fig.update_yaxes(**axis_style)
    return fig


def chart_attack_frequency(df, t, colors):
    fig = go.Figure()
    if df.empty or df["_parsed_time"].isna().all():
        return _chart_base(fig, t, "Attacks over time", 320)

    timed = df.dropna(subset=["_parsed_time"]).copy().sort_values("_parsed_time")
    timed["minute"] = timed["_parsed_time"].dt.floor("min")
    counts = timed.groupby(["minute", "Attack Type"]).size().reset_index(name="n")
    total  = timed.groupby("minute").size().reset_index(name="n")

    for atype in counts["Attack Type"].unique():
        sub = counts[counts["Attack Type"] == atype]
        fig.add_trace(go.Bar(
            x=sub["minute"], y=sub["n"],
            name=atype,
            marker_color=colors.get(atype, t["text_3"]),
            opacity=0.75,
            hovertemplate="%{x|%H:%M} · %{y} events<extra>" + esc(atype) + "</extra>",
        ))

    if not total.empty:
        total["trend"] = total["n"].rolling(3, min_periods=1).mean()
        fig.add_trace(go.Scatter(
            x=total["minute"], y=total["trend"],
            name="3-pt trend",
            mode="lines+markers",
            line=dict(color=t["accent"], width=2, shape="spline"),
            marker=dict(size=5, color=t["accent"]),
            hovertemplate="%{x|%H:%M} · trend %{y:.1f}<extra></extra>",
        ))

    fig.update_layout(barmode="stack")
    fig.update_xaxes(title_text="Time")
    fig.update_yaxes(title_text="Alerts")
    return _chart_base(fig, t, "Attacks over time", 320)


def chart_attack_rate(df, t):
    fig = go.Figure()
    if df.empty or df["_parsed_time"].isna().all():
        return _chart_base(fig, t, "How busy each minute is", 280, showlegend=False)

    timed = df.dropna(subset=["_parsed_time"]).copy().sort_values("_parsed_time")
    pm = timed.groupby(timed["_parsed_time"].dt.floor("min")).size().reset_index(name="attacks")
    pm["rate"] = pm["attacks"].rolling(2, min_periods=1).mean()

    # Use rgba directly — Plotly does not support CSS color-mix()
    fill_color = "rgba(56,189,248,.10)" if t["mode"] == "Dark" else "rgba(2,132,199,.08)"
    fig.add_trace(go.Scatter(
        x=pm["_parsed_time"], y=pm["rate"],
        mode="lines+markers",
        fill="tozeroy",
        fillcolor=fill_color,
        line=dict(color=t["accent"], width=2, shape="spline"),
        marker=dict(size=6, color=t["accent"]),
        hovertemplate="%{x|%H:%M} · %{y:.1f} /min<extra></extra>",
    ))
    fig.update_xaxes(title_text="Time")
    fig.update_yaxes(title_text="Alerts / min")
    return _chart_base(fig, t, "How busy each minute is", 280, showlegend=False)


def chart_score_rolling(df_flows, df_alerts, t):
    fig = go.Figure()
    scores = []

    if not df_flows.empty and "score" in df_flows.columns:
        for i, s in enumerate(pd.to_numeric(df_flows["score"], errors="coerce").dropna()):
            scores.append({"i": i + 1, "s": s, "src": "flows"})

    if not df_alerts.empty and "Score" in df_alerts.columns:
        start = len(scores)
        for i, s in enumerate(pd.to_numeric(df_alerts["Score"], errors="coerce").dropna()):
            scores.append({"i": start + i + 1, "s": s, "src": "alerts"})

    if not scores:
        return _chart_base(fig, t, "Model scores, smoothed out", 280, showlegend=False)

    sdf = pd.DataFrame(scores)
    sdf["roll"] = sdf["s"].rolling(5, min_periods=1).mean()

    fig.add_trace(go.Scatter(
        x=sdf["i"], y=sdf["s"],
        mode="markers", name="Score",
        marker=dict(size=6, color=t["text_3"], opacity=0.55),
        hovertemplate="obs %{x} · score %{y:.4f}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=sdf["i"], y=sdf["roll"],
        mode="lines", name="5-sample avg",
        line=dict(color=t["accent"], width=2.5, shape="spline"),
        hovertemplate="obs %{x} · avg %{y:.4f}<extra></extra>",
    ))
    fig.add_hline(
        y=0.5,
        line=dict(color=t["crimson"], dash="dot", width=1),
        annotation_text="threshold 0.5",
        annotation_font=dict(color=t["text_3"], size=10),
    )
    fig.update_xaxes(title_text="Sample #")
    fig.update_yaxes(title_text="Model score", range=[0, 1])
    return _chart_base(fig, t, "Model scores, smoothed out", 280)


# ──────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    # Theme toggle
    theme = st.radio("Theme", ["Dark", "Light"], index=0, horizontal=True)

t = theme_tokens(theme)

# Attack colour palette derived from tokens
COLORS = {
    "ARP POISONING":    t["crimson"],
    "SSL STRIPPING":    t["amber"],
    "SESSION HIJACKING": t["violet"],
}
BACKGROUNDS = {
    "ARP POISONING":    t["crimson_bg"],
    "SSL STRIPPING":    t["amber_bg"],
    "SESSION HIJACKING": t["violet_bg"],
}
BORDERS = {
    "ARP POISONING":    f"color-mix(in srgb,{t['crimson']} 35%,transparent)",
    "SSL STRIPPING":    f"color-mix(in srgb,{t['amber']} 35%,transparent)",
    "SESSION HIJACKING": f"color-mix(in srgb,{t['violet']} 35%,transparent)",
}

# Inject CSS
st.markdown(build_css(t), unsafe_allow_html=True)

# ── Load data (logic unchanged) ──
status = load_status()
alerts = load_alerts()
is_live       = status is not None and "timestamp" in (status or {})
all_detections = alerts or (status or {}).get("detections", [])
alerts_df      = records_to_df(all_detections)
flows_df       = pd.DataFrame((status or {}).get("flows", []))

# ── Sidebar controls ──
with st.sidebar:

    # ── Branding ──────────────────────────────────────────────────────────────
    st.markdown(f'''
    <div class="sb-brand">
        <div class="sb-brand-row">
            <div class="sb-icon">🛡</div>
            <div class="sb-name">MITM Watch</div>
        </div>
        <div class="sb-caption">Watching the SDN for anything that smells like a man-in-the-middle.</div>
    </div>''', unsafe_allow_html=True)

    # ── Refresh ────────────────────────────────────────────────────────────────
    st.markdown('<div style="padding:0 2px">', unsafe_allow_html=True)
    st.markdown('<div class="sb-group-label">Refresh</div>', unsafe_allow_html=True)
    refresh = st.slider("Refresh interval", 1, 10, 2, label_visibility="collapsed")
    st.markdown(
        f'<div class="refresh-row"><span class="refresh-label">Interval</span><span class="refresh-val">{refresh}s</span></div>',
        unsafe_allow_html=True,
    )

    # ── Attack type filter — styled chips above native multiselect ─────────────
    st.markdown('<div class="sb-group-label">Attack type</div>', unsafe_allow_html=True)

    # Compute per-type counts for chip badges
    _counts_preview = {}
    if not alerts_df.empty and "Attack Type" in alerts_df.columns:
        _counts_preview = alerts_df["Attack Type"].value_counts().to_dict()

    _chip_meta = {
        "ARP POISONING":    (t["crimson"], t["crimson_bg"], f"color-mix(in srgb,{t['crimson']} 28%,{t['border_soft']})"),
        "SSL STRIPPING":    (t["amber"],   t["amber_bg"],   f"color-mix(in srgb,{t['amber']} 28%,{t['border_soft']})"),
        "SESSION HIJACKING":(t["violet"],  t["violet_bg"],  f"color-mix(in srgb,{t['violet']} 28%,{t['border_soft']})"),
    }
    chips_html = '<div class="atk-chips">'
    for atype in ATTACK_TYPES:
        color, bg, border = _chip_meta[atype]
        count = _counts_preview.get(atype, 0)
        chips_html += f'''
        <div class="atk-chip active"
             style="--chip-color:{color};--chip-bg:{bg};--chip-border:{border};">
            <div class="atk-chip-dot"></div>
            <div class="atk-chip-label">{atype}</div>
            <div class="atk-chip-count">{count if count else ""}</div>
            <div class="atk-chip-check">✓</div>
        </div>'''
    chips_html += '</div>'
    st.markdown(chips_html, unsafe_allow_html=True)

    # Native multiselect hidden behind chips (drives actual filter logic)
    selected_types = st.multiselect(
        "Attack type", ATTACK_TYPES, default=ATTACK_TYPES,
        label_visibility="collapsed",
    )

    # ── IP filter ─────────────────────────────────────────────────────────────
    st.markdown('<div class="sb-group-label">IP address</div>', unsafe_allow_html=True)
    ip_options = sorted({
        str(ip)
        for ip in (
            list(alerts_df.get("IP", pd.Series(dtype=str)).dropna()) +
            list(flows_df.get("src_ip", pd.Series(dtype=str)).dropna()) +
            list(flows_df.get("dst_ip", pd.Series(dtype=str)).dropna())
        )
        if str(ip)
    })
    selected_ips = st.multiselect(
        "Filter by IP", ip_options, default=[],
        placeholder="All IPs",
        label_visibility="collapsed",
    )

    # ── Malicious-only toggle ──────────────────────────────────────────────────
    st.markdown('<div class="sb-group-label">Flow view</div>', unsafe_allow_html=True)
    show_malicious_only = st.toggle("Malicious flows only", value=False)

    # Show active filter count
    active_filters = (len(selected_types) < len(ATTACK_TYPES)) or bool(selected_ips) or show_malicious_only
    if active_filters:
        parts = []
        if len(selected_types) < len(ATTACK_TYPES):
            parts.append(f"{len(selected_types)}/{len(ATTACK_TYPES)} types")
        if selected_ips:
            parts.append(f"{len(selected_ips)} IPs")
        if show_malicious_only:
            parts.append("malicious only")
        st.markdown(
            f'<div style="margin-top:8px;padding:6px 10px;background:{t["accent_bg"]};border:1px solid {t["border_soft"]};border-radius:4px;font-size:11px;font-family:\'IBM Plex Mono\',monospace;color:{t["accent"]};">▸ Filtered: {" · ".join(parts)}</div>',
            unsafe_allow_html=True,
        )

    # ── Detection methods info ─────────────────────────────────────────────────
    st.markdown('<div class="sb-group-label">How it spots things</div>', unsafe_allow_html=True)
    st.markdown(f'''
    <div class="method-list">
        <div class="method-row">
            <div class="method-pip" style="background:{t["accent"]};"></div>
            <div class="method-text">
                <span class="method-tag">CNN+LSTM</span>
                Reads every flow and flags it if the score crosses 0.5.
            </div>
        </div>
        <div class="method-row">
            <div class="method-pip" style="background:{t["amber"]};"></div>
            <div class="method-text">
                <span class="method-tag">Old-school rules</span>
                ARP table mismatches, SSL downgrades, spoofed RSTs.
            </div>
        </div>
    </div>''', unsafe_allow_html=True)

    # ── Run commands ───────────────────────────────────────────────────────────
    st.markdown('<div class="sb-group-label">To start things up</div>', unsafe_allow_html=True)
    st.code("ryu-manager my_controller.py\\nsudo python3 run_demo.py\\nstreamlit run live_dashboard.py", language="bash")

    # ── Clear log ──────────────────────────────────────────────────────────────
    st.markdown('<div class="sb-group-label">Reset</div>', unsafe_allow_html=True)
    st.markdown('<div class="sb-danger">', unsafe_allow_html=True)
    if st.button("⚠ Wipe the alert log", use_container_width=True):
        try:
            open(ALERTS_FILE, "w").write("[]")
            open(STATUS_FILE, "w").write("{}")
            st.success("Cleared — starting fresh.")
        except Exception:
            st.error("Couldn't clear the logs, sorry.")
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# APPLY FILTERS  (logic unchanged)
# ──────────────────────────────────────────────────────────────────────────────
filtered_alerts_df = alerts_df.copy()
if not filtered_alerts_df.empty:
    filtered_alerts_df = filtered_alerts_df[filtered_alerts_df["Attack Type"].isin(selected_types)]
    if selected_ips:
        filtered_alerts_df = filtered_alerts_df[filtered_alerts_df["IP"].isin(selected_ips)]

filtered_detections = [
    r for r in all_detections
    if attack_key(r) in selected_types and (not selected_ips or str(r.get("ip","")) in selected_ips)
]

filtered_flows_df = flows_df.copy()
if not filtered_flows_df.empty:
    if selected_ips:
        mask = (
            filtered_flows_df.get("src_ip", pd.Series(dtype=str)).isin(selected_ips) |
            filtered_flows_df.get("dst_ip", pd.Series(dtype=str)).isin(selected_ips)
        )
        filtered_flows_df = filtered_flows_df[mask]
    if show_malicious_only:
        score_mask = pd.to_numeric(filtered_flows_df.get("score", 0), errors="coerce").fillna(0) >= 0.5
        flag_mask  = filtered_flows_df["is_mitm"].astype(bool) if "is_mitm" in filtered_flows_df.columns else pd.Series(False, index=filtered_flows_df.index)
        filtered_flows_df = filtered_flows_df[score_mask | flag_mask]


# ──────────────────────────────────────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────────────────────────────────────
status_cls  = "live" if is_live else "offline"
status_text = (
    f"last update · {(status or {}).get('timestamp', 'unknown')}"
    if is_live else "controller isn't talking yet"
)

st.markdown(f"""
<div class="dash-header">
    <div class="dash-shield">🛡</div>
    <div>
        <div class="dash-title">What's happening on the network</div>
        <div class="dash-sub">live SDN flows — watching for man-in-the-middle activity</div>
    </div>
    <div class="dash-status">
        <span class="dot {status_cls}"></span>
        {esc(status_text)}
    </div>
</div>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# KPI ROW
# ──────────────────────────────────────────────────────────────────────────────
if not is_live and not all_detections:
    # Skeleton loading state
    st.markdown("""
    <div class="skel-row">
        <div class="skeleton"></div><div class="skeleton"></div>
        <div class="skeleton"></div><div class="skeleton"></div>
        <div class="skeleton"></div>
    </div>""", unsafe_allow_html=True)
else:
    attack_counts  = (status or {}).get("attack_counts", {})
    total_attacks  = sum(attack_counts.values()) if attack_counts else len(all_detections)
    blocked        = (status or {}).get("blocked_ips", [])
    malicious_flows = 0
    if not flows_df.empty:
        malicious_flows = int(
            (pd.to_numeric(flows_df.get("score", 0), errors="coerce").fillna(0) >= 0.5).sum()
        )

    st.markdown(f"""
    <div class="kpi-grid">
        {kpi_card("Live flows",      f"{(status or {}).get('active_flows', 0):,}", f"{malicious_flows} look fishy",        t["accent"])}
        {kpi_card("Switches up",     f"{(status or {}).get('switches', 0):,}",     "talking to the controller",            t["cyan"])}
        {kpi_card("Hosts I know",    f"{(status or {}).get('arp_entries', 0):,}",  "IP → MAC pairs seen so far",           t["emerald"])}
        {kpi_card("Attacks caught",  f"{total_attacks:,}",                         "matching the filters on the left",     t["crimson"])}
        {kpi_card("Hosts I blocked", f"{len(blocked):,}",                          "cut off from the network",             t["amber"])}
    </div>""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# TABS
# ──────────────────────────────────────────────────────────────────────────────
tab_live, tab_alerts, tab_flows, tab_analysis = st.tabs(
    ["Live view", "Alert log", "Traffic", "Closer look"]
)


# ── TAB: Live Detection ───────────────────────────────────────────────────────
with tab_live:
    if not is_live and not all_detections:
        st.markdown(state_card(
            "Nothing yet — waiting on the controller",
            "Once ryu-manager and run_demo.py are running, activity will show up here.",
            warn=True,
        ), unsafe_allow_html=True)
    else:
        # Attack type summary cards
        counts_src = {}
        if not filtered_alerts_df.empty:
            counts_src = filtered_alerts_df["Attack Type"].value_counts().to_dict()
        elif filtered_detections:
            counts_src = pd.Series([attack_key(d) for d in filtered_detections]).value_counts().to_dict()
        else:
            counts_src = (status or {}).get("attack_counts", {})

        cards_html = ""
        for atype in ATTACK_TYPES:
            count  = counts_src.get(atype, 0)
            color  = COLORS[atype]
            hot    = count > 0
            bg     = BACKGROUNDS[atype] if hot else t["surface"]
            border = f"color-mix(in srgb,{color} 30%,{t['border_soft']})" if hot else t["border_soft"]
            cnt_cls = "atk-count hot" if hot else "atk-count"
            status_copy = "needs a closer look" if hot else "nothing to worry about"
            cards_html += f"""
            <div class="atk {'hot' if hot else ''}"
                 style="--atk-color:{color}; --atk-bg:{bg}; --atk-border:{border};">
                <div class="atk-header">
                    <div class="atk-pip"></div>
                    <div class="atk-name">{esc(atype)}</div>
                </div>
                <div class="{cnt_cls}">{count:,}</div>
                <div class="atk-status">{esc(status_copy)}</div>
            </div>"""

        st.markdown(f'<div class="attack-row">{cards_html}</div>', unsafe_allow_html=True)

        # Recent detections — newest first, then make sure every attack type
        # present in the log gets at least one card so SSL/SH don't get pushed
        # out of view by a long run of ARP events.
        display_list      = list(reversed(filtered_detections[-10:]))
        shown_ids         = {id(r) for r in display_list}
        seen_types        = {attack_key(r) for r in display_list}
        for atype in selected_types:
            if atype in seen_types:
                continue
            older = next(
                (r for r in reversed(filtered_detections)
                 if attack_key(r) == atype and id(r) not in shown_ids),
                None,
            )
            if older is not None:
                display_list.append(older)
                shown_ids.add(id(older))
                seen_types.add(atype)

        if display_list:
            st.markdown(section_label("Latest activity"), unsafe_allow_html=True)
            for rec in display_list:
                st.markdown(alert_card_html(rec, t, COLORS), unsafe_allow_html=True)
        else:
            st.markdown(state_card(
                "Nothing matches the filters right now",
                "Clear the filters on the left to see everything that came through.",
            ), unsafe_allow_html=True)

        # Blocked IPs
        blocked = (status or {}).get("blocked_ips", [])
        if blocked:
            st.markdown(section_label("Hosts I've cut off"), unsafe_allow_html=True)
            badges = "".join(
                f'<span class="blocked-badge"><span class="blocked-dot"></span>{esc(ip)}</span>'
                for ip in blocked
            )
            st.markdown(f'<div class="blocked-wrap">{badges}</div>', unsafe_allow_html=True)


# ── TAB: Alert Log ────────────────────────────────────────────────────────────
with tab_alerts:
    if filtered_alerts_df.empty:
        st.info("No alerts matching your filters yet.")
    else:
        st.markdown(section_label("Every alert so far"), unsafe_allow_html=True)
        q = st.text_input(
            "Search alerts",
            placeholder="search by IP, MAC, attack type, anything really…",
            key="alert_search",
        )
        tdf = filter_by_search(filtered_alerts_df, q)
        display = tdf.drop(columns=[c for c in ["_parsed_time"] if c in tdf.columns])
        display = display[[c for c in display.columns if c != "Score"] + [c for c in ["Score"] if c in display.columns]]
        st.dataframe(display, use_container_width=True, hide_index=True, height=400)
        st.download_button(
            "Export CSV", display.to_csv(index=False), "mitm_alerts.csv", "text/csv",
            use_container_width=True,
        )


# ── TAB: Network Flows ────────────────────────────────────────────────────────
with tab_flows:
    if filtered_flows_df.empty:
        st.info("No traffic matches your filters at the moment.")
    else:
        st.markdown(section_label("Live traffic"), unsafe_allow_html=True)
        st.caption("Anything scoring 0.5 or higher, or already flagged by the controller, is treated as malicious.")

        qf = st.text_input(
            "Search flows",
            placeholder="search by source, destination, port, score…",
            key="flow_search",
        )
        dfl = filter_by_search(filtered_flows_df, qf)

        table_cols = ["src_ip","dst_ip","src_port","dst_port","protocol","packets","s2d_bytes","d2s_bytes","score","is_mitm"]
        table_cols = [c for c in table_cols if c in dfl.columns]
        tbl = dfl[table_cols].copy().rename(columns={
            "src_ip":"Source IP", "dst_ip":"Destination IP",
            "src_port":"Src Port", "dst_port":"Dst Port",
            "protocol":"Protocol", "packets":"Packets",
            "s2d_bytes":"Bytes Out", "d2s_bytes":"Bytes In",
            "score":"ML Score", "is_mitm":"MITM",
        })
        if "MITM" in tbl.columns:
            tbl["MITM"] = tbl["MITM"].map({True:"Yes", False:"No"})

        st.dataframe(tbl, use_container_width=True, hide_index=True, height=320)

        col_s, col_t = st.columns(2)
        with col_s:
            scores = pd.to_numeric(dfl.get("score", pd.Series(dtype=float)), errors="coerce").dropna()
            fig_hist = go.Figure()
            fig_hist.add_trace(go.Histogram(
                x=scores[scores < 0.5], nbinsx=24, name="Normal",
                marker_color=t["emerald"], opacity=0.72,
            ))
            fig_hist.add_trace(go.Histogram(
                x=scores[scores >= 0.5], nbinsx=24, name="Malicious",
                marker_color=t["crimson"], opacity=0.72,
            ))
            fig_hist.add_vline(
                x=0.5, line=dict(color=t["crimson"], dash="dot", width=1),
                annotation_text="threshold", annotation_font=dict(color=t["text_3"], size=10),
            )
            fig_hist.update_layout(barmode="overlay")
            fig_hist.update_xaxes(title_text="Score", range=[0, 1])
            fig_hist.update_yaxes(title_text="Count")
            st.plotly_chart(_chart_base(fig_hist, t, "How flows scored", 300), use_container_width=True)

        with col_t:
            if {"src_ip","s2d_bytes"}.issubset(dfl.columns):
                ipt = (
                    dfl.groupby("src_ip")
                    .agg(bytes=("s2d_bytes","sum"), flows=("src_ip","count"))
                    .reset_index().sort_values("bytes", ascending=False).head(10)
                )
                fig_tr = go.Figure(go.Bar(
                    x=ipt["bytes"], y=ipt["src_ip"],
                    orientation="h",
                    marker_color=t["accent"],
                    text=ipt["bytes"].apply(lambda x: f"{x:,.0f}"),
                    textposition="outside",
                    hovertemplate="<b>%{y}</b><br>%{x:,} bytes<extra></extra>",
                ))
                fig_tr.update_xaxes(title_text="Bytes out")
                fig_tr.update_yaxes(title_text="", autorange="reversed")
                st.plotly_chart(
                    _chart_base(fig_tr, t, "Who's sending the most traffic", 300,
                                margin=dict(t=48, b=40, l=110, r=24),
                                showlegend=False),
                    use_container_width=True,
                )


# ── TAB: Attack Analysis ──────────────────────────────────────────────────────
with tab_analysis:
    if filtered_alerts_df.empty and filtered_flows_df.empty:
        st.info("Nothing to plot yet — once attacks start coming in, charts will show up here.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            if not filtered_alerts_df.empty:
                tc = filtered_alerts_df["Attack Type"].value_counts()
                fig_pie = go.Figure(go.Pie(
                    labels=tc.index, values=tc.values,
                    hole=0.64,
                    marker=dict(colors=[COLORS.get(x, t["text_3"]) for x in tc.index]),
                    textinfo="label+value",
                    textfont=dict(size=11, color=t["text_2"]),
                    hovertemplate="<b>%{label}</b> · %{value} events<extra></extra>",
                ))
                st.plotly_chart(_chart_base(fig_pie, t, "What kind of attacks", 320, showlegend=False), use_container_width=True)

        with col_b:
            if not filtered_alerts_df.empty and "Method" in filtered_alerts_df.columns:
                mc = filtered_alerts_df["Method"].fillna("UNKNOWN").value_counts()
                fig_m = go.Figure(go.Bar(
                    x=mc.values, y=mc.index,
                    orientation="h",
                    marker_color=[t["accent"] if "ML" in str(m).upper() else t["amber"] for m in mc.index],
                    text=mc.values,
                    textposition="outside",
                    hovertemplate="<b>%{y}</b> · %{x}<extra></extra>",
                ))
                fig_m.update_xaxes(title_text="Count")
                fig_m.update_yaxes(autorange="reversed")
                st.plotly_chart(
                    _chart_base(fig_m, t, "How they got caught", 320,
                                margin=dict(t=48, b=40, l=160, r=24),
                                showlegend=False),
                    use_container_width=True,
                )

        # Attack frequency (full width)
        st.plotly_chart(chart_attack_frequency(filtered_alerts_df, t, COLORS), use_container_width=True)

        col_c, col_d = st.columns(2)
        with col_c:
            st.plotly_chart(chart_attack_rate(filtered_alerts_df, t), use_container_width=True)
        with col_d:
            st.plotly_chart(chart_score_rolling(filtered_flows_df, filtered_alerts_df, t), use_container_width=True)

        # Flagged IP frequency
        if not filtered_alerts_df.empty and "IP" in filtered_alerts_df.columns:
            st.markdown(section_label("Who keeps showing up"), unsafe_allow_html=True)
            ic = filtered_alerts_df["IP"].replace("", np.nan).dropna().value_counts()
            if not ic.empty:
                fig_ip = go.Figure(go.Bar(
                    x=ic.index, y=ic.values,
                    marker_color=t["crimson"],
                    text=ic.values,
                    textposition="outside",
                    hovertemplate="<b>%{x}</b> · %{y} flags<extra></extra>",
                ))
                fig_ip.update_yaxes(title_text="Flags")
                fig_ip.update_xaxes(title_text="IP address")
                st.plotly_chart(_chart_base(fig_ip, t, "Repeat offenders", 280, showlegend=False), use_container_width=True)


# ──────────────────────────────────────────────────────────────────────────────
# FOOTER
# ──────────────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="dash-footer">
    <span>Built for a minor project — CNN+LSTM behind the scenes, plus a few sanity-check rules.</span>
    <span>refreshing every {refresh}s</span>
</div>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# AUTO-REFRESH  (unchanged behaviour)
# ──────────────────────────────────────────────────────────────────────────────
time.sleep(refresh)
st.rerun()