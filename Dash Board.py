#!/usr/bin/env python3
# =============================================================
# CCNS Project - Network Hijack Detection Dashboard
# Light Theme + Extended Intelligence (Stable Figures + Full-history Trend)
# =============================================================

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px
import os, shutil, platform
from datetime import datetime

# -------- Detect OS & set correct paths --------
if platform.system() == "Windows":
    BASE = r"C:\sf_shared"
else:
    BASE = "/media/sf_sf_shared"

ALERT_FILE = os.path.join(BASE, "alerts.csv")
PROTO_FILE = os.path.join(BASE, "protocol_summary.csv")
HTTP_FILE  = os.path.join(BASE, "http_metadata.csv")
SYN_FILE   = os.path.join(BASE, "syn_activity.csv")

# -------- Initialize Dash App --------
app = dash.Dash(_name_)
app.title = "CCNS Network Hijack Detection Dashboard"

# -------- THEME STYLES --------
APP_STYLE = {
    'fontFamily': 'Segoe UI, Roboto, sans-serif',
    'backgroundColor': '#f4f6f9',
    'color': '#000',
    'padding': '10px',
    'minHeight': '100vh'
}

CARD_STYLE = {
    'backgroundColor': '#ffffff',
    'borderRadius': '10px',
    'boxShadow': '0 2px 8px rgba(0,0,0,0.1)',
    'padding': '15px',
    'marginBottom': '15px',
    'border': '1px solid #ddd'
}

HEADER_STYLE = {
    'textAlign': 'center',
    'background': 'linear-gradient(90deg, #0052cc, #1e90ff)',
    'color': 'white',
    'padding': '15px',
    'borderRadius': '10px',
    'marginBottom': '25px',
    'boxShadow': '0 3px 8px rgba(0,0,0,0.2)'
}

FOOTER_STYLE = {
    'textAlign': 'center',
    'color': '#555',
    'padding': '10px',
    'borderRadius': '10px',
    'fontSize': '13px',
    'marginTop': '25px'
}

# =============================================================
# Globals for change-detection caching (prevents redraw jitter)
# =============================================================
_last_mtimes = {'alerts': None, 'proto': None, 'http': None, 'syn': None}
_last_figs = {'proto': None, 'time': None}

# =============================================================
# Helper functions
# =============================================================
def safe_read_csv(src_path):
    """Safe CSV read by copying file first. Returns empty DataFrame on any problem."""
    if not os.path.exists(src_path):
        return pd.DataFrame()
    try:
        temp_path = src_path + ".tmp"
        shutil.copyfile(src_path, temp_path)
        df = pd.read_csv(temp_path, low_memory=False)
        os.remove(temp_path)
        return df
    except Exception as e:
        print(f"[WARN] safe_read_csv failed for {src_path}: {e}")
        return pd.DataFrame()

def load_alerts():
    df = safe_read_csv(ALERT_FILE)
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["timestamp", "type", "ip_or_domain", "details"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").fillna(pd.Timestamp.now())
    return df.sort_values("timestamp").reset_index(drop=True)

def load_protocol_summary():
    df = safe_read_csv(PROTO_FILE)
    if df.empty or "protocol" not in df.columns or "count" not in df.columns:
        return pd.DataFrame({"protocol": [], "count": []})
    df['count'] = pd.to_numeric(df['count'], errors='coerce').fillna(0).astype(int)
    return df.sort_values('count', ascending=False).reset_index(drop=True)

def load_http_metadata():
    df = safe_read_csv(HTTP_FILE)
    if df.empty or "host" not in df.columns:
        return pd.DataFrame(columns=["timestamp", "src", "dst", "host", "uri", "user_agent"])
    return df.sort_values("timestamp").reset_index(drop=True)

def load_syn_activity():
    df = safe_read_csv(SYN_FILE)
    if df.empty or "src_ip" not in df.columns:
        return pd.DataFrame(columns=["src_ip", "syn_count", "timestamp", "severity"])
    return df.sort_values("syn_count", ascending=False).reset_index(drop=True)

def file_mtime(path):
    try:
        return os.path.getmtime(path)
    except Exception:
        return None

def downsample_timeseries(df, ts_col='timestamp', max_points=300):
    """Downsample a timeline if it has too many points."""
    if df.empty or len(df) <= max_points:
        return df
    n = len(df)
    idx = [0] + list(sorted({int(i) for i in
                             (pd.np.linspace(1, n-2, max_points-2))})) + [n-1]
    idx = sorted(set(i if i < n else n-1 for i in idx))
    return df.iloc[idx].reset_index(drop=True)

# =============================================================
# Layout
# =============================================================
app.layout = html.Div([
    html.Div([
        html.H2("⚡ CCNS Project: Network Hijack Detection Dashboard"),
        html.H5("Real-Time Monitoring | ARP Spoof • DNS Hijack • HTTP Sniff • SYN Flood")
    ], style=HEADER_STYLE),

    html.Div(id='metrics', style={
        'display': 'flex',
        'justifyContent': 'space-around',
        'marginBottom': '20px',
        'flexWrap': 'wrap'
    }),

    # ---- FIRST ROW ----
    html.Div([
        html.Div([
            html.H4("🛑 Recent Alerts", style={'textAlign': 'center', 'color': '#d32f2f'}),
            dash_table.DataTable(
                id='alerts-table', page_size=12,
                style_table={'overflowX': 'auto'},
                style_header={'backgroundColor': '#e3f2fd', 'fontWeight': 'bold'},
                style_cell={'textAlign': 'left', 'padding': '6px', 'fontFamily': 'Consolas'}
            )
        ], style={**CARD_STYLE, 'width': '58%'}),

        html.Div([
            html.H4("📊 Protocol Distribution", style={'textAlign': 'center', 'color': '#1976d2'}),
            dcc.Graph(id='proto-graph', config={'displayModeBar': False}, style={'height': '420px'})
        ], style={**CARD_STYLE, 'width': '40%'})
    ], style={'display': 'flex', 'justifyContent': 'space-between', 'gap': '1.5%'}),

    # ---- SECOND ROW ----
    html.Div([
        html.Div([
            html.H4("⚠️ Duplicate IP–MAC Mapping (Spoof Evidence)", style={'textAlign': 'center', 'color': '#f57c00'}),
            dash_table.DataTable(
                id='ipmac-table', page_size=8,
                style_table={'overflowX': 'auto'},
                style_header={'backgroundColor': '#e3f2fd', 'fontWeight': 'bold'},
                style_cell={'textAlign': 'left', 'padding': '6px'}
            )
        ], style={**CARD_STYLE, 'width': '49%'}),

        html.Div([
            html.H4("📈 Spoofing Intensity (Full History)", style={'textAlign': 'center', 'color': '#0288d1'}),
            dcc.Graph(id='alert-timeline', config={'displayModeBar': False}, style={'height': '420px'})
        ], style={**CARD_STYLE, 'width': '49%'})
    ], style={'display': 'flex', 'justifyContent': 'space-between', 'gap': '1.5%'}),

    # ---- THIRD ROW ----
    html.Div([
        html.Div([
            html.H4("🌐 HTTP Metadata Extracted (What Attackers Can Sniff)", style={'textAlign': 'center', 'color': '#6a1b9a'}),
            dash_table.DataTable(
                id='http-table', page_size=8,
                style_table={'overflowX': 'auto', 'height': '280px'},
                style_header={'backgroundColor': '#f3e5f5', 'fontWeight': 'bold'},
                style_cell={'textAlign': 'left', 'padding': '5px', 'fontFamily': 'Consolas'}
            )
        ], style={**CARD_STYLE, 'width': '49%'}),

        html.Div([
            html.H4("⚔️ SYN Activity Summary (Possible Flood/Scan Sources)", style={'textAlign': 'center', 'color': '#ad1457'}),
            dash_table.DataTable(
                id='syn-table', page_size=8,
                style_table={'overflowX': 'auto', 'height': '280px'},
                style_header={'backgroundColor': '#ffebee', 'fontWeight': 'bold'},
                style_cell={'textAlign': 'left', 'padding': '5px', 'fontFamily': 'Consolas'}
            )
        ], style={**CARD_STYLE, 'width': '49%'})
    ], style={'display': 'flex', 'justifyContent': 'space-between', 'gap': '1.5%'}),

    html.Div(id='last-updated', style={
        'textAlign': 'center',
        'marginTop': '15px',
        'fontStyle': 'italic',
        'color': '#555',
        'fontSize': '13px'
    }),

    html.Div("© 2025 CCNS Project | SRM Network Defense Suite", style=FOOTER_STYLE),

    dcc.Interval(id='interval', interval=5000, n_intervals=0)
], style=APP_STYLE)

# =============================================================
# Callback
# =============================================================
@app.callback(
    Output('metrics', 'children'),
    Output('alerts-table', 'data'),
    Output('alerts-table', 'columns'),
    Output('proto-graph', 'figure'),
    Output('ipmac-table', 'data'),
    Output('ipmac-table', 'columns'),
    Output('alert-timeline', 'figure'),
    Output('http-table', 'data'),
    Output('http-table', 'columns'),
    Output('syn-table', 'data'),
    Output('syn-table', 'columns'),
    Output('last-updated', 'children'),
    Input('interval', 'n_intervals')
)
def update_dashboard(n):
    alerts = load_alerts()
    proto = load_protocol_summary()
    http = load_http_metadata()
    syn = load_syn_activity()

    # ---- Metrics ----
    total_pkts = int(proto['count'].sum()) if not proto.empty else 0
    alert_count = len(alerts)
    status = "🟢 Active" if alert_count > 0 else "⚪ Idle"
    spoof_ratio = round((alert_count / (total_pkts + 1)) * 100, 2)

    metrics = [
        ("Total Packets", total_pkts, "#1976d2"),
        ("Alerts", alert_count, "#d32f2f"),
        ("Spoof Ratio", f"{spoof_ratio}%", "#f57c00"),
        ("Status", status, "#388e3c")
    ]
    metric_cards = [html.Div([
        html.H4(name),
        html.H2(str(val), style={'color': color})
    ], style={**CARD_STYLE, 'width': '22%', 'textAlign': 'center'}) for name, val, color in metrics]

    # ---- Alerts table ----
    alerts_table = alerts.tail(25).copy()
    if not alerts_table.empty:
        alerts_table['timestamp'] = pd.to_datetime(alerts_table['timestamp'], errors='coerce').dt.strftime("%Y-%m-%d %H:%M:%S")
    alerts_cols = [{"name": c, "id": c} for c in alerts_table.columns]

    # ---- Protocol Graph ----
    if not proto.empty:
        pmax = max(5, int(proto['count'].max() * 1.2))
        fig_proto = px.bar(proto, x='protocol', y='count', text='count',
                           color='protocol', color_discrete_sequence=px.colors.qualitative.Safe)
        fig_proto.update_traces(textposition='auto')
        fig_proto.update_layout(height=400, margin=dict(l=30, r=30, t=40, b=20),
                                plot_bgcolor='#ffffff', paper_bgcolor='#ffffff',
                                yaxis=dict(range=[0, pmax], fixedrange=True))
    else:
        fig_proto = px.bar(title="No Protocol Data Available")

        # ---- IP–MAC Table (fixed multiple rows) ----
    ipmac_pairs = []
    for _, row in alerts.iterrows():
        details = str(row.get("details", ""))
        if "MACs" in details:
            ip = row.get("ip_or_domain", "").strip()
            macs_str = details.split("MACs", 1)[1].lstrip(": ").strip()
            mac_candidates = [mac.strip() for mac in macs_str.replace(",", ";").split(";") if mac.strip()]
            for mac in mac_candidates:
                ipmac_pairs.append({"IP": ip, "MAC": mac})

    ipmac_df = pd.DataFrame(ipmac_pairs).drop_duplicates().reset_index(drop=True)
    if not ipmac_df.empty:
        ipmac_df = ipmac_df.sort_values(["IP", "MAC"]).reset_index(drop=True)
    ipmac_cols = [{"name": c, "id": c} for c in ipmac_df.columns]


    # ---- Spoofing Intensity Trend ----
    if not alerts.empty:
        alerts_ts = pd.to_datetime(alerts['timestamp'], errors='coerce').dt.floor('min')
        timeline = alerts_ts.value_counts().sort_index().reset_index(name='count')
        timeline.columns = ['timestamp', 'count']
        timeline = downsample_timeseries(timeline, max_points=500)
        ymax = max(5, int(timeline['count'].max() * 1.2))
        fig_time = px.line(timeline, x='timestamp', y='count', markers=True, color_discrete_sequence=['#1976d2'])
        fig_time.update_layout(height=420, plot_bgcolor='#ffffff', paper_bgcolor='#ffffff',
                               yaxis=dict(range=[0, ymax], fixedrange=True),
                               xaxis_title='Time', yaxis_title='Alerts per minute')
    else:
        fig_time = px.line(title="No Recent Alerts Available")

    # ---- HTTP & SYN tables ----
    http_table = http.tail(25)
    http_cols = [{"name": c, "id": c} for c in http_table.columns]
    syn_table = syn.copy()
    syn_cols = [{"name": c, "id": c} for c in syn_table.columns]

    last_update = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    return (metric_cards, alerts_table.to_dict('records'), alerts_cols,
            fig_proto, ipmac_df.to_dict('records'), ipmac_cols,
            fig_time, http_table.to_dict('records'), http_cols,
            syn_table.to_dict('records'), syn_cols, last_update)

# =============================================================
# Run
# =============================================================
if _name_ == '_main_':
    print("🚀 Dashboard running on http://127.0.0.1:8050")
    app.run(debug=False, port=8050, use_reloader=False)