from pathlib import Path
import json
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st

# =========================================================
# Cowrie Security Dashboard — Old Photograph theme
# =========================================================

CREAM = "#FDFBD4"
BEIGE = "#D9D7B6"
GRAY = "#878672"
OLIVE = "#505037"
BORDER = "#B8B59A"
WHITE = "#FFFFFF"

DEFAULT_LOG = Path.home() / "cowrie" / "var" / "log" / "cowrie.json"

st.set_page_config(
    page_title="Cowrie Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    f"""
    <style>
    :root {{
        color-scheme: light;
    }}
    .stApp {{
        background-color: {CREAM};
        color: {OLIVE};
    }}
    [data-testid="stSidebar"] {{
        background-color: {BEIGE};
    }}
    [data-testid="stHeader"] {{
        background-color: {CREAM};
    }}
    h1, h2, h3, h4, p, label, span, li,
    [data-testid="stMarkdownContainer"],
    [data-testid="stMetricLabel"],
    [data-testid="stMetricValue"],
    [data-testid="stMetricDelta"] {{
        color: {OLIVE};
    }}
    [data-testid="stMetric"] {{
        background: {BEIGE};
        border: 1px solid {BORDER};
        padding: 14px;
        border-radius: 10px;
    }}
    div.stButton > button {{
        color: {CREAM};
        background-color: {OLIVE};
        border: 1px solid {OLIVE};
        border-radius: 8px;
    }}
    div.stButton > button:hover {{
        color: {OLIVE};
        background-color: {CREAM};
        border: 1px solid {OLIVE};
    }}
    input, textarea, [data-baseweb="select"] {{
        color: {OLIVE} !important;
    }}
    [data-testid="stDataFrame"] {{
        border: 1px solid {BORDER};
        border-radius: 8px;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


def discover_log():
    candidates = [
        DEFAULT_LOG,
        Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json"),
        Path.cwd() / "var/log/cowrie/cowrie.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return DEFAULT_LOG


def load_events(log_path):
    records = []
    invalid_lines = 0
    read_error = None

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        records.append(item)
                    else:
                        invalid_lines += 1
                except json.JSONDecodeError:
                    invalid_lines += 1
    except OSError as exc:
        read_error = str(exc)

    df = pd.json_normalize(records, sep="_") if records else pd.DataFrame()
    if not df.empty:
        if "eventid" not in df.columns:
            df["eventid"] = "unknown"
        df["eventid"] = df["eventid"].fillna("unknown").astype(str)

        for col in ("src_ip", "username", "timestamp", "message", "session"):
            if col not in df.columns:
                df[col] = ""

        df["src_ip"] = df["src_ip"].fillna("Unknown").astype(str)
        df.loc[df["src_ip"].eq(""), "src_ip"] = "Unknown"
        df["username"] = df["username"].fillna("").astype(str)
        df["timestamp_parsed"] = pd.to_datetime(
            df["timestamp"], errors="coerce", utc=True
        )
        df = df.sort_values("timestamp_parsed", na_position="last")
    return df, invalid_lines, read_error


def style_fig(fig, height=340):
    fig.update_layout(
        height=height,
        paper_bgcolor=CREAM,
        plot_bgcolor=BEIGE,
        font=dict(family="Arial, sans-serif", color=OLIVE, size=13),
        title_font=dict(color=OLIVE, size=17),
        margin=dict(l=25, r=20, t=55, b=35),
        legend=dict(
            bgcolor=BEIGE,
            bordercolor=BORDER,
            borderwidth=1,
            font=dict(color=OLIVE, size=12),
        ),
    )
    fig.update_xaxes(
        color=OLIVE,
        title_font=dict(color=OLIVE),
        tickfont=dict(color=OLIVE),
        gridcolor=BORDER,
        linecolor=OLIVE,
        zerolinecolor=GRAY,
    )
    fig.update_yaxes(
        color=OLIVE,
        title_font=dict(color=OLIVE),
        tickfont=dict(color=OLIVE),
        gridcolor=BORDER,
        linecolor=OLIVE,
        zerolinecolor=GRAY,
    )
    return fig


def show_chart(fig, key):
    st.plotly_chart(style_fig(fig), use_container_width=True, key=key)


def safe_display(df):
    """Remove secrets and keep only useful, safe columns for display."""
    if df.empty:
        return df
    hidden = {
        "password", "password_text", "input", "client_version",
        "kex", "uuid", "timestamp_parsed",
    }
    result = df.drop(columns=[c for c in hidden if c in df.columns], errors="ignore")
    preferred = [
        "timestamp", "eventid", "src_ip", "src_port", "dst_ip",
        "dst_port", "username", "session", "duration_ms", "message",
    ]
    cols = [c for c in preferred if c in result.columns]
    if not cols:
        cols = list(result.columns[:10])
    return result[cols].copy()


# Sidebar controls
st.sidebar.markdown("# 🛡 COWRIE")
st.sidebar.markdown("### Security Intelligence")
st.sidebar.caption("Local honeypot event monitoring")
st.sidebar.divider()

default_path = str(discover_log())
log_path_text = st.sidebar.text_input(
    "Cowrie JSON log path",
    value=default_path,
    help="Path to Cowrie's newline-delimited cowrie.json file.",
)
if st.sidebar.button("↻ Refresh dashboard", use_container_width=True):
    st.rerun()

st.sidebar.caption("Only monitor systems you own or are authorized to assess.")
st.sidebar.markdown("---")
st.sidebar.caption("Theme: Old Photograph")

st.title("🛡 Cowrie Security Dashboard")
st.write("SSH honeypot activity, authentication events, source IPs and commands.")

log_path = Path(log_path_text).expanduser()
df, invalid_lines, read_error = load_events(log_path)

if read_error:
    st.error(f"Could not read the log file: {read_error}")
    st.info("Check the path and the account's read permissions.")
    st.stop()

if not log_path.is_file():
    st.error("Cowrie JSON log file was not found.")
    st.code(str(log_path))
    st.info("Enter the correct path in the sidebar.")
    st.stop()

if df.empty:
    st.warning("The log file exists, but no valid event records were found.")
    st.caption(f"File: {log_path}")
    st.stop()

# Filters
with st.expander("Filters", expanded=False):
    event_options = sorted(df["eventid"].dropna().unique().tolist())
    selected_events = st.multiselect(
        "Event types",
        event_options,
        default=event_options,
    )
    ip_options = sorted(df["src_ip"].dropna().unique().tolist())
    selected_ips = st.multiselect("Source IPs", ip_options, default=ip_options)
    time_filter = st.selectbox(
        "Time range",
        ["All available logs", "Last 24 hours", "Last 7 days", "Last 30 days"],
    )

filtered = df.copy()
if selected_events:
    filtered = filtered[filtered["eventid"].isin(selected_events)]
else:
    filtered = filtered.iloc[0:0]
if selected_ips:
    filtered = filtered[filtered["src_ip"].isin(selected_ips)]
else:
    filtered = filtered.iloc[0:0]

if time_filter != "All available logs":
    days = {"Last 24 hours": 1, "Last 7 days": 7, "Last 30 days": 30}[time_filter]
    latest = df["timestamp_parsed"].max()
    if pd.notna(latest):
        filtered = filtered[
            filtered["timestamp_parsed"] >= latest - pd.Timedelta(days=days)
        ]

success_count = int(filtered["eventid"].eq("cowrie.login.success").sum())
failed_count = int(filtered["eventid"].eq("cowrie.login.failed").sum())
command_count = int(filtered["eventid"].eq("cowrie.command.input").sum())
unique_ips = int(
    filtered.loc[filtered["src_ip"].ne("Unknown"), "src_ip"].nunique()
)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Events", f"{len(filtered):,}")
m2.metric("Successful Logins", f"{success_count:,}")
m3.metric("Failed Logins", f"{failed_count:,}")
m4.metric("Unique Source IPs", f"{unique_ips:,}")
m5.metric("Command Events", f"{command_count:,}")

st.caption(
    f"Log file: {log_path} · Valid events: {len(df)} · "
    f"Invalid JSON lines: {invalid_lines}"
)
if invalid_lines:
    st.warning(f"{invalid_lines} line(s) could not be parsed as JSON.")

st.divider()

left, right = st.columns(2)
with left:
    st.subheader("Event Type Distribution")
    event_counts = filtered["eventid"].value_counts().rename_axis("Event").reset_index(name="Count")
    if not event_counts.empty:
        fig = px.bar(event_counts, x="Event", y="Count", text="Count")
        fig.update_traces(marker_color=OLIVE, textfont_color=OLIVE)
        fig.update_xaxes(tickangle=-30)
        show_chart(fig, "event_distribution")
    else:
        st.info("No events match the selected filters.")

with right:
    st.subheader("Login Activity")
    login_mask = filtered["eventid"].isin(
        ["cowrie.login.success", "cowrie.login.failed"]
    )
    login_df = filtered[login_mask].copy()
    if not login_df.empty:
        login_df["Result"] = login_df["eventid"].map({
            "cowrie.login.success": "Successful",
            "cowrie.login.failed": "Failed",
        })
        result_counts = login_df["Result"].value_counts().rename_axis("Result").reset_index(name="Count")
        fig = px.bar(result_counts, x="Result", y="Count", color="Result", text="Count",
                     color_discrete_map={"Successful": "#505037", "Failed": "#A34B3F"})
        fig.update_traces(textfont_color=OLIVE)
        show_chart(fig, "login_activity")
    else:
        st.info("No login success/failure events in the selected data.")

left, right = st.columns(2)
with left:
    st.subheader("Top Source IPs")
    ip_counts = filtered.loc[filtered["src_ip"].ne("Unknown"), "src_ip"].value_counts().head(10)
    if not ip_counts.empty:
        ip_df = ip_counts.rename_axis("Source IP").reset_index(name="Events")
        fig = px.bar(ip_df, x="Events", y="Source IP", orientation="h", text="Events")
        fig.update_traces(marker_color=OLIVE, textfont_color=OLIVE)
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        show_chart(fig, "top_source_ips")
    else:
        st.info("No source IP values available.")

with right:
    st.subheader("Most Targeted Usernames")
    login_user_df = filtered[
        filtered["eventid"].isin(["cowrie.login.success", "cowrie.login.failed"])
        & filtered["username"].ne("")
    ]
    if not login_user_df.empty:
        user_counts = login_user_df["username"].value_counts().head(10).rename_axis("Username").reset_index(name="Attempts")
        fig = px.bar(user_counts, x="Username", y="Attempts", text="Attempts")
        fig.update_traces(marker_color=GRAY, textfont_color=OLIVE)
        show_chart(fig, "username_activity")
    else:
        st.info("No username-related login events available.")

st.subheader("Command Activity")
command_df = filtered[filtered["eventid"].eq("cowrie.command.input")].copy()
if not command_df.empty:
    # Do not render raw command input by default; show event counts and metadata.
    command_summary = command_df.groupby("src_ip").size().rename("Command Events").reset_index()
    fig = px.bar(command_summary, x="src_ip", y="Command Events", text="Command Events")
    fig.update_traces(marker_color=OLIVE, textfont_color=OLIVE)
    fig.update_layout(xaxis_title="Source IP", yaxis_title="Number of command events")
    show_chart(fig, "command_activity")
    st.caption("Raw command contents are omitted from this chart.")
else:
    st.info("No command input events in the selected data.")

st.subheader("Recent Security Events")
recent = filtered.sort_values("timestamp_parsed", ascending=False, na_position="last").head(25)
display_df = safe_display(recent)
if not display_df.empty:
    st.dataframe(display_df, use_container_width=True, hide_index=True)
else:
    st.info("No recent events to display.")

with st.expander("Data quality and field availability"):
    st.write(f"Parsed events: {len(df)}")
    st.write(f"Invalid JSON lines: {invalid_lines}")
    st.write("Available fields:")
    st.code(", ".join(sorted(df.columns)))
    st.caption("Sensitive fields such as passwords are excluded from the event table.")
