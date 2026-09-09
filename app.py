import importlib
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from PIL import Image

import es_service
importlib.reload(es_service)
from es_service import fetch_cve_data, fetch_priority_cves, fetch_summary_stats  # noqa: E402

ES_INDEX = "list-cve"
TABLE_ROW_LIMIT = 1000
VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
LOGO_FILE = Path(__file__).resolve().parent / "logo_bssn.png"

try:
    APP_VERSION = VERSION_FILE.read_text(encoding="utf-8").strip() or "unknown"
except Exception:
    APP_VERSION = "unknown"

# One severity palette for metrics, sparklines, charts and tables.
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLORS = {
    "CRITICAL": "#FF2B2B",
    "HIGH": "#FF9800",
    "MEDIUM": "#FFEB3B",
    "LOW": "#00E676",
}
STATUS_OPTIONS = [
    "Received", "Awaiting Analysis", "Undergoing Analysis",
    "Analyzed", "Modified", "Deferred", "Rejected",
]
CVSS_VERSION_OPTIONS = ["3.1", "3.0", "2.0"]
FIRST_CVE_YEAR = 1988
YEAR_OPTIONS = ["All"] + [str(y) for y in range(datetime.now().year, FIRST_CVE_YEAR - 1, -1)]
PRIORITY_SORT_OPTIONS = {
    "KEV first, then CVSS, then EPSS": "kev",
    "Highest CVSS score": "score",
    "Highest EPSS probability": "epss",
}
INTERVAL_LABEL_FORMAT = {
    "year": "%Y",
    "month": "%Y-%m",
    "week": "%Y-%m-%d",
    "day": "%Y-%m-%d",
    "hour": "%H:00",
}
CHART_BG = "#262730"
ACCENT = "#00D4FF"

# --- Page Config ---
try:
    favicon = Image.open(LOGO_FILE)
except Exception:
    favicon = "🛡️"

st.set_page_config(
    page_title="CVE Intelligence Dashboard",
    page_icon=favicon,
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .block-container { padding-top: 2rem; }
    h1 { font-size: 2.2rem !important; }
    div[data-testid="stMetricLabel"] { color: #A3A8B8; }
    div[data-testid="stMetricValue"] { color: #00D4FF; }
    /* Bordered containers act as cards */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #262730;
        border: 1px solid #363945;
        border-radius: 8px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
</style>
""",
    unsafe_allow_html=True,
)

# --- Session State ---
TODAY = pd.Timestamp.now().date()
FILTER_DEFAULTS = {
    "timezone_mode": "UTC",
    "status_filter": [],
    "filter_mode": "All Time",
    "selected_date": TODAY,
    "start_date_range": TODAY - pd.Timedelta(days=7),
    "end_date_range": TODAY,
    "cve_status_type": "Published (New)",
    "severity_filter": [],
    "vendor_filter": "",
    "product_filter": "",
    "cwe_filter": "",
    "cvss_version_filter": [],
    "score_range": (0.0, 10.0),
    "kev_filter": False,
    "epss_range": (0.0, 1.0),
    "selected_year": "All",
    "main_search": "",
}
for key, value in FILTER_DEFAULTS.items():
    st.session_state.setdefault(key, value)
st.session_state.setdefault("chart_nonce", 0)

# Chart clicks cannot write to a widget's session-state key after the widget has been
# rendered, so they queue the change here and it is applied at the top of the next run.
pending_update = st.session_state.pop("pending_filter_update", None)
if pending_update:
    for key, value in pending_update.items():
        st.session_state[key] = value


def request_filter_update(**changes):
    st.session_state.pending_filter_update = changes
    # A new key gives the clicked chart a fresh (empty) selection on the next run.
    st.session_state.chart_nonce += 1
    st.rerun()


def toggle_value(key, value):
    """Toggle a single-valued filter (vendor, product, CWE)."""
    request_filter_update(**{key: "" if st.session_state[key] == value else value})


def toggle_in_list(key, value):
    """Toggle membership in a multi-valued filter (severity)."""
    current = list(st.session_state[key])
    if value in current:
        current.remove(value)
    else:
        current.append(value)
    request_filter_update(**{key: current})


def reset_filters_callback():
    for key, value in FILTER_DEFAULTS.items():
        if key != "timezone_mode":
            st.session_state[key] = value
    st.session_state.chart_nonce += 1


def set_daily_filter(mode_type):
    st.session_state.filter_mode = "Specific Date"
    st.session_state.selected_date = TODAY
    st.session_state.cve_status_type = "Published (New)" if mode_type == "new" else "Modified (Updated)"


# --- Sidebar ---
with st.sidebar:
    col_center = st.columns([1, 2, 1])
    with col_center[1]:
        try:
            st.image(Image.open(LOGO_FILE), width=110)
        except Exception:
            pass

    st.markdown(
        """
        <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="margin:0; padding:0; font-size: 1.5em;">CVE Explorer</h2>
            <p style="margin:0; padding:0; color: #A3A8B8; font-size: 0.9em;">Badan Siber dan Sandi Negara</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.subheader("Filters")

    st.radio("Timezone Display", ["UTC", "WIB"], horizontal=True, key="timezone_mode",
             format_func=lambda v: "WIB (UTC+7)" if v == "WIB" else v)

    st.markdown("---")
    st.multiselect("Vulnerability Status", options=STATUS_OPTIONS, key="status_filter")

    st.radio("Observation Mode", ["All Time", "Specific Date", "Date Range"], key="filter_mode")

    selected_date = None
    date_field = "published"
    if st.session_state.filter_mode != "All Time":
        if st.session_state.filter_mode == "Specific Date":
            selected_date = st.date_input("Select Date", key="selected_date")
        else:
            d_col1, d_col2 = st.columns(2)
            with d_col1:
                start_d = st.date_input("Start Date", key="start_date_range")
            with d_col2:
                end_d = st.date_input("End Date", key="end_date_range")
            selected_date = (start_d, end_d)

        st.radio("CVE Status Type", ["Published (New)", "Modified (Updated)"], key="cve_status_type")
        date_field = "published" if "New" in st.session_state.cve_status_type else "lastModified"

    st.markdown("---")
    st.markdown("**Severity Level**")
    st.multiselect("Select Severity", options=SEV_ORDER, key="severity_filter",
                   help="Leave empty to select ALL")

    st.markdown("---")
    st.markdown("**Affected Components**")
    st.text_input("Vendor Name", key="vendor_filter", placeholder="e.g. Microsoft, Apache")
    st.text_input("Product Name", key="product_filter", placeholder="e.g. Exchange Server")
    st.text_input("Weakness (CWE ID)", key="cwe_filter", placeholder="e.g. CWE-79",
                  help="Exact CWE id. Clicking a bar in the Top Weaknesses chart fills this in.")

    st.markdown("---")
    st.markdown("**Risk Scoring**")
    st.multiselect("CVSS Version", CVSS_VERSION_OPTIONS, key="cvss_version_filter",
                   help="Filter by the CVSS version used for the base score")
    st.slider("CVSS Base Score", 0.0, 10.0, step=0.1, key="score_range",
              help="Leave at 0-10 to include CVEs that have no score yet")

    st.markdown("---")
    st.markdown("**Threat Intelligence**")
    st.checkbox("Has CISA KEV", key="kev_filter", help="Known Exploited Vulnerabilities")
    st.slider("EPSS Probability", 0.0, 1.0, step=0.01, key="epss_range",
              help="Exploit Prediction Scoring System")

    st.markdown("---")
    st.selectbox("Year Filter", YEAR_OPTIONS, key="selected_year",
                 help="Filter by year on the selected date field")
    st.caption(f"Elasticsearch index: {ES_INDEX}")

    st.text_input("Search", placeholder="CVE-ID or Description...", key="main_search")
    st.button("Reset Filters", type="primary", on_click=reset_filters_callback)

# Every query (table, stats, watchlist) receives this same dict, which is also the cache key.
active_filters = dict(
    search_text=st.session_state.main_search or None,
    severity_filter=st.session_state.severity_filter or None,
    date_filter=selected_date if st.session_state.filter_mode != "All Time" else None,
    date_field=date_field,
    score_range=st.session_state.score_range,
    kev_filter=st.session_state.kev_filter,
    epss_range=st.session_state.epss_range,
    vendor_filter=st.session_state.vendor_filter or None,
    product_filter=st.session_state.product_filter or None,
    cwe_filter=st.session_state.cwe_filter or None,
    cvss_version_filter=st.session_state.cvss_version_filter or None,
    status_filter=st.session_state.status_filter or None,
    year_filter=st.session_state.selected_year if st.session_state.selected_year != "All" else None,
)


# --- Data Loading ---
def _to_display_tz(series, timezone_mode):
    converted = pd.to_datetime(series, errors="coerce", utc=True)
    if timezone_mode == "WIB":
        converted = converted.dt.tz_convert("Asia/Jakarta")
    return converted


@st.cache_data(ttl=600)
def load_data(timezone_mode, **filters):
    try:
        df, total_hits = fetch_cve_data(index_pattern=ES_INDEX, size=TABLE_ROW_LIMIT, **filters)
        for col in ("published", "lastModified"):
            if col in df.columns:
                df[col] = _to_display_tz(df[col], timezone_mode)
        return df, total_hits, None
    except Exception as e:
        return None, 0, str(e)


@st.cache_data(ttl=600)
def load_stats(**filters):
    try:
        return fetch_summary_stats(index_pattern=ES_INDEX, **filters), None
    except Exception as e:
        return None, str(e)


@st.cache_data(ttl=600)
def load_priority(sort_mode, size, timezone_mode, **filters):
    try:
        df = fetch_priority_cves(index_pattern=ES_INDEX, size=size, sort_mode=sort_mode, **filters)
        for col in ("published", "lastModified", "cisaActionDue"):
            if col in df.columns:
                df[col] = _to_display_tz(df[col], timezone_mode)
        return df, None
    except Exception as e:
        return None, str(e)


@st.cache_data(ttl=300)
def load_today_metrics():
    today_str = pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d")
    try:
        _, new_count = fetch_cve_data(index_pattern=ES_INDEX, size=1, date_filter=today_str, date_field="published")
        _, mod_count = fetch_cve_data(index_pattern=ES_INDEX, size=1, date_filter=today_str, date_field="lastModified")
        return new_count, mod_count, None
    except Exception as e:
        return 0, 0, str(e)


# --- Chart helpers ---
def style_fig(fig, height=None, **layout):
    layout.setdefault("margin", dict(t=30, b=10, l=10, r=10))
    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor=CHART_BG,
        **layout,
    )
    if height:
        fig.update_layout(height=height)
    return fig


def chart_title(text):
    st.markdown(f"#### {text}")


def clicked_point_index(fig, chart_id):
    """Render a selectable chart and return the clicked point index, or None."""
    event = st.plotly_chart(
        fig,
        use_container_width=True,
        theme=None,
        on_select="rerun",
        selection_mode="points",
        key=f"{chart_id}_{st.session_state.chart_nonce}",
        config={"displayModeBar": False},
    )
    try:
        points = event["selection"]["points"]
    except (KeyError, TypeError):
        points = []
    if points:
        return points[0].get("point_index")
    return None


def make_sparkline(data, color):
    if not isinstance(data, list) or not data:
        data = [0] * 10
    c = color.lstrip("#")
    rgb = tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))
    fig = go.Figure(
        data=go.Scatter(
            y=data,
            mode="lines",
            fill="tozeroy",
            line=dict(color=color, width=2),
            fillcolor=f"rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, 0.2)",
        )
    )
    fig.update_layout(
        template="plotly_dark",
        showlegend=False,
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=0, b=0, l=0, r=0),
        height=40,
        xaxis=dict(visible=False, fixedrange=True),
        yaxis=dict(visible=False, fixedrange=True),
    )
    return fig


def horizontal_bar(df, y_label, color):
    fig = px.bar(df, x="doc_count", y="key", orientation="h",
                 labels={"doc_count": "Count", "key": y_label}, text="doc_count")
    fig.update_traces(marker_color=color, textposition="outside", cliponaxis=False)
    return style_fig(fig, yaxis={"categoryorder": "total ascending"})


def parse_nested_timeline(agg_data):
    rows = []
    for bucket in agg_data["buckets"]:
        for time_bucket in bucket["history"]["buckets"]:
            rows.append({
                "Name": bucket["key"],
                "Year": pd.to_datetime(time_bucket["key_as_string"]).year,
                "Count": time_bucket["doc_count"],
            })
    return pd.DataFrame(rows)


def trend_line(df, title):
    fig = px.line(df, x="Year", y="Count", color="Name", markers=True, title=title)
    return style_fig(fig, xaxis_type="category", hovermode="x unified", margin=dict(t=40, b=10, l=10, r=10))


def nvd_link_config(label="NVD"):
    return st.column_config.LinkColumn(label, display_text="Open", width="small")


# --- Load everything ---
df_cves, total_cves, error_msg = load_data(st.session_state.timezone_mode, **active_filters)
stats_aggs, stats_error = load_stats(**active_filters)
new_today, mod_today, today_error = load_today_metrics()

# --- Header ---
c_header, c_ctx = st.columns([3, 2], vertical_alignment="center")
with c_header:
    st.title("Vulnerability Intelligence Center")
    mode = st.session_state.filter_mode
    if mode == "Specific Date":
        context_str = str(st.session_state.selected_date)
    elif mode == "Date Range" and isinstance(selected_date, tuple):
        context_str = f"{selected_date[0]} to {selected_date[1]}"
    else:
        context_str = "All Time"
    field_label = "published" if date_field == "published" else "last modified"
    st.caption(f"Context: **{context_str}** by {field_label} date · {st.session_state.timezone_mode}")

with c_ctx:
    t1, t2 = st.columns(2)
    with t1, st.container(border=True):
        st.metric("Published today", f"{new_today:,}")
        st.button("View", key="btn_today_new", on_click=set_daily_filter, args=("new",), use_container_width=True)
    with t2, st.container(border=True):
        st.metric("Modified today", f"{mod_today:,}")
        st.button("View", key="btn_today_mod", on_click=set_daily_filter, args=("mod",), use_container_width=True)
    st.caption("Today's activity in UTC. View switches the filters to today.")

st.divider()

if error_msg:
    st.error(f"Failed to connect to Elasticsearch: {error_msg}")
    st.stop()
if stats_error:
    st.warning(f"Charts unavailable: {stats_error}")

# --- Metrics ---
sev_counts = {s: 0 for s in SEV_ORDER}
spark_data = {s: [0] * 10 for s in SEV_ORDER}
cnt_kev = cnt_vendors = cnt_products = 0

if stats_aggs:
    for b in stats_aggs["severity_counts"]["buckets"]:
        sev_counts[b["key"]] = b["doc_count"]
    cnt_kev = stats_aggs.get("kev_count", {}).get("doc_count", 0)
    cnt_vendors = stats_aggs.get("unique_vendors", {}).get("value", 0)
    cnt_products = stats_aggs.get("unique_products", {}).get("value", 0)
    for bucket in stats_aggs.get("severity_over_time", {}).get("buckets", []):
        history = [h["doc_count"] for h in bucket["history"]["buckets"]]
        if len(history) > 15:
            history = history[-15:]
        elif len(history) < 2:
            history = [0] * 5 + history
        spark_data[bucket["key"]] = history

st.subheader("Severity Overview")
for col, sev in zip(st.columns(4), SEV_ORDER):
    with col:
        with st.container(border=True):
            st.metric(sev, f"{sev_counts.get(sev, 0):,}")
            st.plotly_chart(make_sparkline(spark_data.get(sev), SEV_COLORS[sev]),
                            use_container_width=True, config={"displayModeBar": False},
                            key=f"spark_{sev}")

st.subheader("Impact & Scope")
impact_metrics = [
    ("KEV Exploited", cnt_kev, "Listed in CISA Known Exploited Vulnerabilities"),
    ("Affected Vendors", cnt_vendors, None),
    ("Affected Products", cnt_products, None),
    ("Total Matching", total_cves, "CVEs matching the current filters"),
]
for col, (label, value, help_text) in zip(st.columns(4), impact_metrics):
    with col:
        with st.container(border=True):
            st.metric(label, f"{value:,}", help=help_text)

st.divider()

# --- Charts ---
st.subheader("Visual Analytics")

if stats_aggs:
    interval = stats_aggs.get("_interval", "year")
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Rankings", "Vendor Trends", "Product Trends"])

    with tab1:
        c1, c2 = st.columns([1, 2])

        with c1:
            chart_title("Severity Distribution")
            buckets = stats_aggs["severity_counts"]["buckets"]
            if buckets:
                sev_data = pd.DataFrame(buckets)
                fig_pie = px.pie(sev_data, values="doc_count", names="key", color="key",
                                 color_discrete_map=SEV_COLORS, hole=0.4)
                style_fig(fig_pie, showlegend=True,
                          legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5))
                idx = clicked_point_index(fig_pie, "sev_pie")
                if idx is not None and idx < len(sev_data):
                    toggle_in_list("severity_filter", sev_data.iloc[idx]["key"])
                st.caption("Click a slice to toggle that severity filter.")
            else:
                st.info("No severity data available.")

            chart_title("Status Distribution")
            stat_buckets = stats_aggs.get("vuln_status_counts", {}).get("buckets", [])
            if stat_buckets:
                fig_stat = px.pie(pd.DataFrame(stat_buckets), values="doc_count", names="key", hole=0.4,
                                  color_discrete_sequence=px.colors.qualitative.Set2)
                style_fig(fig_stat, showlegend=True,
                          legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5))
                st.plotly_chart(fig_stat, use_container_width=True, theme=None, key="status_pie")
            else:
                st.info("No status data available.")

        with c2:
            chart_title(f"Activity Trend (per {interval})")
            overview_buckets = stats_aggs["activity_over_time"]["buckets"]
            if overview_buckets:
                trend_data = pd.DataFrame(overview_buckets)
                trend_data["label"] = pd.to_datetime(trend_data["key_as_string"]).dt.strftime(
                    INTERVAL_LABEL_FORMAT.get(interval, "%Y-%m-%d"))
                fig_bar = px.bar(trend_data, x="label", y="doc_count",
                                 labels={"label": interval.capitalize(), "doc_count": "Count"})
                fig_bar.update_traces(marker_color=ACCENT)
                style_fig(fig_bar, xaxis_type="category")
                st.plotly_chart(fig_bar, use_container_width=True, theme=None, key="activity_bar")
            else:
                st.info("No timeline data available.")

            chart_title("CVSS Score Distribution")
            score_buckets = stats_aggs["score_histogram"]["buckets"]
            if score_buckets:
                fig_hist = px.bar(pd.DataFrame(score_buckets), x="key", y="doc_count",
                                  labels={"key": "Score", "doc_count": "Count"},
                                  color="key", color_continuous_scale="RdYlGn_r")
                style_fig(fig_hist, coloraxis_showscale=False)
                st.plotly_chart(fig_hist, use_container_width=True, theme=None, key="score_hist")

    with tab2:
        c_r1, c_r2 = st.columns(2)

        with c_r1:
            chart_title("Top 5 Vendors")
            v_buckets = stats_aggs.get("top_vendors", {}).get("buckets", [])
            if v_buckets:
                df_v = pd.DataFrame(v_buckets)
                idx = clicked_point_index(horizontal_bar(df_v, "Vendor", ACCENT), "vendor_bar")
                if idx is not None and idx < len(df_v):
                    toggle_value("vendor_filter", df_v.iloc[idx]["key"])
                st.caption("Click a bar to filter by that vendor.")
            else:
                st.info("No vendor data.")

        with c_r2:
            chart_title("Top 5 Products")
            p_buckets = stats_aggs.get("top_products", {}).get("buckets", [])
            if p_buckets:
                df_p = pd.DataFrame(p_buckets)
                idx = clicked_point_index(horizontal_bar(df_p, "Product", "#FF00FF"), "product_bar")
                if idx is not None and idx < len(df_p):
                    toggle_value("product_filter", df_p.iloc[idx]["key"])
                st.caption("Click a bar to filter by that product.")
            else:
                st.info("No product data.")

        chart_title("Top 5 Weaknesses (CWE)")
        w_buckets = stats_aggs.get("top_weaknesses", {}).get("buckets", [])
        if w_buckets:
            df_w = pd.DataFrame(w_buckets)
            idx = clicked_point_index(horizontal_bar(df_w, "CWE", "#FFA500"), "cwe_bar")
            if idx is not None and idx < len(df_w):
                toggle_value("cwe_filter", df_w.iloc[idx]["key"])
            st.caption("Click a bar to filter by that weakness. Placeholder entries (NVD-CWE-noinfo, NVD-CWE-Other) are excluded.")
        else:
            st.info("No weakness data.")

    with tab3:
        chart_title("Top 5 Vendors Over Time")
        if "top_vendors" in stats_aggs:
            df_vendor = parse_nested_timeline(stats_aggs["top_vendors"])
            if not df_vendor.empty:
                st.plotly_chart(trend_line(df_vendor, "Vulnerability Trends by Vendor"),
                                use_container_width=True, theme=None, key="vendor_trend")
            else:
                st.info("No vendor data found.")

    with tab4:
        chart_title("Top 5 Products Over Time")
        if "top_products" in stats_aggs:
            df_prod = parse_nested_timeline(stats_aggs["top_products"])
            if not df_prod.empty:
                st.plotly_chart(trend_line(df_prod, "Vulnerability Trends by Product"),
                                use_container_width=True, theme=None, key="product_trend")
            else:
                st.info("No product data found.")

st.divider()

# --- Priority Watchlist ---
st.subheader("Priority Watchlist")
st.caption("CVEs in the current filter ranked by exploitation risk. KEV = listed in CISA Known Exploited Vulnerabilities.")

pw_c1, pw_c2 = st.columns([4, 1])
with pw_c1:
    priority_sort_label = st.radio("Rank by", list(PRIORITY_SORT_OPTIONS.keys()), horizontal=True, key="priority_sort")
with pw_c2:
    priority_size = st.selectbox("Rows", [25, 50, 100, 250], index=1, key="priority_size")

df_priority, priority_error = load_priority(
    PRIORITY_SORT_OPTIONS[priority_sort_label], priority_size, st.session_state.timezone_mode, **active_filters
)

if priority_error:
    st.warning(f"Priority watchlist unavailable: {priority_error}")
elif df_priority is None or df_priority.empty:
    st.info("No CVEs found matching your criteria.")
else:
    df_priority = df_priority.copy()
    df_priority.insert(0, "rank", range(1, len(df_priority) + 1))
    df_priority["nvd"] = "https://nvd.nist.gov/vuln/detail/" + df_priority["id"].astype(str)
    df_priority["percentile"] = pd.to_numeric(df_priority["percentile"], errors="coerce") * 100

    st.dataframe(
        df_priority[[
            "rank", "id", "nvd", "hasCisa", "sev", "score", "epss", "percentile",
            "cisaActionDue", "vulnStatus", "published", "vendors", "products", "desc",
        ]],
        hide_index=True,
        use_container_width=True,
        height=min(60 + 35 * len(df_priority), 800),
        column_config={
            "rank": st.column_config.NumberColumn("#", width="small"),
            "id": st.column_config.TextColumn("CVE", width="medium"),
            "nvd": nvd_link_config(),
            "hasCisa": st.column_config.CheckboxColumn("KEV", width="small"),
            "sev": st.column_config.TextColumn("Severity", width="small"),
            "score": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
            "epss": st.column_config.ProgressColumn("EPSS", format="%.4f", min_value=0.0, max_value=1.0),
            "percentile": st.column_config.NumberColumn("EPSS %ile", format="%.1f%%", width="small"),
            "cisaActionDue": st.column_config.DateColumn("KEV Due", width="small"),
            "vulnStatus": st.column_config.TextColumn("Status", width="small"),
            "published": st.column_config.DatetimeColumn("Published", format="YYYY-MM-DD HH:mm"),
            "vendors": st.column_config.TextColumn("Vendors", width="medium"),
            "products": st.column_config.TextColumn("Products", width="medium"),
            "desc": st.column_config.TextColumn("Description", width="large"),
        },
    )

st.divider()

# --- Detail List ---
st.subheader("Detailed CVE List")

if df_cves is not None and not df_cves.empty:
    shown = len(df_cves)
    st.caption(f"Showing the newest {shown:,} of {total_cves:,} matching CVEs." if total_cves > shown
               else f"{total_cves:,} matching CVEs.")

    df_table = df_cves.copy()
    df_table["nvd"] = "https://nvd.nist.gov/vuln/detail/" + df_table["id"].astype(str)
    for col in ("vendors", "products"):
        if col in df_table.columns:
            df_table[col] = df_table[col].apply(lambda v: ", ".join(v) if isinstance(v, list) else v)

    cols_to_show = ["id", "nvd", "sev", "vulnStatus", "score", "epss", "hasCisa", "published", "vendors", "products", "desc"]
    available_cols = [c for c in cols_to_show if c in df_table.columns]

    st.dataframe(
        df_table[available_cols],
        hide_index=True,
        use_container_width=True,
        height=400,
        column_config={
            "id": st.column_config.TextColumn("CVE", width="medium"),
            "nvd": nvd_link_config(),
            "sev": st.column_config.TextColumn("Severity", width="small"),
            "vulnStatus": st.column_config.TextColumn("Status", width="small"),
            "score": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
            "epss": st.column_config.NumberColumn("EPSS", format="%.4f", width="small"),
            "hasCisa": st.column_config.CheckboxColumn("KEV", width="small"),
            "published": st.column_config.DatetimeColumn("Published", format="YYYY-MM-DD HH:mm"),
            "vendors": st.column_config.TextColumn("Vendors", width="medium"),
            "products": st.column_config.TextColumn("Products", width="medium"),
            "desc": st.column_config.TextColumn("Description", width="large"),
        },
    )

    with st.expander("Raw Data Inspection (first 5 records)"):
        st.json(df_cves.head().to_dict(orient="records"))
else:
    st.info("No CVEs found matching your criteria.")

st.markdown("---")
st.caption(f"Version: {APP_VERSION}")
