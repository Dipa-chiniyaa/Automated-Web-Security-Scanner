"""
app.py
======
WebScanner AI — Streamlit dashboard
Integrates: crawler, scanners, vulnerability_tests, reporter
"""

import logging
import time
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from crawler import WebCrawler
from reporter import DatabaseManager, ReportGenerator, compute_security_score
from scanners import HeaderScanner, PortScanner
from vulnerability_tests import DirectoryBruteforce, SQLiDetector, XSSDetector

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebScanner AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0d1117; color: #c9d1d9;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22; border-right: 1px solid #30363d;
    }
    .card {
        background: #161b22; border: 1px solid #30363d;
        border-radius: 10px; padding: 20px 24px; text-align: center;
    }
    .card-label {
        font-size: .78rem; color: #8b949e;
        letter-spacing: .06em; text-transform: uppercase; margin-bottom: 6px;
    }
    .card-value { font-size: 2.2rem; font-weight: 700; line-height: 1.1; }
    .card-delta { font-size: .75rem; margin-top: 4px; color: #8b949e; }
    .accent-blue   { color: #58a6ff; }
    .accent-red    { color: #f85149; }
    .accent-orange { color: #d29922; }
    .accent-green  { color: #3fb950; }
    hr { border-color: #30363d; }
    [data-testid="stTabs"] button { color: #8b949e; font-size: .9rem; }
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #58a6ff; border-bottom: 2px solid #58a6ff;
    }
    div.stButton > button {
        background: #238636; color: #fff; border: 1px solid #2ea043;
        border-radius: 6px; width: 100%; font-weight: 600;
        padding: .55rem 1rem; transition: background .2s;
    }
    div.stButton > button:hover { background: #2ea043; }
    div.stDownloadButton > button {
        background: #1f6feb; color: #fff; border: 1px solid #388bfd;
        border-radius: 6px; font-weight: 600;
        padding: .45rem .9rem; transition: background .2s;
    }
    div.stDownloadButton > button:hover { background: #388bfd; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Constants ─────────────────────────────────────────────────────────────────
SEVERITY_COLOURS = {
    "Critical": "#f85149",
    "High":     "#d29922",
    "Medium":   "#ffc107",
    "Low":      "#3fb950",
    "Info":     "#58a6ff",
}
DB_PATH = "scanner.db"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_url(url: str) -> tuple[bool, str]:
    """Return (is_valid, error_message). error_message is '' when valid."""
    if not url.strip():
        return False, "Target URL cannot be empty."
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Could not parse URL."
    if parsed.scheme not in ("http", "https"):
        return False, "URL must start with http:// or https://"
    if not parsed.netloc:
        return False, "URL must include a hostname (e.g. https://example.com)."
    return True, ""


def _metric_card(col, label: str, value, colour_class: str, delta: str = "") -> None:
    col.markdown(
        f"""<div class="card">
              <div class="card-label">{label}</div>
              <div class="card-value {colour_class}">{value}</div>
              <div class="card-delta">{delta}</div>
            </div>""",
        unsafe_allow_html=True,
    )


def _severity_badge(sev: str) -> str:
    colour = SEVERITY_COLOURS.get(sev, "#8b949e")
    return f'<span style="color:{colour}; font-weight:700;">{sev}</span>'


def _findings_to_df(findings: list[dict]) -> pd.DataFrame:
    """Convert finding dicts to a display-ready DataFrame."""
    if not findings:
        return pd.DataFrame()
    rows = [
        {
            "ID":          f.get("id", ""),
            "Severity":    f.get("severity", ""),
            "Category":    f.get("category", ""),
            "Title":       f.get("title", ""),
            "URL":         f.get("url", "") or "",
            "Parameter":   f.get("parameter", "") or "",
        }
        for f in findings
    ]
    df = pd.DataFrame(rows)
    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    df["_order"] = df["Severity"].map(lambda s: sev_order.get(s, 99))
    df = df.sort_values("_order").drop(columns=["_order"]).reset_index(drop=True)
    return df


# ── Run scan (cached to session_state) ───────────────────────────────────────

def run_scan(
    target_url: str,
    depth: int,
    run_headers: bool,
    run_ports: bool,
    run_sqli: bool,
    run_xss: bool,
    run_dirbust: bool,
) -> None:
    """
    Execute all enabled scan modules, persist results, and store everything
    in st.session_state so the UI can render without re-running.
    """
    # ── Reset state ───────────────────────────────────────────────────────────
    st.session_state.scan_done    = False
    st.session_state.scan_error   = None
    st.session_state.all_findings = []
    st.session_state.crawl_result = {}
    st.session_state.port_result  = {}
    st.session_state.score        = 100
    st.session_state.session_id   = None

    progress_bar  = st.progress(0, text="Initialising scan…")
    status_area   = st.empty()

    try:
        db = DatabaseManager(DB_PATH)
        active_modules = [
            m for m, active in [
                ("Header/SSL Audit", run_headers),
                ("Port Scan",        run_ports),
                ("SQLi Probes",      run_sqli),
                ("XSS Probes",       run_xss),
                ("Dir Brute-force",  run_dirbust),
            ]
            if active
        ]
        session_id = db.create_session(target_url, depth=depth, modules=active_modules)
        st.session_state.session_id = session_id

        all_findings: list[dict] = []

        # ── Step 1: Crawl ─────────────────────────────────────────────────────
        progress_bar.progress(5, text="🕷️  Crawling target…")
        status_area.info(f"**Crawling** `{target_url}` at depth {depth}…")
        try:
            crawler = WebCrawler(target_url, depth=depth, delay=0.1)
            crawl_result = crawler.crawl()
        except ValueError as exc:
            st.session_state.scan_error = f"Invalid target URL: {exc}"
            progress_bar.empty()
            status_area.empty()
            return
        except Exception as exc:
            st.session_state.scan_error = f"Crawler error: {exc}"
            progress_bar.empty()
            status_area.empty()
            return

        db.save_urls(session_id, crawl_result.get("pages", []))
        st.session_state.crawl_result = crawl_result
        pages = crawl_result.get("pages", [])
        forms = crawl_result.get("forms", [])

        # ── Step 2: Header / SSL Audit ────────────────────────────────────────
        if run_headers:
            progress_bar.progress(20, text="🔒  Auditing HTTP headers & SSL…")
            status_area.info("**Auditing** HTTP response headers and TLS configuration…")
            try:
                hs = HeaderScanner(target_url)
                hdr_result = hs.scan()
                if hdr_result.get("error"):
                    st.session_state.scan_error = (
                        f"Header scanner could not reach target: {hdr_result['error']}"
                    )
                    progress_bar.empty()
                    status_area.empty()
                    return
                all_findings.extend(hdr_result.get("findings", []))
            except Exception as exc:
                all_findings.append({
                    "id": "ERR-HDR", "title": "Header Scan Error", "severity": "Info",
                    "category": "Error", "description": str(exc),
                    "evidence": None, "remediation": "Check connectivity.",
                    "url": target_url, "parameter": None, "payload": None,
                })

        # ── Step 3: Port Scan ─────────────────────────────────────────────────
        port_result: dict = {}
        if run_ports:
            progress_bar.progress(40, text="🔌  Scanning open ports…")
            status_area.info("**Scanning** common TCP ports…")
            try:
                hostname = urlparse(target_url).hostname or ""
                ps = PortScanner(hostname, timeout=0.8)
                port_result = ps.scan()
                if port_result.get("error"):
                    all_findings.append({
                        "id": "ERR-PORT", "title": "Port Scan Error", "severity": "Info",
                        "category": "Error",
                        "description": port_result["error"],
                        "evidence": None, "remediation": "Verify hostname resolves.",
                        "url": target_url, "parameter": None, "payload": None,
                    })
                else:
                    pf = port_result.get("findings", [])
                    db.save_ports(session_id, pf)
                    all_findings.extend(pf)
            except Exception as exc:
                all_findings.append({
                    "id": "ERR-PORT", "title": "Port Scan Error", "severity": "Info",
                    "category": "Error", "description": str(exc),
                    "evidence": None, "remediation": "Check hostname.",
                    "url": target_url, "parameter": None, "payload": None,
                })
            st.session_state.port_result = port_result

        # ── Step 4: SQLi Probes ───────────────────────────────────────────────
        if run_sqli:
            progress_bar.progress(60, text="💉  Probing for SQL injection…")
            status_area.info("**Probing** form parameters and query strings for SQLi…")
            try:
                sqli = SQLiDetector(target_url, delay=0.1)
                sqli_findings = sqli.scan(forms=forms, pages=pages)
                all_findings.extend(sqli_findings)
            except Exception as exc:
                all_findings.append({
                    "id": "ERR-SQLI", "title": "SQLi Probe Error", "severity": "Info",
                    "category": "Error", "description": str(exc),
                    "evidence": None, "remediation": "Check connectivity.",
                    "url": target_url, "parameter": None, "payload": None,
                })

        # ── Step 5: XSS Probes ────────────────────────────────────────────────
        if run_xss:
            progress_bar.progress(75, text="🎭  Probing for reflected XSS…")
            status_area.info("**Probing** form inputs and query parameters for reflected XSS…")
            try:
                xss = XSSDetector(target_url, delay=0.1)
                xss_findings = xss.scan(forms=forms, pages=pages)
                all_findings.extend(xss_findings)
            except Exception as exc:
                all_findings.append({
                    "id": "ERR-XSS", "title": "XSS Probe Error", "severity": "Info",
                    "category": "Error", "description": str(exc),
                    "evidence": None, "remediation": "Check connectivity.",
                    "url": target_url, "parameter": None, "payload": None,
                })

        # ── Step 6: Directory Brute-force ─────────────────────────────────────
        if run_dirbust:
            progress_bar.progress(88, text="📂  Enumerating sensitive paths…")
            status_area.info("**Brute-forcing** common sensitive directories and files…")
            try:
                db_scanner = DirectoryBruteforce(target_url, delay=0.05)
                dir_findings = db_scanner.scan()
                all_findings.extend(dir_findings)
            except Exception as exc:
                all_findings.append({
                    "id": "ERR-DIR", "title": "Dir Brute Error", "severity": "Info",
                    "category": "Error", "description": str(exc),
                    "evidence": None, "remediation": "Check connectivity.",
                    "url": target_url, "parameter": None, "payload": None,
                })

        # ── Finalise ──────────────────────────────────────────────────────────
        progress_bar.progress(95, text="📊  Computing score and persisting results…")
        score = compute_security_score(all_findings)
        db.save_vulnerabilities(session_id, all_findings)
        db.finish_session(session_id, score)

        st.session_state.all_findings = all_findings
        st.session_state.score        = score
        st.session_state.scan_done    = True
        st.session_state.target_url   = target_url
        st.session_state.active_modules = active_modules

        progress_bar.progress(100, text="✅  Scan complete!")
        time.sleep(0.5)
        progress_bar.empty()
        status_area.empty()

    except Exception as exc:
        st.session_state.scan_error = f"Unexpected error during scan: {exc}"
        try:
            progress_bar.empty()
            status_area.empty()
        except Exception:
            pass


# ── Session state defaults ────────────────────────────────────────────────────
defaults = {
    "scan_done":      False,
    "scan_error":     None,
    "all_findings":   [],
    "crawl_result":   {},
    "port_result":    {},
    "score":          100,
    "session_id":     None,
    "target_url":     "",
    "active_modules": [],
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ════════════════════════════════════════════════════════════════════════════ #
#  UI
# ════════════════════════════════════════════════════════════════════════════ #

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ WebScanner AI")
st.markdown(
    "<p style='color:#8b949e; margin-top:-10px;'>"
    "Automated Web Security Scanner — crawl, audit headers, probe for "
    "SQLi/XSS, scan ports, and enumerate sensitive paths."
    "</p>",
    unsafe_allow_html=True,
)
st.markdown("<hr>", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Scan Configuration")
    st.markdown("<hr>", unsafe_allow_html=True)

    target_url = st.text_input(
        "🌐 Target URL",
        placeholder="https://example.com",
        help="Full URL including scheme.",
    )
    scan_depth = st.slider("🔍 Scan Scope (Depth)", 1, 3, 1,
                           help="1 = surface only · 2 = linked pages · 3 = deep crawl")

    st.markdown("**🧩 Active Scan Modules**")
    chk_headers  = st.checkbox("Header / SSL Audit",    value=True)
    chk_ports    = st.checkbox("Port Scan",              value=False)
    chk_sqli     = st.checkbox("SQLi Probes",            value=False)
    chk_xss      = st.checkbox("XSS Probes",             value=False)
    chk_dirbust  = st.checkbox("Directory Brute-force",  value=False)

    st.markdown("<br>", unsafe_allow_html=True)
    run_clicked = st.button("🚀 Start Scan")

    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(
        "<p style='font-size:.75rem; color:#8b949e;'>"
        "⚠️ Only scan systems you own or have explicit written permission to test."
        "</p>",
        unsafe_allow_html=True,
    )

# ── Trigger scan ──────────────────────────────────────────────────────────────
if run_clicked:
    valid, err_msg = _validate_url(target_url)
    if not valid:
        st.error(f"❌ {err_msg}")
    else:
        run_scan(
            target_url=target_url,
            depth=scan_depth,
            run_headers=chk_headers,
            run_ports=chk_ports,
            run_sqli=chk_sqli,
            run_xss=chk_xss,
            run_dirbust=chk_dirbust,
        )
        st.rerun()

# ── Scan error banner ─────────────────────────────────────────────────────────
if st.session_state.scan_error:
    st.error(f"❌ {st.session_state.scan_error}")

# ── Metric cards ──────────────────────────────────────────────────────────────
crawl_stats   = st.session_state.crawl_result.get("stats", {})
all_findings  = st.session_state.all_findings
score         = st.session_state.score

urls_val   = crawl_stats.get("total_urls_crawled", "—")
ports_val  = (
    len(st.session_state.port_result.get("open_ports", []))
    if st.session_state.scan_done else "—"
)
critical_n = sum(1 for f in all_findings if f.get("severity") == "Critical")
high_n     = sum(1 for f in all_findings if f.get("severity") == "High")
vulns_val  = critical_n + high_n if st.session_state.scan_done else "—"
score_val  = f"{score}/100" if st.session_state.scan_done else "—"

c1, c2, c3, c4 = st.columns(4)
_metric_card(c1, "Total URLs Scanned",    urls_val,  "accent-blue",
             "pages discovered" if st.session_state.scan_done else "Run a scan to populate")
_metric_card(c2, "Critical / High Vulns", vulns_val, "accent-red",
             "require immediate action" if st.session_state.scan_done else "Run a scan to populate")
_metric_card(c3, "Open Ports",            ports_val, "accent-orange",
             "exposed services" if st.session_state.scan_done else "Run a scan to populate")
score_colour = (
    "accent-green" if isinstance(score, int) and score >= 70
    else "accent-orange" if isinstance(score, int) and score >= 40
    else "accent-red"
)
_metric_card(c4, "Security Score", score_val, score_colour,
             "overall posture" if st.session_state.scan_done else "Run a scan to populate")

st.markdown("<br>", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_results, tab_details, tab_crawl, tab_export = st.tabs(
    ["📋 Scan Results", "🔎 Vulnerability Details", "🕷️ Crawl Map", "📤 Export Report"]
)

# ── Tab 1: Scan Results ───────────────────────────────────────────────────────
with tab_results:
    st.markdown("#### Scan Results")

    if not st.session_state.scan_done:
        st.info("No scan data yet — configure the target in the sidebar and click **Start Scan**.")
    else:
        target_display = st.session_state.get("target_url", "")
        modules_str = ", ".join(st.session_state.get("active_modules", [])) or "None"
        st.markdown(
            f"**Target:** `{target_display}` &nbsp;·&nbsp; "
            f"**Depth:** {scan_depth} &nbsp;·&nbsp; "
            f"**Modules:** {modules_str}"
        )
        st.markdown("<br>", unsafe_allow_html=True)

        # Severity breakdown bar
        sev_counts = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Info")}
        for f in all_findings:
            sev = f.get("severity", "Info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        cols = st.columns(5)
        for col, sev in zip(cols, ("Critical", "High", "Medium", "Low", "Info")):
            colour = SEVERITY_COLOURS[sev]
            col.markdown(
                f"<div style='text-align:center; background:#161b22; border:1px solid #30363d;"
                f" border-radius:8px; padding:12px 4px;'>"
                f"<div style='font-size:.7rem; color:#8b949e; text-transform:uppercase;"
                f" letter-spacing:.05em;'>{sev}</div>"
                f"<div style='font-size:1.8rem; font-weight:700; color:{colour};'>"
                f"{sev_counts[sev]}</div></div>",
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)

        # Findings dataframe
        df = _findings_to_df(all_findings)
        if df.empty:
            st.success("✅ No findings — nothing detected by the enabled modules.")
        else:
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Severity": st.column_config.TextColumn("Severity", width="small"),
                    "URL":      st.column_config.LinkColumn("URL",      width="medium"),
                },
            )

# ── Tab 2: Vulnerability Details ──────────────────────────────────────────────
with tab_details:
    st.markdown("#### Vulnerability Details")

    if not st.session_state.scan_done:
        st.info("No vulnerability data yet — run a scan first.")
    elif not all_findings:
        st.success("✅ No findings to display.")
    else:
        # Filter controls
        filter_col1, filter_col2 = st.columns([1, 3])
        with filter_col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Critical", "High", "Medium", "Low", "Info"],
                default=["Critical", "High", "Medium"],
            )
        with filter_col2:
            cat_options = sorted({f.get("category", "") for f in all_findings if f.get("category")})
            category_filter = st.multiselect("Filter by Category", options=cat_options, default=[])

        filtered = [
            f for f in all_findings
            if f.get("severity") in severity_filter
            and (not category_filter or f.get("category") in category_filter)
        ]

        if not filtered:
            st.info("No findings match the current filters.")
        else:
            st.markdown(f"**Showing {len(filtered)} of {len(all_findings)} finding(s)**")
            for f in sorted(filtered, key=lambda x: (
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(
                    x.get("severity", "Info"), 99
                )
            )):
                sev   = f.get("severity", "Info")
                colour = SEVERITY_COLOURS.get(sev, "#8b949e")
                with st.expander(
                    f"[{sev}] {f.get('id', '')}  —  {f.get('title', 'Untitled')}",
                    expanded=False,
                ):
                    col_a, col_b = st.columns([1, 2])
                    with col_a:
                        st.markdown(
                            f"<span style='color:{colour}; font-size:1.1rem;"
                            f" font-weight:700;'>● {sev}</span>",
                            unsafe_allow_html=True,
                        )
                        st.markdown(f"**Category:** {f.get('category', 'N/A')}")
                        if f.get("url"):
                            st.markdown(f"**URL:** `{f.get('url')}`")
                        if f.get("parameter"):
                            st.markdown(f"**Parameter:** `{f.get('parameter')}`")
                        if f.get("payload"):
                            st.markdown(f"**Payload:** `{f.get('payload')}`")
                    with col_b:
                        st.markdown(f"**Description**  \n{f.get('description', '')}")
                        if f.get("evidence"):
                            st.code(f.get("evidence"), language=None)
                        st.markdown(
                            f"<div style='background:#0f2027; border-left:3px solid #3fb950;"
                            f" padding:.6rem .9rem; border-radius:0 4px 4px 0;"
                            f" font-size:.85rem; color:#b3d9c4; margin-top:.5rem;'>"
                            f"🔧 <strong>Remediation:</strong> {f.get('remediation', '')}"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

# ── Tab 3: Crawl Map ──────────────────────────────────────────────────────────
with tab_crawl:
    st.markdown("#### Crawl Map")

    if not st.session_state.scan_done:
        st.info("No crawl data yet — run a scan first.")
    else:
        cr    = st.session_state.crawl_result
        stats = cr.get("stats", {})
        pages = cr.get("pages", [])
        forms = cr.get("forms", [])

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("URLs Crawled",     stats.get("total_urls_crawled",  0))
        m2.metric("Successful",       stats.get("successful_fetches",  0))
        m3.metric("Failed",           stats.get("failed_fetches",      0))
        m4.metric("Forms Found",      stats.get("total_forms_found",   0))

        if pages:
            st.markdown("##### Discovered Pages")
            pages_df = pd.DataFrame([
                {
                    "URL":           p.get("url", ""),
                    "Status":        p.get("status_code", ""),
                    "Depth":         p.get("depth", ""),
                    "Response (ms)": round(p.get("response_time_ms") or 0, 1),
                    "Forms":         p.get("forms_found", 0),
                    "Links":         p.get("links_found", 0),
                    "Error":         p.get("error", "") or "",
                }
                for p in pages
            ])
            st.dataframe(pages_df, use_container_width=True, hide_index=True)

        if forms:
            st.markdown("##### Discovered Forms (injectable parameters)")
            forms_df = pd.DataFrame([
                {
                    "Action":     f.get("action", ""),
                    "Method":     f.get("method", ""),
                    "Page":       f.get("page_url", ""),
                    "# Inputs":   len(f.get("inputs", [])),
                    "Input Names": ", ".join(
                        i.get("name", "") for i in f.get("inputs", []) if i.get("name")
                    ),
                }
                for f in forms
            ])
            st.dataframe(forms_df, use_container_width=True, hide_index=True)

        # Port map
        if st.session_state.port_result.get("open_ports"):
            st.markdown("##### Open Ports")
            port_rows = []
            for pf in st.session_state.port_result.get("findings", []):
                ev = pf.get("evidence", "") or ""
                port_rows.append({
                    "Finding ID": pf.get("id", ""),
                    "Severity":   pf.get("severity", ""),
                    "Evidence":   ev,
                })
            st.dataframe(pd.DataFrame(port_rows), use_container_width=True, hide_index=True)

# ── Tab 4: Export Report ──────────────────────────────────────────────────────
with tab_export:
    st.markdown("#### Export Report")

    if not st.session_state.scan_done:
        st.info("No report to export yet — run a scan first.")
    else:
        target_display = st.session_state.get("target_url", "unknown")

        gen = ReportGenerator(
            target=target_display,
            findings=all_findings,
            score=score,
            session_id=st.session_state.session_id,
            scan_modules=st.session_state.get("active_modules", []),
        )

        json_bytes = gen.to_json()
        html_bytes = gen.to_html()

        st.markdown(
            f"Report generated for **`{target_display}`** — "
            f"**{len(all_findings)}** finding(s), Security Score **{score}/100**."
        )
        st.markdown("<br>", unsafe_allow_html=True)

        dl1, dl2 = st.columns(2)

        with dl1:
            st.markdown("##### 📄 JSON Report")
            st.markdown(
                "Full programmatic dump of all findings, metadata, "
                "and severity counts. Ideal for CI/CD integration."
            )
            st.download_button(
                label="⬇️ Download JSON",
                data=json_bytes,
                file_name="webscanner_report.json",
                mime="application/json",
                use_container_width=True,
            )

        with dl2:
            st.markdown("##### 🌐 HTML Report")
            st.markdown(
                "Self-contained styled executive summary with severity badges, "
                "evidence snippets, and remediation advice."
            )
            st.download_button(
                label="⬇️ Download HTML",
                data=html_bytes,
                file_name="webscanner_report.html",
                mime="text/html",
                use_container_width=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("##### Preview — JSON Metadata")
        import json as _json
        meta_preview = _json.loads(json_bytes)["report_metadata"]
        st.json(meta_preview)
