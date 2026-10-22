"""
reporter.py
===========
Persistent storage and report generation for the WebScanner AI project.

  • DatabaseManager  — SQLite-backed storage for sessions, URLs, ports,
                        and vulnerabilities.
  • ReportGenerator  — Produces JSON and self-contained HTML reports from
                        a set of findings.
  • compute_security_score() — Weighted 0-100 score derived from findings.

Usage
-----
    from reporter import DatabaseManager, ReportGenerator, compute_security_score

    db = DatabaseManager("scanner.db")
    session_id = db.create_session("https://example.com", depth=2, modules=["headers", "sqli"])

    db.save_urls(session_id, crawler_result["pages"])
    db.save_ports(session_id, port_result["findings"])
    db.save_vulnerabilities(session_id, all_findings)

    score = compute_security_score(all_findings)

    gen = ReportGenerator(
        target="https://example.com",
        session_id=session_id,
        findings=all_findings,
        score=score,
    )
    json_bytes = gen.to_json()
    html_bytes = gen.to_html()
"""

from __future__ import annotations

import html as _html_escape
import json
import logging
import sqlite3
import textwrap
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Severity ordering ─────────────────────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High":     1,
    "Medium":   2,
    "Low":      3,
    "Info":     4,
}

# ── Security score weights (penalty per finding) ──────────────────────────────
SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical": 25,
    "High":     15,
    "Medium":    7,
    "Low":       3,
    "Info":      0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Security Score
# ─────────────────────────────────────────────────────────────────────────────

def compute_security_score(findings: list[dict]) -> int:
    """
    Compute an overall Security Score (0–100) from a list of findings.

    Scoring model
    -------------
    Start at 100. Subtract weighted penalties for every non-Info finding.
    The result is clamped to [0, 100] and returned as an integer.

    Penalty weights
    ~~~~~~~~~~~~~~~
    Critical : -25 pts each
    High     : -15 pts each
    Medium   :  -7 pts each
    Low      :  -3 pts each
    Info     :   0 pts

    Parameters
    ----------
    findings : list[dict]
        Any iterable of finding dicts that carry a ``"severity"`` key.

    Returns
    -------
    int  — score in [0, 100].
    """
    penalty = sum(
        SEVERITY_WEIGHTS.get(f.get("severity", "Info"), 0)
        for f in findings
    )
    return max(0, min(100, 100 - penalty))


# ─────────────────────────────────────────────────────────────────────────────
# DatabaseManager
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseManager:
    """
    SQLite-backed persistence layer for WebScanner AI.

    Schema
    ------
    sessions        — one row per scan run
    crawled_urls    — one row per discovered URL
    open_ports      — one row per open port finding
    vulnerabilities — one row per vulnerability finding

    Parameters
    ----------
    db_path : str | Path
        File path for the SQLite database. Use ``:memory:`` for in-memory.
    """

    # ── DDL ───────────────────────────────────────────────────────────────────
    _CREATE_SESSIONS = """
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT    NOT NULL,
            depth       INTEGER NOT NULL DEFAULT 1,
            modules     TEXT    NOT NULL DEFAULT '',
            started_at  TEXT    NOT NULL,
            finished_at TEXT,
            score       INTEGER,
            status      TEXT    NOT NULL DEFAULT 'running'
        );
    """

    _CREATE_CRAWLED_URLS = """
        CREATE TABLE IF NOT EXISTS crawled_urls (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id    INTEGER NOT NULL REFERENCES sessions(id),
            url           TEXT    NOT NULL,
            status_code   INTEGER,
            content_type  TEXT,
            response_time REAL,
            depth         INTEGER,
            forms_found   INTEGER DEFAULT 0,
            links_found   INTEGER DEFAULT 0,
            error         TEXT,
            discovered_at TEXT    NOT NULL
        );
    """

    _CREATE_OPEN_PORTS = """
        CREATE TABLE IF NOT EXISTS open_ports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  INTEGER NOT NULL REFERENCES sessions(id),
            port        INTEGER NOT NULL,
            service     TEXT,
            banner      TEXT,
            severity    TEXT,
            discovered_at TEXT NOT NULL
        );
    """

    _CREATE_VULNERABILITIES = """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   INTEGER NOT NULL REFERENCES sessions(id),
            finding_id   TEXT,
            title        TEXT    NOT NULL,
            severity     TEXT    NOT NULL,
            category     TEXT,
            url          TEXT,
            parameter    TEXT,
            payload      TEXT,
            description  TEXT,
            evidence     TEXT,
            remediation  TEXT,
            discovered_at TEXT   NOT NULL
        );
    """

    def __init__(self, db_path: str | Path = "scanner.db") -> None:
        self.db_path = str(db_path)
        # Keep a single persistent connection so :memory: databases survive
        # across multiple method calls and file-based DBs avoid repeated open/close.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._initialise()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield the persistent connection inside a savepoint transaction."""
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _initialise(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.execute(self._CREATE_SESSIONS)
            conn.execute(self._CREATE_CRAWLED_URLS)
            conn.execute(self._CREATE_OPEN_PORTS)
            conn.execute(self._CREATE_VULNERABILITIES)
        logger.debug("Database initialised at %s", self.db_path)

    def close(self) -> None:
        """Explicitly close the underlying database connection."""
        self._conn.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Session management ────────────────────────────────────────────────────

    def create_session(
        self,
        target: str,
        depth: int = 1,
        modules: Optional[list[str]] = None,
    ) -> int:
        """
        Insert a new scan session row and return its auto-generated ID.

        Parameters
        ----------
        target : str
            The scan target URL.
        depth : int
            Crawl depth used for this session.
        modules : list[str] | None
            Names of active scan modules (stored as comma-separated string).

        Returns
        -------
        int — the new session ID.
        """
        modules_str = ",".join(modules or [])
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO sessions (target, depth, modules, started_at, status) "
                "VALUES (?, ?, ?, ?, 'running')",
                (target, depth, modules_str, self._now()),
            )
            session_id = cur.lastrowid
        logger.info("Session %d created for target '%s'", session_id, target)
        return session_id

    def finish_session(self, session_id: int, score: int) -> None:
        """
        Mark a session as completed, recording its finish time and score.

        Parameters
        ----------
        session_id : int
        score : int  — computed security score (0–100).
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET finished_at=?, score=?, status='completed' WHERE id=?",
                (self._now(), score, session_id),
            )
        logger.info("Session %d finished (score=%d)", session_id, score)

    def get_session(self, session_id: int) -> Optional[dict]:
        """Return a session row as a dict, or None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_sessions(self) -> list[dict]:
        """Return all sessions ordered by most-recent first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── URL storage ───────────────────────────────────────────────────────────

    def save_urls(self, session_id: int, pages: list[dict]) -> int:
        """
        Persist crawled page records for a session.

        Parameters
        ----------
        session_id : int
        pages : list[dict]
            Page dicts from ``WebCrawler._build_result()`` (key: ``url``,
            ``status_code``, ``content_type``, ``response_time_ms``, ``depth``,
            ``forms_found``, ``links_found``, ``error``).

        Returns
        -------
        int — number of rows inserted.
        """
        now = self._now()
        rows = [
            (
                session_id,
                p.get("url", ""),
                p.get("status_code"),
                p.get("content_type", ""),
                p.get("response_time_ms"),
                p.get("depth"),
                p.get("forms_found", 0),
                p.get("links_found", 0),
                p.get("error"),
                now,
            )
            for p in pages
        ]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO crawled_urls "
                "(session_id, url, status_code, content_type, response_time, "
                " depth, forms_found, links_found, error, discovered_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        logger.debug("Saved %d URL(s) for session %d", len(rows), session_id)
        return len(rows)

    def get_urls(self, session_id: int) -> list[dict]:
        """Return all crawled URLs for a session."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM crawled_urls WHERE session_id=? ORDER BY id",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Port storage ──────────────────────────────────────────────────────────

    def save_ports(self, session_id: int, port_findings: list[dict]) -> int:
        """
        Persist open-port findings from ``PortScanner``.

        Parameters
        ----------
        session_id : int
        port_findings : list[dict]
            Finding dicts from ``PortScanner.scan()["findings"]``.
            Expected keys: ``evidence`` (``"80/tcp  HTTP  [banner]"``),
            ``severity``, ``title``.

        Returns
        -------
        int — rows inserted.
        """
        now = self._now()
        rows = []
        for f in port_findings:
            evidence = f.get("evidence", "") or ""
            parts = evidence.split("/")
            port_num = int(parts[0]) if parts and parts[0].isdigit() else 0
            service_part = evidence.split("  ")[1].strip() if "  " in evidence else ""
            banner_part  = evidence.split("[")[1].rstrip("]") if "[" in evidence else None
            rows.append((
                session_id, port_num, service_part, banner_part,
                f.get("severity", "Info"), now,
            ))
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO open_ports (session_id, port, service, banner, severity, discovered_at) "
                "VALUES (?,?,?,?,?,?)",
                rows,
            )
        logger.debug("Saved %d port finding(s) for session %d", len(rows), session_id)
        return len(rows)

    def get_ports(self, session_id: int) -> list[dict]:
        """Return all open-port records for a session."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM open_ports WHERE session_id=? ORDER BY port",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Vulnerability storage ─────────────────────────────────────────────────

    def save_vulnerabilities(self, session_id: int, findings: list[dict]) -> int:
        """
        Persist vulnerability findings from any detector module.

        Parameters
        ----------
        session_id : int
        findings : list[dict]
            Finding dicts in the shared 10-key schema used across
            ``scanners.py`` and ``vulnerability_tests.py``.

        Returns
        -------
        int — rows inserted.
        """
        now = self._now()
        rows = [
            (
                session_id,
                f.get("id", ""),
                f.get("title", ""),
                f.get("severity", "Info"),
                f.get("category", ""),
                f.get("url", ""),
                f.get("parameter", ""),
                f.get("payload", ""),
                f.get("description", ""),
                f.get("evidence", ""),
                f.get("remediation", ""),
                now,
            )
            for f in findings
        ]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO vulnerabilities "
                "(session_id, finding_id, title, severity, category, url, "
                " parameter, payload, description, evidence, remediation, discovered_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        logger.debug("Saved %d vulnerability finding(s) for session %d", len(rows), session_id)
        return len(rows)

    def get_vulnerabilities(self, session_id: int) -> list[dict]:
        """Return all vulnerability rows for a session, sorted by severity."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM vulnerabilities WHERE session_id=? ORDER BY "
                "CASE severity "
                "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 "
                "WHEN 'Low' THEN 3 ELSE 4 END, id",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_session(self, session_id: int) -> None:
        """Delete a session and all its associated rows (cascade)."""
        with self._connect() as conn:
            for table in ("vulnerabilities", "open_ports", "crawled_urls", "sessions"):
                col = "id" if table == "sessions" else "session_id"
                conn.execute(f"DELETE FROM {table} WHERE {col}=?", (session_id,))
        logger.info("Session %d deleted", session_id)


# ─────────────────────────────────────────────────────────────────────────────
# ReportGenerator
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Formats scan findings into downloadable report files.

    Supported formats
    -----------------
    * JSON  — complete programmatic dump of all findings.
    * HTML  — self-contained styled executive summary with severity badges,
              evidence snippets, and remediation advice.

    Parameters
    ----------
    target : str
        The scanned URL (displayed in report headers).
    session_id : int | None
        Database session ID (informational; included in report metadata).
    findings : list[dict]
        All finding dicts from any scanner/detector module.
    score : int
        Pre-computed security score (use ``compute_security_score()``).
    scan_modules : list[str] | None
        Names of modules that ran (informational).
    """

    # Severity display colours (inline CSS)
    _SEVERITY_COLOURS: dict[str, tuple[str, str]] = {
        "Critical": ("#7c0000", "#ff4d4d"),
        "High":     ("#5a1e00", "#ff8c42"),
        "Medium":   ("#4a3800", "#ffc107"),
        "Low":      ("#003320", "#4caf50"),
        "Info":     ("#0a2240", "#58a6ff"),
    }

    def __init__(
        self,
        target: str,
        findings: list[dict],
        score: int,
        session_id: Optional[int] = None,
        scan_modules: Optional[list[str]] = None,
    ) -> None:
        self.target = target
        self.findings = findings
        self.score = score
        self.session_id = session_id
        self.scan_modules = scan_modules or []
        self._generated_at = datetime.now(timezone.utc).isoformat()

    # ── JSON ──────────────────────────────────────────────────────────────────

    def to_json(self, indent: int = 2) -> bytes:
        """
        Serialise all findings to a JSON report.

        Returns
        -------
        bytes — UTF-8 encoded JSON.
        """
        payload = {
            "report_metadata": {
                "target":       self.target,
                "session_id":   self.session_id,
                "generated_at": self._generated_at,
                "scan_modules": self.scan_modules,
                "security_score": self.score,
                "total_findings": len(self.findings),
                "severity_counts": self._severity_counts(),
            },
            "findings": sorted(
                self.findings,
                key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
            ),
        }
        return json.dumps(payload, indent=indent, ensure_ascii=False).encode("utf-8")

    # ── HTML ──────────────────────────────────────────────────────────────────

    def to_html(self) -> bytes:
        """
        Render a self-contained styled HTML executive summary.

        Returns
        -------
        bytes — UTF-8 encoded HTML.
        """
        counts   = self._severity_counts()
        findings = sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
        )

        score_colour = (
            "#3fb950" if self.score >= 70
            else "#ffc107" if self.score >= 40
            else "#f85149"
        )

        # ── Build finding cards ───────────────────────────────────────────────
        finding_cards = "".join(self._render_finding_card(f) for f in findings) or (
            "<p style='color:#8b949e; padding:1rem;'>No findings recorded.</p>"
        )

        # ── Summary table rows ────────────────────────────────────────────────
        _sev_row_parts = []
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            _colour = self._SEVERITY_COLOURS.get(sev, ("", "#fff"))[1]
            _count  = counts.get(sev, 0)
            _sev_row_parts.append(
                f"<tr><td>{sev}</td>"
                f"<td style='color:{_colour}; font-weight:700;'>{_count}</td></tr>"
            )
        severity_rows = "".join(_sev_row_parts)

        modules_str = ", ".join(self.scan_modules) if self.scan_modules else "N/A"

        doc = textwrap.dedent(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WebScanner AI — Security Report</title>
        <style>
          *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
          body {{
            font-family: -apple-system,"Segoe UI",system-ui,sans-serif;
            font-size: 14px; line-height: 1.6;
            background: #0d1117; color: #c9d1d9;
          }}
          a {{ color: #58a6ff; text-decoration: none; }}
          .container {{ max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }}

          /* Header */
          .report-header {{
            border-bottom: 1px solid #30363d;
            padding-bottom: 1.5rem; margin-bottom: 2rem;
          }}
          .report-header h1 {{ font-size: 1.6rem; color: #e6edf3; }}
          .report-header p  {{ color: #8b949e; margin-top: .25rem; }}

          /* Score ring */
          .score-row {{ display: flex; align-items: center; gap: 2rem;
                        flex-wrap: wrap; margin-bottom: 2rem; }}
          .score-circle {{
            width: 110px; height: 110px; border-radius: 50%;
            border: 5px solid {score_colour};
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            flex-shrink: 0;
          }}
          .score-circle .num {{
            font-size: 2rem; font-weight: 700; color: {score_colour};
            line-height: 1;
          }}
          .score-circle .lbl {{ font-size: .65rem; color: #8b949e;
                                text-transform: uppercase; letter-spacing:.05em; }}

          /* Summary table */
          .summary-table {{ border-collapse: collapse; min-width: 240px; }}
          .summary-table th {{
            text-align: left; padding: .4rem .8rem;
            background: #161b22; color: #8b949e;
            font-size: .72rem; text-transform: uppercase;
            letter-spacing: .05em; border-bottom: 1px solid #30363d;
          }}
          .summary-table td {{
            padding: .4rem .8rem; border-bottom: 1px solid #21262d;
            font-size: .9rem; color: #c9d1d9;
          }}

          /* Metadata box */
          .meta-grid {{
            display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: .75rem; background: #161b22;
            border: 1px solid #30363d; border-radius: 8px;
            padding: 1rem 1.25rem; margin-bottom: 2rem;
          }}
          .meta-item .label {{ font-size: .7rem; color: #8b949e;
                               text-transform: uppercase; letter-spacing: .05em; }}
          .meta-item .value {{ font-size: .9rem; color: #e6edf3; word-break: break-all; }}

          /* Section header */
          .section-title {{
            font-size: 1rem; color: #e6edf3; font-weight: 600;
            border-bottom: 1px solid #30363d;
            padding-bottom: .4rem; margin-bottom: 1rem;
          }}

          /* Finding card */
          .finding-card {{
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; margin-bottom: 1rem;
            overflow: hidden;
          }}
          .finding-header {{
            display: flex; align-items: center; gap: .75rem;
            padding: .75rem 1rem; border-bottom: 1px solid #21262d;
          }}
          .badge {{
            font-size: .7rem; font-weight: 700;
            padding: .2rem .55rem; border-radius: 999px;
            text-transform: uppercase; letter-spacing: .04em;
            white-space: nowrap; flex-shrink: 0;
          }}
          .finding-title {{ font-weight: 600; color: #e6edf3; font-size: .92rem; }}
          .finding-id     {{ font-size: .75rem; color: #8b949e; margin-left: auto; flex-shrink:0; }}
          .finding-body   {{ padding: .9rem 1rem; }}
          .finding-body p {{ margin-bottom: .6rem; }}
          .field-label {{
            font-size: .7rem; text-transform: uppercase;
            letter-spacing: .05em; color: #8b949e; margin-bottom: .2rem;
          }}
          .code-block {{
            background: #0d1117; border: 1px solid #30363d;
            border-radius: 4px; padding: .5rem .75rem;
            font-family: "SFMono-Regular",Consolas,monospace;
            font-size: .8rem; color: #79c0ff;
            white-space: pre-wrap; word-break: break-all;
            margin-bottom: .6rem;
          }}
          .remediation-box {{
            background: #0f2027; border-left: 3px solid #3fb950;
            padding: .6rem .9rem; border-radius: 0 4px 4px 0;
            font-size: .85rem; color: #b3d9c4;
          }}
          .url-link {{ color: #58a6ff; word-break: break-all; font-size: .85rem; }}

          /* Footer */
          .report-footer {{
            margin-top: 3rem; padding-top: 1rem;
            border-top: 1px solid #30363d;
            text-align: center; font-size: .75rem; color: #8b949e;
          }}
        </style>
        </head>
        <body>
        <div class="container">

          <div class="report-header">
            <h1>&#128737; WebScanner AI — Security Report</h1>
            <p>Automated web vulnerability assessment</p>
          </div>

          <!-- Score + severity summary -->
          <div class="score-row">
            <div class="score-circle">
              <span class="num">{self.score}</span>
              <span class="lbl">Score</span>
            </div>
            <table class="summary-table">
              <thead>
                <tr><th>Severity</th><th>Count</th></tr>
              </thead>
              <tbody>{severity_rows}</tbody>
            </table>
          </div>

          <!-- Metadata -->
          <div class="meta-grid">
            <div class="meta-item">
              <div class="label">Target</div>
              <div class="value"><a href="{_html_escape.escape(self.target)}" class="url-link">{_html_escape.escape(self.target)}</a></div>
            </div>
            <div class="meta-item">
              <div class="label">Generated</div>
              <div class="value">{_html_escape.escape(self._generated_at)}</div>
            </div>
            <div class="meta-item">
              <div class="label">Session ID</div>
              <div class="value">{self.session_id or "N/A"}</div>
            </div>
            <div class="meta-item">
              <div class="label">Total Findings</div>
              <div class="value">{len(self.findings)}</div>
            </div>
            <div class="meta-item">
              <div class="label">Modules Run</div>
              <div class="value">{_html_escape.escape(modules_str)}</div>
            </div>
          </div>

          <!-- Findings -->
          <div class="section-title">Findings</div>
          {finding_cards}

          <div class="report-footer">
            Generated by <strong>WebScanner AI</strong> &mdash;
            for authorised security testing only.
          </div>

        </div>
        </body>
        </html>
        """).strip()

        return doc.encode("utf-8")

    # ── Internal rendering helpers ────────────────────────────────────────────

    def _render_finding_card(self, f: dict) -> str:
        """Return the HTML string for a single finding card."""
        sev      = f.get("severity", "Info")
        bg, fg   = self._SEVERITY_COLOURS.get(sev, ("#111", "#fff"))
        fid      = _html_escape.escape(f.get("id", ""))
        title    = _html_escape.escape(f.get("title", "Untitled"))
        category = _html_escape.escape(f.get("category", ""))
        url      = _html_escape.escape(f.get("url", "") or "")
        param    = _html_escape.escape(str(f.get("parameter", "") or ""))
        payload  = _html_escape.escape(str(f.get("payload", "") or ""))
        desc     = _html_escape.escape(f.get("description", "") or "")
        evidence = _html_escape.escape(str(f.get("evidence", "") or ""))
        remed    = _html_escape.escape(f.get("remediation", "") or "")

        url_section = (
            f'<p><div class="field-label">URL</div>'
            f'<a href="{url}" class="url-link" target="_blank">{url}</a></p>'
        ) if url else ""

        param_section = (
            f'<p><div class="field-label">Parameter</div>'
            f'<span style="color:#e6edf3;">{param}</span></p>'
        ) if param else ""

        payload_section = (
            f'<p><div class="field-label">Payload Injected</div>'
            f'<div class="code-block">{payload}</div></p>'
        ) if payload else ""

        evidence_section = (
            f'<p><div class="field-label">Evidence</div>'
            f'<div class="code-block">{evidence}</div></p>'
        ) if evidence else ""

        return f"""
<div class="finding-card">
  <div class="finding-header">
    <span class="badge" style="background:{bg}; color:{fg};">{sev}</span>
    <span class="finding-title">{title}</span>
    <span class="finding-id">{fid} &mdash; {category}</span>
  </div>
  <div class="finding-body">
    <p><div class="field-label">Description</div>{desc}</p>
    {url_section}
    {param_section}
    {payload_section}
    {evidence_section}
    <div class="field-label">Remediation</div>
    <div class="remediation-box">{remed}</div>
  </div>
</div>
"""

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts


# ── Unit tests ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Standalone unit tests — run with:  python reporter.py
    Uses an in-memory SQLite database; no files are written to disk.
    """
    import sys
    import unittest

    # ── Sample fixtures ───────────────────────────────────────────────────────

    def _make_finding(severity: str, fid: str = "TST-001") -> dict:
        return {
            "id": fid, "title": f"Test {severity}", "severity": severity,
            "category": "Test", "description": f"Desc {severity}",
            "evidence": "some evidence", "remediation": "Fix it.",
            "url": "https://example.com/test",
            "parameter": "q", "payload": "<test>",
        }

    def _make_page() -> dict:
        return {
            "url": "https://example.com/page",
            "status_code": 200, "content_type": "text/html",
            "response_time_ms": 123.4, "depth": 1,
            "forms_found": 2, "links_found": 5, "error": None,
        }

    def _make_port_finding() -> dict:
        return {
            "id": "PORT-00080", "title": "Open Port: 80/tcp (HTTP)",
            "severity": "Low", "category": "Port Scan",
            "description": "HTTP is open.", "evidence": "80/tcp  HTTP  [banner data]",
            "remediation": "Redirect to HTTPS.",
            "url": "", "parameter": None, "payload": None,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # compute_security_score Tests
    # ─────────────────────────────────────────────────────────────────────────

    class TestComputeSecurityScore(unittest.TestCase):
        def test_no_findings_is_perfect(self):
            self.assertEqual(compute_security_score([]), 100)

        def test_one_critical_deducts_25(self):
            self.assertEqual(compute_security_score([_make_finding("Critical")]), 75)

        def test_one_high_deducts_15(self):
            self.assertEqual(compute_security_score([_make_finding("High")]), 85)

        def test_one_medium_deducts_7(self):
            self.assertEqual(compute_security_score([_make_finding("Medium")]), 93)

        def test_one_low_deducts_3(self):
            self.assertEqual(compute_security_score([_make_finding("Low")]), 97)

        def test_info_has_no_penalty(self):
            self.assertEqual(compute_security_score([_make_finding("Info")]), 100)

        def test_score_clamped_to_zero(self):
            findings = [_make_finding("Critical")] * 10  # -250 pts
            self.assertEqual(compute_security_score(findings), 0)

        def test_score_clamped_to_hundred(self):
            self.assertEqual(compute_security_score([]), 100)

        def test_mixed_findings(self):
            findings = [
                _make_finding("Critical"),   # -25
                _make_finding("High"),        # -15
                _make_finding("Medium"),      #  -7
                _make_finding("Low"),         #  -3
                _make_finding("Info"),        #   0
            ]
            # 100 - 25 - 15 - 7 - 3 = 50
            self.assertEqual(compute_security_score(findings), 50)

    # ─────────────────────────────────────────────────────────────────────────
    # DatabaseManager Tests
    # ─────────────────────────────────────────────────────────────────────────

    class TestDatabaseManagerSessions(unittest.TestCase):
        def setUp(self):
            self.db = DatabaseManager(":memory:")

        def test_create_session_returns_int(self):
            sid = self.db.create_session("https://example.com")
            self.assertIsInstance(sid, int)
            self.assertGreater(sid, 0)

        def test_get_session_returns_dict(self):
            sid = self.db.create_session("https://example.com", depth=2,
                                          modules=["headers", "sqli"])
            row = self.db.get_session(sid)
            self.assertIsNotNone(row)
            self.assertEqual(row["target"], "https://example.com")
            self.assertEqual(row["depth"], 2)
            self.assertIn("headers", row["modules"])

        def test_get_nonexistent_session_returns_none(self):
            self.assertIsNone(self.db.get_session(9999))

        def test_finish_session(self):
            sid = self.db.create_session("https://example.com")
            self.db.finish_session(sid, score=72)
            row = self.db.get_session(sid)
            self.assertEqual(row["status"], "completed")
            self.assertEqual(row["score"], 72)
            self.assertIsNotNone(row["finished_at"])

        def test_list_sessions(self):
            self.db.create_session("https://a.com")
            self.db.create_session("https://b.com")
            sessions = self.db.list_sessions()
            self.assertEqual(len(sessions), 2)
            # Most recent first
            self.assertEqual(sessions[0]["target"], "https://b.com")

        def test_delete_session(self):
            sid = self.db.create_session("https://example.com")
            self.db.delete_session(sid)
            self.assertIsNone(self.db.get_session(sid))

    class TestDatabaseManagerURLs(unittest.TestCase):
        def setUp(self):
            self.db = DatabaseManager(":memory:")
            self.sid = self.db.create_session("https://example.com")

        def test_save_and_retrieve_urls(self):
            pages = [_make_page(), _make_page()]
            pages[1]["url"] = "https://example.com/about"
            inserted = self.db.save_urls(self.sid, pages)
            self.assertEqual(inserted, 2)
            rows = self.db.get_urls(self.sid)
            self.assertEqual(len(rows), 2)

        def test_url_fields_persisted(self):
            self.db.save_urls(self.sid, [_make_page()])
            row = self.db.get_urls(self.sid)[0]
            self.assertEqual(row["status_code"], 200)
            self.assertEqual(row["depth"], 1)
            self.assertEqual(row["forms_found"], 2)

        def test_url_with_error_field(self):
            page = _make_page()
            page["error"] = "Connection refused"
            self.db.save_urls(self.sid, [page])
            row = self.db.get_urls(self.sid)[0]
            self.assertEqual(row["error"], "Connection refused")

    class TestDatabaseManagerPorts(unittest.TestCase):
        def setUp(self):
            self.db = DatabaseManager(":memory:")
            self.sid = self.db.create_session("https://example.com")

        def test_save_and_retrieve_ports(self):
            inserted = self.db.save_ports(self.sid, [_make_port_finding()])
            self.assertEqual(inserted, 1)
            rows = self.db.get_ports(self.sid)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["port"], 80)
            self.assertEqual(rows[0]["service"], "HTTP")

        def test_banner_parsed(self):
            self.db.save_ports(self.sid, [_make_port_finding()])
            row = self.db.get_ports(self.sid)[0]
            self.assertEqual(row["banner"], "banner data")

        def test_port_severity_stored(self):
            self.db.save_ports(self.sid, [_make_port_finding()])
            row = self.db.get_ports(self.sid)[0]
            self.assertEqual(row["severity"], "Low")

    class TestDatabaseManagerVulnerabilities(unittest.TestCase):
        def setUp(self):
            self.db = DatabaseManager(":memory:")
            self.sid = self.db.create_session("https://example.com")

        def test_save_and_retrieve_vulns(self):
            findings = [
                _make_finding("Critical", "XSS-001"),
                _make_finding("High", "HDR-001"),
                _make_finding("Low", "DIR-001"),
            ]
            inserted = self.db.save_vulnerabilities(self.sid, findings)
            self.assertEqual(inserted, 3)
            rows = self.db.get_vulnerabilities(self.sid)
            self.assertEqual(len(rows), 3)

        def test_vulns_sorted_by_severity(self):
            findings = [
                _make_finding("Low",      "L-001"),
                _make_finding("Critical", "C-001"),
                _make_finding("High",     "H-001"),
            ]
            self.db.save_vulnerabilities(self.sid, findings)
            rows = self.db.get_vulnerabilities(self.sid)
            self.assertEqual(rows[0]["severity"], "Critical")
            self.assertEqual(rows[1]["severity"], "High")
            self.assertEqual(rows[2]["severity"], "Low")

        def test_vuln_fields_persisted(self):
            self.db.save_vulnerabilities(self.sid, [_make_finding("High", "H-001")])
            row = self.db.get_vulnerabilities(self.sid)[0]
            self.assertEqual(row["finding_id"], "H-001")
            self.assertEqual(row["parameter"], "q")
            self.assertEqual(row["payload"], "<test>")

        def test_cascade_delete(self):
            self.db.save_vulnerabilities(self.sid, [_make_finding("High")])
            self.db.delete_session(self.sid)
            # Vulns should be gone
            rows = self.db.get_vulnerabilities(self.sid)
            self.assertEqual(rows, [])

    # ─────────────────────────────────────────────────────────────────────────
    # ReportGenerator Tests
    # ─────────────────────────────────────────────────────────────────────────

    class TestReportGeneratorJSON(unittest.TestCase):
        def setUp(self):
            self.findings = [
                _make_finding("Critical", "XSS-001"),
                _make_finding("High",     "HDR-001"),
                _make_finding("Info",     "HDR-001-OK"),
            ]
            self.gen = ReportGenerator(
                target="https://example.com",
                findings=self.findings,
                score=60,
                session_id=1,
                scan_modules=["headers", "xss"],
            )

        def test_to_json_returns_bytes(self):
            result = self.gen.to_json()
            self.assertIsInstance(result, bytes)

        def test_json_is_valid(self):
            data = json.loads(self.gen.to_json())
            self.assertIn("report_metadata", data)
            self.assertIn("findings", data)

        def test_json_metadata_fields(self):
            meta = json.loads(self.gen.to_json())["report_metadata"]
            self.assertEqual(meta["target"], "https://example.com")
            self.assertEqual(meta["session_id"], 1)
            self.assertEqual(meta["security_score"], 60)
            self.assertEqual(meta["total_findings"], 3)

        def test_json_severity_counts(self):
            counts = json.loads(self.gen.to_json())["report_metadata"]["severity_counts"]
            self.assertEqual(counts["Critical"], 1)
            self.assertEqual(counts["High"], 1)
            self.assertEqual(counts["Info"], 1)

        def test_json_findings_sorted_by_severity(self):
            findings = json.loads(self.gen.to_json())["findings"]
            sevs = [f["severity"] for f in findings]
            self.assertEqual(sevs[0], "Critical")
            self.assertEqual(sevs[-1], "Info")

        def test_json_empty_findings(self):
            gen = ReportGenerator("https://example.com", findings=[], score=100)
            data = json.loads(gen.to_json())
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["report_metadata"]["total_findings"], 0)

    class TestReportGeneratorHTML(unittest.TestCase):
        def setUp(self):
            self.findings = [
                _make_finding("Critical", "SQLI-001"),
                _make_finding("High",     "XSS-001"),
                _make_finding("Medium",   "HDR-003"),
                _make_finding("Info",     "CKI-000"),
            ]
            self.gen = ReportGenerator(
                target="https://example.com",
                findings=self.findings,
                score=48,
                session_id=7,
            )

        def test_to_html_returns_bytes(self):
            result = self.gen.to_html()
            self.assertIsInstance(result, bytes)

        def test_html_is_decodable_utf8(self):
            html = self.gen.to_html().decode("utf-8")
            self.assertIn("<!DOCTYPE html>", html)

        def test_html_contains_target(self):
            html = self.gen.to_html().decode("utf-8")
            self.assertIn("example.com", html)

        def test_html_contains_score(self):
            html = self.gen.to_html().decode("utf-8")
            self.assertIn("48", html)

        def test_html_contains_finding_titles(self):
            html = self.gen.to_html().decode("utf-8")
            self.assertIn("Test Critical", html)
            self.assertIn("Test High", html)

        def test_html_contains_severity_badges(self):
            html = self.gen.to_html().decode("utf-8")
            for sev in ("Critical", "High", "Medium", "Info"):
                self.assertIn(sev, html)

        def test_html_escapes_xss_in_evidence(self):
            f = _make_finding("High", "XSS-T")
            f["evidence"] = '<script>alert(1)</script>'
            gen = ReportGenerator("https://example.com", findings=[f], score=85)
            html = gen.to_html().decode("utf-8")
            # Raw tag must NOT appear unescaped
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;", html)

        def test_html_no_findings_shows_placeholder(self):
            gen = ReportGenerator("https://example.com", findings=[], score=100)
            html = gen.to_html().decode("utf-8")
            self.assertIn("No findings recorded", html)

    # ── Run ────────────────────────────────────────────────────────────────────
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in (
        TestComputeSecurityScore,
        TestDatabaseManagerSessions,
        TestDatabaseManagerURLs,
        TestDatabaseManagerPorts,
        TestDatabaseManagerVulnerabilities,
        TestReportGeneratorJSON,
        TestReportGeneratorHTML,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
