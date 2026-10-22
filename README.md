# WebScanner AI 🛡️

> **Automated Web Security Scanner** — Crawl, audit, and report vulnerabilities in web applications from a clean, dark-themed Streamlit dashboard.

---

## ⚠️ Legal Disclaimer

> **This tool is intended strictly for authorised security testing and educational purposes.**  
> Only scan systems you own or have **explicit written permission** to test.  
> Unauthorised scanning may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction. The authors accept no liability for misuse.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Running the App](#running-the-app)
- [Usage Guide](#usage-guide)
- [Security Score Calculation](#security-score-calculation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**WebScanner AI** is a Python-based automated web vulnerability scanner with an interactive Streamlit dashboard. It combines multiple scanning modules — crawling, header auditing, injection probing, port scanning, and directory brute-forcing — into a single unified interface. Results are persisted locally in a SQLite database and can be exported as JSON, CSV, HTML, or PDF reports.

---

## Features

| Module | Description |
|--------|-------------|
| 🕷️ **URL Crawler** | Recursively crawls target pages up to depth 3, extracting all internal links |
| 🔒 **Header / SSL Audit** | Checks for missing security headers (CSP, HSTS, X-Frame-Options …) and validates TLS certificates |
| 💉 **SQLi Probes** | Injects SQL payloads into form fields and URL parameters; detects database error signatures |
| 🎭 **XSS Probes** | Injects XSS payloads and checks for unencoded reflection in responses |
| 🔌 **Port Scanner** | TCP connect scan on common ports with service banner grabbing |
| 📂 **Dir Brute-force** | Wordlist-based discovery of hidden paths and sensitive files |
| 📊 **Dashboard** | Live metric cards, severity-grouped findings, and a Security Score (0–100) |
| 📤 **Report Export** | One-click export to JSON, CSV, HTML, or PDF |

---

## Tech Stack

| Library | Version | Purpose |
|---------|---------|---------|
| [`streamlit`](https://streamlit.io) | ≥ 1.35 | Interactive web dashboard / GUI |
| [`requests`](https://docs.python-requests.org) | ≥ 2.31 | HTTP client for crawling and probe requests |
| [`beautifulsoup4`](https://www.crummy.com/software/BeautifulSoup/) | ≥ 4.12 | HTML parsing and link/form extraction |
| [`lxml`](https://lxml.de) | ≥ 5.0 | Fast HTML/XML parser backend for BeautifulSoup |
| `socket` | stdlib | TCP port scanning and hostname resolution |
| `ssl` | stdlib | TLS certificate inspection |
| `sqlite3` | stdlib | Local persistence of scan history and findings |
| [`fpdf2`](https://py-pdf.github.io/fpdf2/) | ≥ 2.7 | PDF report generation |
| [`pandas`](https://pandas.pydata.org) | ≥ 2.0 | Tabular data handling and CSV export |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Streamlit Frontend                  │
│  Sidebar Config → Metric Cards → Tabs (Results /    │
│  Vulnerability Details / Export Report)             │
└───────────────────────┬─────────────────────────────┘
                        │ triggers
                        ▼
┌─────────────────────────────────────────────────────┐
│               Scan Orchestrator                     │
│  Reads config → dispatches enabled modules in order │
└──┬──────────┬──────────┬──────────┬──────────┬──────┘
   │          │          │          │          │
   ▼          ▼          ▼          ▼          ▼
┌──────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌─────────┐
│Crawl │ │Header/ │ │ SQLi / │ │  Port  │ │  Dir    │
│Engine│ │SSL Aud.│ │  XSS   │ │Scanner │ │Brute-   │
│      │ │        │ │ Probes │ │(socket)│ │ force   │
└──┬───┘ └───┬────┘ └───┬────┘ └───┬────┘ └────┬────┘
   │         │          │          │            │
   └─────────┴──────────┴──────────┴────────────┘
                        │ findings[]
                        ▼
              ┌─────────────────┐
              │  SQLite DB      │
              │  scanner.db     │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Report Builder  │
              │ JSON/CSV/HTML/  │
              │ PDF             │
              └─────────────────┘
```

**Workflow summary:**

1. User enters a target URL, selects scan depth, and toggles scan modules in the sidebar.
2. On **Start Scan**, the orchestrator sequentially runs each enabled module.
3. The crawler builds the URL inventory first; all subsequent modules operate on that inventory.
4. Each module appends structured `Finding` objects (severity, URL, evidence, remediation) to a shared results list.
5. Findings are persisted to `scanner.db` and immediately surfaced in the dashboard tabs.
6. The Security Score is recalculated after all modules complete.
7. Users can export the full report from the **Export Report** tab.

---

## Project Structure

```
web-scanner/
├── app.py                  # Streamlit entry point & dashboard UI
├── requirements.txt        # Python dependencies
├── REQUIREMENTS.md         # Software Requirements Specification (SRS)
├── README.md               # This file
│
├── scanner/                # Core scanning modules (production build)
│   ├── __init__.py
│   ├── crawler.py          # URL crawling engine (requests + BeautifulSoup)
│   ├── header_audit.py     # HTTP header and SSL/TLS checks
│   ├── sqli_probe.py       # SQL Injection detection
│   ├── xss_probe.py        # Cross-Site Scripting detection
│   ├── port_scanner.py     # TCP port scanner (socket)
│   ├── dir_bruteforce.py   # Directory brute-forcing
│   ├── orchestrator.py     # Dispatches and coordinates all modules
│   └── report.py           # Report generation (JSON / CSV / HTML / PDF)
│
├── data/
│   ├── payloads_sqli.txt   # SQLi test payload wordlist
│   ├── payloads_xss.txt    # XSS test payload wordlist
│   └── wordlist_dirs.txt   # Directory brute-force wordlist
│
└── scanner.db              # SQLite scan history (auto-created on first run)
```

> **Note:** The `scanner/` package and `data/` payloads represent the production architecture. The current `app.py` contains a self-contained demo with mock data. See the [Roadmap](#roadmap) for integration plans.

---

## Prerequisites

- **Python 3.9 or higher**
- **pip** (bundled with Python)
- Outbound network access to your authorised scan target

Verify your Python version:

```bash
python --version
# Python 3.x.x  (must be 3.9+)
```

---

## Installation & Setup

### 1 — Clone the repository

```bash
git clone https://github.com/your-org/webscanner-ai.git
cd webscanner-ai
```

### 2 — (Recommended) Create a virtual environment

```bash
# Create
python -m venv .venv

# Activate — macOS / Linux
source .venv/bin/activate

# Activate — Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the App

```bash
streamlit run app.py
```

Streamlit will start a local server and open the dashboard automatically. If it does not open, navigate to:

```
http://localhost:8501
```

To stop the app, press `Ctrl + C` in the terminal.

---

## Usage Guide

1. **Enter Target URL** — Type the full URL (including `https://`) of the site you are authorised to scan.
2. **Set Scan Depth** — Use the slider to choose depth 1 (surface only), 2 (linked pages), or 3 (deep crawl).
3. **Select Modules** — Enable the scan modules you want to run via the checkboxes.
4. **Start Scan** — Click the green **🚀 Start Scan** button. A progress spinner will appear during execution.
5. **Review Results** — Findings populate the three dashboard tabs once the scan completes:
   - **📋 Scan Results** — full list of discovered URLs and module outputs
   - **🔎 Vulnerability Details** — per-finding severity, evidence, and remediation advice
   - **📤 Export Report** — download the report in your preferred format
6. **Iterate** — Adjust configuration and re-scan as needed; history is saved to `scanner.db`.

---

## Security Score Calculation

The Security Score (0–100) is computed using a weighted penalty model:

| Severity | Weight |
|----------|--------|
| Critical | −20 pts per finding |
| High | −10 pts per finding |
| Medium | −5 pts per finding |
| Low | −2 pts per finding |

Starting from a perfect score of **100**, penalties are applied and the result is clamped to a minimum of **0**. A score ≥ 60 is displayed in green; below 60 is displayed in red.

---

## Roadmap

- [ ] Integrate real crawler engine (`requests` + `BeautifulSoup`)
- [ ] Implement live SQLi/XSS probing with payload files
- [ ] Add authenticated scanning (session cookie / Bearer token support)
- [ ] Implement concurrent scanning with `asyncio` / `ThreadPoolExecutor`
- [ ] Add OWASP ZAP API integration as an optional back-end
- [ ] Nuclei template runner integration
- [ ] Scan scheduling and diff-based alerts
- [ ] Docker image for zero-install deployment

---

## Contributing

1. Fork the repository and create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes following PEP 8 conventions and add docstrings to all public functions.
3. Run the test suite: `pytest tests/`
4. Submit a pull request with a clear description of the change and its motivation.

Please read `CONTRIBUTING.md` (coming soon) before submitting large changes.

---

## License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

*WebScanner AI — built for defenders, by defenders.*
