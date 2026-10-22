# Software Requirements Specification (SRS)
## WebScanner AI — Automated Web Security Scanner

**Document Version:** 1.0  
**Status:** Draft  
**Last Updated:** 2025  

---

## Table of Contents

1. [Introduction](#1-introduction)  
2. [Overall Description](#2-overall-description)  
3. [Functional Requirements](#3-functional-requirements)  
4. [Non-Functional Requirements](#4-non-functional-requirements)  
5. [System Constraints](#5-system-constraints)  
6. [Assumptions and Dependencies](#6-assumptions-and-dependencies)  

---

## 1. Introduction

### 1.1 Purpose
This document specifies the software requirements for **WebScanner AI**, an automated web security scanning tool. It is intended for developers, QA engineers, and security reviewers involved in the design, implementation, and testing of the system.

### 1.2 Scope
WebScanner AI provides an interactive dashboard for performing reconnaissance and vulnerability assessment on web targets. It detects common security misconfigurations, injects test payloads to discover injection flaws, enumerates open ports, and produces structured reports — all from a single Streamlit-based interface.

### 1.3 Definitions and Acronyms

| Term | Definition |
|------|------------|
| SRS  | Software Requirements Specification |
| SQLi | SQL Injection — an attack where malicious SQL is inserted into an input field |
| XSS  | Cross-Site Scripting — injection of client-side scripts into web pages |
| HSTS | HTTP Strict Transport Security — a web security policy mechanism |
| CVE  | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| CSP  | Content Security Policy |
| GUI  | Graphical User Interface |

### 1.4 References
- OWASP Top 10 (2021): https://owasp.org/Top10/
- NIST SP 800-115 Technical Guide to Information Security Testing
- RFC 7230 — HTTP/1.1 Message Syntax and Routing

---

## 2. Overall Description

### 2.1 Product Perspective
WebScanner AI is a standalone desktop/local-server application. It does not depend on external cloud scanning APIs and runs entirely within the user's environment. The front-end is provided by Streamlit; the back-end scanning logic is implemented in pure Python using standard and third-party libraries.

### 2.2 Product Functions (Summary)

- Crawl target web applications up to a configurable depth  
- Audit HTTP response headers and TLS/SSL certificate configurations  
- Probe for SQL Injection and Cross-Site Scripting vulnerabilities  
- Enumerate open TCP ports on the target host  
- Perform directory and file brute-forcing  
- Persist scan results to a local SQLite database  
- Generate exportable reports (PDF, JSON, CSV, HTML)  

### 2.3 User Classes

| Class | Description |
|-------|-------------|
| Security Analyst | Primary user; runs scans and interprets results |
| Developer | Uses scanner to validate own applications during development |
| Administrator | Manages scan history and configures scanner settings |

### 2.4 Operating Environment
- **OS:** Windows 10/11, macOS 12+, Ubuntu 20.04+  
- **Python:** 3.9 or higher  
- **Network:** Outbound HTTP/HTTPS access to target; raw socket access for port scanning  
- **Browser:** Any modern browser (Chrome, Firefox, Edge) for the Streamlit UI  

---

## 3. Functional Requirements

### FR-01 — URL Crawling

| ID | Requirement |
|----|-------------|
| FR-01.1 | The system SHALL accept a fully qualified URL (including scheme) as the scan target. |
| FR-01.2 | The system SHALL crawl the target recursively up to a user-selected depth of 1, 2, or 3. |
| FR-01.3 | The crawler SHALL extract all `<a href>` links from each discovered page using BeautifulSoup. |
| FR-01.4 | The crawler SHALL respect the target domain scope and SHALL NOT follow links to external domains unless explicitly configured. |
| FR-01.5 | The system SHALL track visited URLs in-memory to prevent duplicate requests. |
| FR-01.6 | The system SHALL record the HTTP status code, response time, and content-type for each crawled URL. |
| FR-01.7 | The system SHALL handle HTTP redirects (3xx) and follow them up to a configurable redirect limit (default: 5). |
| FR-01.8 | Crawl results SHALL be stored in the local SQLite database with a timestamp. |

---

### FR-02 — HTTP Header and SSL/TLS Audit

| ID | Requirement |
|----|-------------|
| FR-02.1 | The system SHALL check each response for the presence of the following security headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. |
| FR-02.2 | Each missing or misconfigured header SHALL be recorded as a finding with a severity level (Low / Medium / High). |
| FR-02.3 | The system SHALL verify that the target serves content over HTTPS. |
| FR-02.4 | The system SHALL validate the TLS certificate: expiry date, issuer, subject, and whether it matches the target hostname. |
| FR-02.5 | Expired or self-signed certificates SHALL be reported as High severity findings. |
| FR-02.6 | The presence of deprecated TLS versions (TLS 1.0, TLS 1.1) SHALL be reported as a Medium severity finding. |

---

### FR-03 — SQL Injection (SQLi) Detection

| ID | Requirement |
|----|-------------|
| FR-03.1 | The system SHALL discover all HTML forms on crawled pages and extract input field names and `action` URLs. |
| FR-03.2 | The system SHALL inject a standard set of SQLi test payloads (e.g., `'`, `' OR '1'='1`, `"; DROP TABLE--`) into each discovered parameter. |
| FR-03.3 | The system SHALL analyse HTTP responses for known database error strings (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) to identify potential SQLi vulnerabilities. |
| FR-03.4 | Positive SQLi detections SHALL be recorded with the affected URL, parameter name, payload used, and a snippet of the response body. |
| FR-03.5 | SQLi findings SHALL be rated **Critical** severity by default. |

---

### FR-04 — Cross-Site Scripting (XSS) Detection

| ID | Requirement |
|----|-------------|
| FR-04.1 | The system SHALL inject XSS probe payloads (e.g., `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`) into form fields and URL query parameters. |
| FR-04.2 | The system SHALL check whether the injected payload is reflected unencoded in the HTTP response body (Reflected XSS). |
| FR-04.3 | XSS findings SHALL be recorded with the affected URL, parameter, payload, and response snippet. |
| FR-04.4 | Reflected XSS findings SHALL be rated **High** severity. |

---

### FR-05 — Port Scanning

| ID | Requirement |
|----|-------------|
| FR-05.1 | The system SHALL resolve the target hostname to an IP address using the `socket` library. |
| FR-05.2 | The system SHALL perform a TCP connect scan on a configurable list of common ports (default: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443). |
| FR-05.3 | Each port scan attempt SHALL have a configurable timeout (default: 1 second). |
| FR-05.4 | The system SHALL record all open ports and attempt service banner grabbing where possible. |
| FR-05.5 | Sensitive open ports (e.g., 22-SSH, 3306-MySQL, 3389-RDP) SHALL generate Medium or High findings. |

---

### FR-06 — Directory and File Brute-Forcing

| ID | Requirement |
|----|-------------|
| FR-06.1 | The system SHALL attempt to access a configurable wordlist of common paths (e.g., `/admin`, `/login`, `/.env`, `/backup.zip`). |
| FR-06.2 | Any path returning an HTTP 200 or 403 response SHALL be recorded as a discovered resource. |
| FR-06.3 | Sensitive paths (e.g., `/.env`, `/wp-admin`, `/phpmyadmin`) SHALL be flagged as High severity findings. |
| FR-06.4 | The brute-force module SHALL respect a configurable request rate limit to avoid overwhelming the target. |

---

### FR-07 — Reporting and Export

| ID | Requirement |
|----|-------------|
| FR-07.1 | The system SHALL display all findings in the **Scan Results** tab, grouped by severity (Critical → High → Medium → Low → Informational). |
| FR-07.2 | The **Vulnerability Details** tab SHALL show, for each finding: severity badge, affected URL, description, evidence snippet, and remediation advice. |
| FR-07.3 | The system SHALL support exporting the full report in the following formats: JSON, CSV, HTML, and PDF. |
| FR-07.4 | All scan records SHALL be persisted to a local SQLite database (`scanner.db`) for historical review. |
| FR-07.5 | The dashboard SHALL display a **Security Score** (0–100) computed from the weighted severity of all findings. |

---

### FR-08 — Dashboard and UX

| ID | Requirement |
|----|-------------|
| FR-08.1 | The application SHALL provide a Streamlit-based GUI accessible via a local web browser. |
| FR-08.2 | The sidebar SHALL contain all scan configuration controls: target URL, depth, and module toggles. |
| FR-08.3 | Four metric cards SHALL display live summary statistics after each scan. |
| FR-08.4 | A progress indicator SHALL be visible during active scanning operations. |
| FR-08.5 | The interface SHALL use a dark theme with accessible contrast ratios. |

---

## 4. Non-Functional Requirements

### NFR-01 — Performance

| ID | Requirement |
|----|-------------|
| NFR-01.1 | The crawler SHALL complete a depth-1 scan of a 50-page site in under 30 seconds on a standard broadband connection. |
| NFR-01.2 | Port scanning of the default 16-port list SHALL complete within 20 seconds (1 s timeout per port). |
| NFR-01.3 | The Streamlit UI SHALL remain responsive (no blocking) during scan execution by running scan tasks asynchronously or in a background thread. |
| NFR-01.4 | Memory usage SHALL not exceed 512 MB during a depth-2 scan of a site with up to 500 pages. |

### NFR-02 — Reliability and Error Handling

| ID | Requirement |
|----|-------------|
| NFR-02.1 | The system SHALL gracefully handle network errors (connection timeout, DNS failure, SSL error) without crashing, logging a descriptive error message for each failed request. |
| NFR-02.2 | Invalid or unreachable target URLs SHALL produce a clear user-facing error message within 5 seconds. |
| NFR-02.3 | Malformed HTML that causes parser errors SHALL be caught and logged; the crawler SHALL continue to the next URL. |
| NFR-02.4 | Database write failures SHALL be caught and surfaced to the user; the scan SHALL continue and results SHALL be held in memory. |

### NFR-03 — Security

| ID | Requirement |
|----|-------------|
| NFR-03.1 | The application SHALL NOT store any credentials or session tokens in plain text. |
| NFR-03.2 | The tool SHALL include a visible disclaimer requiring users to confirm they have authorisation to scan the target. |
| NFR-03.3 | No scan data SHALL be transmitted to external servers; all processing is local. |

### NFR-04 — Maintainability

| ID | Requirement |
|----|-------------|
| NFR-04.1 | Each scanning module (crawler, header audit, SQLi, XSS, port scan, brute-force) SHALL be implemented as an independent Python module or class for ease of extension. |
| NFR-04.2 | SQLi/XSS payload lists SHALL be stored in separate plain-text files to allow updates without code changes. |
| NFR-04.3 | The codebase SHALL follow PEP 8 style conventions and include docstrings on all public functions. |

### NFR-05 — Portability

| ID | Requirement |
|----|-------------|
| NFR-05.1 | The application SHALL run on Windows, macOS, and Linux without platform-specific modifications. |
| NFR-05.2 | All dependencies SHALL be installable via `pip` from PyPI without requiring system-level packages. |

---

## 5. System Constraints

- **Legal:** The tool must only be used against systems the operator owns or has written permission to test. Misuse may violate the Computer Fraud and Abuse Act (CFAA) or equivalent local legislation.  
- **Network:** Raw socket operations (port scanning) may require elevated privileges on some operating systems.  
- **Rate Limiting:** Aggressive scanning may trigger WAFs, CDN rate-limits, or IP bans on the target.  
- **Scope:** The current version targets HTTP/HTTPS applications only; non-HTTP services are out of scope except for port identification.  

---

## 6. Assumptions and Dependencies

| # | Assumption / Dependency |
|---|-------------------------|
| 1 | Python 3.9+ is installed on the host machine. |
| 2 | The host machine has outbound internet access to the scan target. |
| 3 | `pip` is available and functional for dependency installation. |
| 4 | The user has obtained explicit written authorisation before scanning any target. |
| 5 | The target web application serves standard HTTP/HTTPS responses parseable by `requests` + `BeautifulSoup`. |
| 6 | SQLite is available (bundled with Python's standard library). |
