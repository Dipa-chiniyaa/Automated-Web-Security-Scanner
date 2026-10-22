"""
scanners.py
===========
Two diagnostic tools for the WebScanner AI project:

  • HeaderScanner — audits HTTP response headers, cookie flags, and CORS policy.
  • PortScanner   — multi-threaded TCP port scan using socket + concurrent.futures.

Both tools return findings as a list of structured dicts:

    {
        "id"         : str,          # unique finding identifier, e.g. "HDR-001"
        "title"      : str,          # short human-readable label
        "severity"   : str,          # "Critical" | "High" | "Medium" | "Low" | "Info"
        "category"   : str,          # logical group, e.g. "Security Headers"
        "description": str,          # what was found / why it matters
        "evidence"   : str | None,   # raw header value or port/service info
        "remediation": str,          # actionable fix advice
    }

Usage
-----
    from scanners import HeaderScanner, PortScanner

    hs = HeaderScanner("https://example.com")
    header_findings = hs.scan()

    ps = PortScanner("example.com")
    port_findings = ps.scan()
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookiejar import CookieJar
from typing import Optional
from urllib.parse import urlparse

import requests

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Shared constants ──────────────────────────────────────────────────────────
DEFAULT_HTTP_TIMEOUT: int = 10        # seconds
DEFAULT_PORT_TIMEOUT: float = 1.0     # seconds per port probe
DEFAULT_USER_AGENT: str = "WebScannerAI/1.0 (security-audit; authorised)"
MAX_WORKERS: int = 20                 # thread-pool size for port scanning

# Common ports with known service names
COMMON_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Ports whose exposure warrants a High finding
HIGH_RISK_PORTS: frozenset[int] = frozenset({21, 23, 3306, 3389, 5432, 6379, 445})
# Ports that are Medium risk when open externally
MEDIUM_RISK_PORTS: frozenset[int] = frozenset({22, 25, 110, 143})


# ── Finding factory ───────────────────────────────────────────────────────────

def _finding(
    fid: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    remediation: str,
    evidence: Optional[str] = None,
) -> dict:
    """Return a normalised finding dictionary."""
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HeaderScanner
# ─────────────────────────────────────────────────────────────────────────────

class HeaderScanner:
    """
    Audits the HTTP response headers of a target URL for security
    misconfigurations, weak cookie attributes, and dangerous CORS policies.

    Parameters
    ----------
    target_url : str
        Fully-qualified URL to scan (must include http:// or https://).
    timeout : int
        Request timeout in seconds. Defaults to DEFAULT_HTTP_TIMEOUT.
    user_agent : str
        User-Agent header sent with the probe request.
    follow_redirects : bool
        Whether to follow redirects before inspecting headers. Default True.
    """

    # Security headers that MUST be present, with per-header metadata
    _REQUIRED_HEADERS: list[dict] = [
        {
            "header": "Strict-Transport-Security",
            "id": "HDR-001",
            "severity": "High",
            "description": (
                "HTTP Strict Transport Security (HSTS) is missing. Without HSTS the "
                "browser may connect over plain HTTP, enabling downgrade attacks and "
                "SSL-stripping."
            ),
            "remediation": (
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
        },
        {
            "header": "Content-Security-Policy",
            "id": "HDR-002",
            "severity": "High",
            "description": (
                "Content-Security-Policy (CSP) is absent. Without CSP, the browser "
                "places no restrictions on script/style sources, making XSS attacks "
                "significantly easier to exploit."
            ),
            "remediation": (
                "Define a strict CSP. Example: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'"
            ),
        },
        {
            "header": "X-Frame-Options",
            "id": "HDR-003",
            "severity": "Medium",
            "description": (
                "X-Frame-Options is not set. The page can be embedded in an <iframe>, "
                "enabling clickjacking attacks."
            ),
            "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally)",
        },
        {
            "header": "X-Content-Type-Options",
            "id": "HDR-004",
            "severity": "Medium",
            "description": (
                "X-Content-Type-Options is missing. Browsers may MIME-sniff responses "
                "and execute content with an incorrect content-type, enabling sniffing attacks."
            ),
            "remediation": "Add: X-Content-Type-Options: nosniff",
        },
        {
            "header": "Referrer-Policy",
            "id": "HDR-005",
            "severity": "Low",
            "description": (
                "Referrer-Policy is not present. Full URLs (including path and query "
                "string) may be leaked to third-party sites via the Referer header."
            ),
            "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        {
            "header": "Permissions-Policy",
            "id": "HDR-006",
            "severity": "Low",
            "description": (
                "Permissions-Policy (formerly Feature-Policy) is absent. Browser "
                "features such as camera, microphone, and geolocation are unrestricted."
            ),
            "remediation": (
                "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
            ),
        },
    ]

    def __init__(
        self,
        target_url: str,
        timeout: int = DEFAULT_HTTP_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
    ) -> None:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"target_url must use http/https, got: {target_url!r}")
        self.target_url = target_url
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self._session = requests.Session()
        self._session.headers["User-Agent"] = user_agent

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> dict:
        """
        Perform the full header audit.

        Returns
        -------
        dict with keys:
            "target"        : str
            "status_code"   : int | None
            "response_time_ms" : float | None
            "findings"      : list[dict]
            "error"         : str | None
        """
        resp, err = self._fetch()
        if err or resp is None:
            return {
                "target": self.target_url,
                "status_code": None,
                "response_time_ms": None,
                "findings": [],
                "error": err,
            }

        findings: list[dict] = []
        headers = resp.headers  # CaseInsensitiveDict

        findings.extend(self._audit_security_headers(headers))
        findings.extend(self._audit_cookies(resp))
        findings.extend(self._audit_cors(headers))
        findings.extend(self._audit_information_disclosure(headers))

        elapsed_ms = round(resp.elapsed.total_seconds() * 1000, 2)
        logger.info(
            "HeaderScanner finished for %s — %d finding(s)", self.target_url, len(findings)
        )

        return {
            "target": self.target_url,
            "status_code": resp.status_code,
            "response_time_ms": elapsed_ms,
            "findings": findings,
            "error": None,
        }

    # ── HTTP fetch ────────────────────────────────────────────────────────────

    def _fetch(self) -> tuple[Optional[requests.Response], Optional[str]]:
        try:
            resp = self._session.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=True,
            )
            return resp, None
        except requests.exceptions.SSLError as exc:
            return None, f"SSL error: {exc}"
        except requests.exceptions.ConnectionError as exc:
            return None, f"Connection error: {exc}"
        except requests.exceptions.Timeout:
            return None, f"Request timed out after {self.timeout}s"
        except requests.exceptions.RequestException as exc:
            return None, f"Request failed: {exc}"

    # ── Audit methods ─────────────────────────────────────────────────────────

    def _audit_security_headers(self, headers: requests.structures.CaseInsensitiveDict) -> list[dict]:
        """Check for required security response headers."""
        findings: list[dict] = []
        for spec in self._REQUIRED_HEADERS:
            hdr = spec["header"]
            if hdr not in headers:
                findings.append(_finding(
                    fid=spec["id"],
                    title=f"Missing Header: {hdr}",
                    severity=spec["severity"],
                    category="Security Headers",
                    description=spec["description"],
                    remediation=spec["remediation"],
                    evidence=None,
                ))
            else:
                # Header present — log informational confirmation
                findings.append(_finding(
                    fid=f"{spec['id']}-OK",
                    title=f"Header Present: {hdr}",
                    severity="Info",
                    category="Security Headers",
                    description=f"'{hdr}' is configured.",
                    remediation="No action required.",
                    evidence=headers[hdr],
                ))
        return findings

    def _audit_cookies(self, resp: requests.Response) -> list[dict]:
        """Inspect Set-Cookie headers for missing security flags."""
        findings: list[dict] = []
        raw_cookies = resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else []

        # requests.structures.CaseInsensitiveDict doesn't expose getlist;
        # iterate the raw headers via response.raw.headers if available,
        # otherwise fall back to the single merged header value.
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:  # noqa: BLE001
            raw_set_cookie = resp.headers.get("Set-Cookie", "")
            raw_cookies = [raw_set_cookie] if raw_set_cookie else []

        for idx, cookie_str in enumerate(raw_cookies, start=1):
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()
            cid_base = f"CKI-{idx:03d}"

            if "httponly" not in cookie_lower:
                findings.append(_finding(
                    fid=f"{cid_base}-A",
                    title=f"Cookie Missing HttpOnly: {name}",
                    severity="Medium",
                    category="Cookie Security",
                    description=(
                        f"Cookie '{name}' does not have the HttpOnly flag. "
                        "Client-side JavaScript can read this cookie, aiding XSS-based "
                        "session hijacking."
                    ),
                    remediation=f"Set the HttpOnly flag on cookie '{name}'.",
                    evidence=cookie_str,
                ))

            if "secure" not in cookie_lower:
                findings.append(_finding(
                    fid=f"{cid_base}-B",
                    title=f"Cookie Missing Secure Flag: {name}",
                    severity="Medium",
                    category="Cookie Security",
                    description=(
                        f"Cookie '{name}' lacks the Secure flag. It may be transmitted "
                        "over unencrypted HTTP connections."
                    ),
                    remediation=f"Add the Secure attribute to cookie '{name}'.",
                    evidence=cookie_str,
                ))

            if "samesite" not in cookie_lower:
                findings.append(_finding(
                    fid=f"{cid_base}-C",
                    title=f"Cookie Missing SameSite: {name}",
                    severity="Low",
                    category="Cookie Security",
                    description=(
                        f"Cookie '{name}' has no SameSite attribute. Cross-site request "
                        "forgery (CSRF) attacks may be easier to conduct."
                    ),
                    remediation=f"Add SameSite=Strict or SameSite=Lax to cookie '{name}'.",
                    evidence=cookie_str,
                ))

        if not raw_cookies:
            findings.append(_finding(
                fid="CKI-000",
                title="No Set-Cookie Headers Observed",
                severity="Info",
                category="Cookie Security",
                description="The response did not set any cookies.",
                remediation="No action required.",
            ))

        return findings

    def _audit_cors(self, headers: requests.structures.CaseInsensitiveDict) -> list[dict]:
        """Evaluate CORS policy headers."""
        findings: list[dict] = []
        acao = headers.get("Access-Control-Allow-Origin", "")

        if not acao:
            findings.append(_finding(
                fid="CORS-001",
                title="CORS: Access-Control-Allow-Origin Not Set",
                severity="Info",
                category="CORS Policy",
                description="No CORS policy is configured on this response.",
                remediation=(
                    "If cross-origin access is needed, define an explicit allowlist. "
                    "If not, no header is required."
                ),
            ))
        elif acao.strip() == "*":
            findings.append(_finding(
                fid="CORS-002",
                title="CORS: Wildcard Origin Allowed",
                severity="High",
                category="CORS Policy",
                description=(
                    "Access-Control-Allow-Origin is set to '*', allowing any origin to "
                    "make cross-origin requests. Combined with credentialed requests this "
                    "can expose sensitive data to attacker-controlled sites."
                ),
                remediation=(
                    "Replace '*' with an explicit allowlist of trusted origins. "
                    "Never combine '*' with Access-Control-Allow-Credentials: true."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}",
            ))
        else:
            findings.append(_finding(
                fid="CORS-003",
                title="CORS: Specific Origin(s) Allowed",
                severity="Info",
                category="CORS Policy",
                description=f"CORS is restricted to: {acao}",
                remediation="Verify this origin allowlist is intentional and minimal.",
                evidence=f"Access-Control-Allow-Origin: {acao}",
            ))

        # Dangerous combination: credentials + wildcard
        acac = headers.get("Access-Control-Allow-Credentials", "").lower()
        if acac == "true" and acao.strip() == "*":
            findings.append(_finding(
                fid="CORS-004",
                title="CORS: Credentials Allowed with Wildcard Origin",
                severity="Critical",
                category="CORS Policy",
                description=(
                    "Access-Control-Allow-Credentials: true combined with a wildcard origin "
                    "is a critical misconfiguration. Browsers block this combination per "
                    "spec, but its presence signals a broken CORS policy that may allow "
                    "authentication bypass via other means."
                ),
                remediation=(
                    "Remove the wildcard and specify exact trusted origins. "
                    "Never set both Allow-Credentials: true and Allow-Origin: *."
                ),
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}  |  "
                    f"Access-Control-Allow-Credentials: {acac}"
                ),
            ))

        return findings

    def _audit_information_disclosure(
        self, headers: requests.structures.CaseInsensitiveDict
    ) -> list[dict]:
        """Flag headers that leak server/technology details."""
        findings: list[dict] = []

        server = headers.get("Server", "")
        if server:
            # Detailed version strings are a concern; generic values are Info only
            import re
            if re.search(r"[\d.]{3,}", server):
                findings.append(_finding(
                    fid="INFO-001",
                    title="Server Version Disclosure",
                    severity="Low",
                    category="Information Disclosure",
                    description=(
                        f"The Server header reveals a version number: '{server}'. "
                        "Attackers can use this to identify vulnerable software versions."
                    ),
                    remediation=(
                        "Configure the web server to suppress version information "
                        "(e.g., ServerTokens Prod in Apache, server_tokens off in Nginx)."
                    ),
                    evidence=f"Server: {server}",
                ))
            else:
                findings.append(_finding(
                    fid="INFO-001",
                    title="Server Header Present (No Version)",
                    severity="Info",
                    category="Information Disclosure",
                    description=f"Server header is present but does not expose a version: '{server}'.",
                    remediation="Consider removing the Server header entirely for defence in depth.",
                    evidence=f"Server: {server}",
                ))

        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            findings.append(_finding(
                fid="INFO-002",
                title="X-Powered-By Header Exposes Technology Stack",
                severity="Low",
                category="Information Disclosure",
                description=(
                    f"X-Powered-By reveals the application framework: '{x_powered}'. "
                    "This aids fingerprinting and targeted exploitation."
                ),
                remediation=(
                    "Remove the X-Powered-By header. "
                    "In Express.js: app.disable('x-powered-by'). "
                    "In PHP: expose_php = Off in php.ini."
                ),
                evidence=f"X-Powered-By: {x_powered}",
            ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# PortScanner
# ─────────────────────────────────────────────────────────────────────────────

class PortScanner:
    """
    Multi-threaded TCP connect scanner.

    Uses :mod:`concurrent.futures.ThreadPoolExecutor` to probe ports in
    parallel, keeping total scan time bounded regardless of port count.

    Parameters
    ----------
    target : str
        Hostname or IP address to scan. Do not include a scheme or path.
    ports : list[int] | None
        Ports to scan. Defaults to COMMON_PORTS keys.
    timeout : float
        Per-port socket timeout in seconds. Defaults to DEFAULT_PORT_TIMEOUT.
    max_workers : int
        Thread-pool size. Defaults to MAX_WORKERS.
    grab_banner : bool
        Attempt to read a banner string after connect. Default True.
    """

    def __init__(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        timeout: float = DEFAULT_PORT_TIMEOUT,
        max_workers: int = MAX_WORKERS,
        grab_banner: bool = True,
    ) -> None:
        # Strip any scheme/path that may have been accidentally included
        parsed = urlparse(target if "://" in target else f"tcp://{target}")
        self.target = parsed.hostname or target
        self.ports = ports if ports is not None else list(COMMON_PORTS.keys())
        self.timeout = timeout
        self.max_workers = max_workers
        self.grab_banner = grab_banner
        self._ip: Optional[str] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> dict:
        """
        Scan all configured ports concurrently.

        Returns
        -------
        dict with keys:
            "target"        : str
            "ip"            : str | None
            "ports_scanned" : int
            "open_ports"    : list[int]
            "findings"      : list[dict]
            "error"         : str | None
        """
        # Resolve hostname once
        try:
            self._ip = socket.gethostbyname(self.target)
            logger.debug("Resolved %s → %s", self.target, self._ip)
        except socket.gaierror as exc:
            err = f"DNS resolution failed for '{self.target}': {exc}"
            logger.error(err)
            return {
                "target": self.target,
                "ip": None,
                "ports_scanned": 0,
                "open_ports": [],
                "findings": [],
                "error": err,
            }

        findings: list[dict] = []
        open_ports: list[int] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_port = {
                pool.submit(self._probe_port, port): port
                for port in self.ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Unexpected error probing port %d: %s", port, exc)
                    result = None

                if result is not None:
                    open_ports.append(port)
                    findings.append(result)

        # Sort findings by port number for deterministic output
        findings.sort(key=lambda f: int(f["evidence"].split("/")[0]) if f["evidence"] else 0)
        open_ports.sort()

        logger.info(
            "PortScanner finished for %s (%s) — %d/%d open",
            self.target, self._ip, len(open_ports), len(self.ports),
        )

        return {
            "target": self.target,
            "ip": self._ip,
            "ports_scanned": len(self.ports),
            "open_ports": open_ports,
            "findings": findings,
            "error": None,
        }

    # ── Port probe ────────────────────────────────────────────────────────────

    def _probe_port(self, port: int) -> Optional[dict]:
        """
        Attempt a TCP connect to *port*.

        Returns a finding dict if the port is open, or None if closed/filtered.
        """
        banner: Optional[str] = None
        try:
            with socket.create_connection((self._ip, port), timeout=self.timeout) as sock:
                if self.grab_banner:
                    banner = self._grab_banner(sock, port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None  # port closed or filtered

        service = COMMON_PORTS.get(port, "Unknown")
        severity = self._port_severity(port)
        description = self._port_description(port, service)
        evidence_str = f"{port}/tcp  {service}"
        if banner:
            evidence_str += f"  [{banner[:120]}]"

        return _finding(
            fid=f"PORT-{port:05d}",
            title=f"Open Port: {port}/tcp ({service})",
            severity=severity,
            category="Port Scan",
            description=description,
            remediation=self._port_remediation(port, service),
            evidence=evidence_str,
        )

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """
        Send a minimal probe and read up to 1 KB of banner data.
        Returns None on any error.
        """
        try:
            sock.settimeout(self.timeout)
            # HTTP ports get a HEAD request; others get a raw newline nudge
            if port in (80, 8080, 8443, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                sock.sendall(b"\r\n")
            banner = sock.recv(1024).decode(errors="replace").strip()
            return banner if banner else None
        except Exception:  # noqa: BLE001
            return None

    # ── Severity + description helpers ───────────────────────────────────────

    @staticmethod
    def _port_severity(port: int) -> str:
        if port in HIGH_RISK_PORTS:
            return "High"
        if port in MEDIUM_RISK_PORTS:
            return "Medium"
        return "Low"

    @staticmethod
    def _port_description(port: int, service: str) -> str:
        descriptions: dict[int, str] = {
            21:   "FTP is open. FTP transmits credentials in plaintext and is vulnerable to brute-force and sniffing attacks.",
            22:   "SSH is open. Ensure key-based authentication is enforced and password auth is disabled.",
            23:   "Telnet is open. Telnet transmits all data including passwords in cleartext. This service should be disabled immediately.",
            25:   "SMTP is accessible. Verify this port is not openly relaying email (open relay).",
            53:   "DNS is accessible on a non-standard transport. Verify this is intentional.",
            80:   "HTTP is open. Ensure all traffic is redirected to HTTPS.",
            110:  "POP3 is open. Emails are transmitted in cleartext unless STARTTLS is enforced.",
            143:  "IMAP is open. Ensure STARTTLS or IMAPS (port 993) is used.",
            443:  "HTTPS is open. Verify TLS configuration and certificate validity.",
            445:  "SMB is exposed. SMB should never be accessible from the internet (EternalBlue, ransomware vector).",
            3306: "MySQL is publicly accessible. Database ports should be firewalled and accessible only from the application server.",
            3389: "RDP is open. RDP is a common ransomware and brute-force target. Restrict to VPN/allowlisted IPs only.",
            5432: "PostgreSQL is publicly accessible. Restrict database access to trusted internal networks.",
            6379: "Redis is open. Redis has no authentication by default and should never be internet-facing.",
            8080: "HTTP alternate port is open. Confirm this is intentional and traffic is encrypted where needed.",
            8443: "HTTPS alternate port is open. Verify TLS configuration.",
        }
        return descriptions.get(port, f"Port {port}/tcp ({service}) is open.")

    @staticmethod
    def _port_remediation(port: int, service: str) -> str:
        remediations: dict[int, str] = {
            21:   "Disable FTP. Use SFTP (SSH port 22) or FTPS instead.",
            22:   "Restrict SSH access to known IP ranges. Disable password auth; use SSH keys. Consider non-standard port + fail2ban.",
            23:   "Disable Telnet immediately. Replace with SSH.",
            25:   "Restrict SMTP to authenticated users only. Test for open relay with MXToolbox.",
            53:   "Restrict DNS to authorised resolvers. Disable recursive queries on authoritative servers.",
            80:   "Redirect all HTTP traffic to HTTPS with a 301 response.",
            110:  "Enforce STARTTLS or migrate users to POP3S (port 995).",
            143:  "Enforce STARTTLS or migrate users to IMAPS (port 993).",
            443:  "Run an SSL/TLS audit (e.g., ssllabs.com/ssltest). Disable TLS < 1.2.",
            445:  "Block port 445 at the firewall perimeter. Only expose SMB on isolated internal segments.",
            3306: "Bind MySQL to 127.0.0.1. Use firewall rules to whitelist only the app server IP.",
            3389: "Place RDP behind a VPN or allowlist specific IPs. Enable Network Level Authentication (NLA).",
            5432: "Bind PostgreSQL to localhost or a private network interface. Use pg_hba.conf to restrict access.",
            6379: "Bind Redis to 127.0.0.1. Enable requirepass in redis.conf. Never expose Redis to the internet.",
            8080: "Ensure this alternate HTTP port redirects to HTTPS. Restrict access if for internal use only.",
            8443: "Verify TLS configuration is as hardened as the primary 443 endpoint.",
        }
        return remediations.get(port, f"Review whether port {port}/tcp ({service}) needs to be publicly accessible.")


# ── Unit tests ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Standalone unit tests — run with:  python scanners.py

    All network I/O is mocked; no real HTTP or TCP connections are made.
    """
    import sys
    import unittest
    from unittest.mock import MagicMock, patch, PropertyMock

    # ─────────────────────────────────────────────────────────────────────────
    # HeaderScanner Tests
    # ─────────────────────────────────────────────────────────────────────────

    class TestHeaderScannerInit(unittest.TestCase):
        def test_valid_https_url(self):
            hs = HeaderScanner("https://example.com")
            self.assertEqual(hs.target_url, "https://example.com")

        def test_valid_http_url(self):
            hs = HeaderScanner("http://example.com")
            self.assertEqual(hs.target_url, "http://example.com")

        def test_invalid_scheme_raises(self):
            with self.assertRaises(ValueError):
                HeaderScanner("ftp://example.com")

    class TestHeaderScannerSecurityHeaders(unittest.TestCase):
        """Audit of required security response headers."""

        def _make_scanner(self) -> HeaderScanner:
            return HeaderScanner("https://example.com")

        def _make_headers(self, extra: dict = None) -> requests.structures.CaseInsensitiveDict:
            from requests.structures import CaseInsensitiveDict
            base = {}
            if extra:
                base.update(extra)
            return CaseInsensitiveDict(base)

        def test_missing_hsts_produces_high_finding(self):
            scanner = self._make_scanner()
            headers = self._make_headers()  # no HSTS
            findings = scanner._audit_security_headers(headers)
            hdr_findings = [f for f in findings if f["id"] == "HDR-001"]
            self.assertEqual(len(hdr_findings), 1)
            self.assertEqual(hdr_findings[0]["severity"], "High")

        def test_present_hsts_produces_info_finding(self):
            scanner = self._make_scanner()
            headers = self._make_headers({"Strict-Transport-Security": "max-age=31536000"})
            findings = scanner._audit_security_headers(headers)
            ok_findings = [f for f in findings if f["id"] == "HDR-001-OK"]
            self.assertEqual(len(ok_findings), 1)
            self.assertEqual(ok_findings[0]["severity"], "Info")

        def test_missing_csp_produces_high_finding(self):
            scanner = self._make_scanner()
            headers = self._make_headers()
            findings = scanner._audit_security_headers(headers)
            csp_findings = [f for f in findings if f["id"] == "HDR-002"]
            self.assertEqual(csp_findings[0]["severity"], "High")

        def test_missing_x_frame_options_produces_medium_finding(self):
            scanner = self._make_scanner()
            headers = self._make_headers()
            findings = scanner._audit_security_headers(headers)
            xfo = [f for f in findings if f["id"] == "HDR-003"]
            self.assertEqual(xfo[0]["severity"], "Medium")

        def test_all_headers_present_produces_only_info(self):
            scanner = self._make_scanner()
            from requests.structures import CaseInsensitiveDict
            headers = CaseInsensitiveDict({
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            })
            findings = scanner._audit_security_headers(headers)
            non_info = [f for f in findings if f["severity"] != "Info"]
            self.assertEqual(non_info, [])

        def test_finding_has_required_keys(self):
            scanner = self._make_scanner()
            headers = self._make_headers()
            findings = scanner._audit_security_headers(headers)
            for f in findings:
                for key in ("id", "title", "severity", "category", "description", "evidence", "remediation"):
                    self.assertIn(key, f)

    class TestHeaderScannerCORS(unittest.TestCase):
        """CORS policy audit tests."""

        def _make_scanner(self) -> HeaderScanner:
            return HeaderScanner("https://example.com")

        def _headers(self, kv: dict) -> requests.structures.CaseInsensitiveDict:
            from requests.structures import CaseInsensitiveDict
            return CaseInsensitiveDict(kv)

        def test_wildcard_cors_is_high(self):
            scanner = self._make_scanner()
            findings = scanner._audit_cors(self._headers({"Access-Control-Allow-Origin": "*"}))
            cors002 = [f for f in findings if f["id"] == "CORS-002"]
            self.assertEqual(len(cors002), 1)
            self.assertEqual(cors002[0]["severity"], "High")

        def test_specific_origin_is_info(self):
            scanner = self._make_scanner()
            findings = scanner._audit_cors(self._headers({"Access-Control-Allow-Origin": "https://trusted.com"}))
            cors003 = [f for f in findings if f["id"] == "CORS-003"]
            self.assertEqual(cors003[0]["severity"], "Info")

        def test_no_cors_header_is_info(self):
            scanner = self._make_scanner()
            findings = scanner._audit_cors(self._headers({}))
            cors001 = [f for f in findings if f["id"] == "CORS-001"]
            self.assertEqual(cors001[0]["severity"], "Info")

        def test_wildcard_with_credentials_is_critical(self):
            scanner = self._make_scanner()
            findings = scanner._audit_cors(self._headers({
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }))
            cors004 = [f for f in findings if f["id"] == "CORS-004"]
            self.assertEqual(len(cors004), 1)
            self.assertEqual(cors004[0]["severity"], "Critical")

    class TestHeaderScannerInfoDisclosure(unittest.TestCase):
        """Information disclosure header checks."""

        def _scanner(self) -> HeaderScanner:
            return HeaderScanner("https://example.com")

        def _headers(self, kv: dict) -> requests.structures.CaseInsensitiveDict:
            from requests.structures import CaseInsensitiveDict
            return CaseInsensitiveDict(kv)

        def test_server_with_version_is_low(self):
            scanner = self._scanner()
            findings = scanner._audit_information_disclosure(
                self._headers({"Server": "Apache/2.4.51 (Ubuntu)"})
            )
            info001 = [f for f in findings if f["id"] == "INFO-001"]
            self.assertEqual(info001[0]["severity"], "Low")

        def test_server_without_version_is_info(self):
            scanner = self._scanner()
            findings = scanner._audit_information_disclosure(
                self._headers({"Server": "nginx"})
            )
            info001 = [f for f in findings if f["id"] == "INFO-001"]
            self.assertEqual(info001[0]["severity"], "Info")

        def test_x_powered_by_is_low(self):
            scanner = self._scanner()
            findings = scanner._audit_information_disclosure(
                self._headers({"X-Powered-By": "PHP/8.1.0"})
            )
            info002 = [f for f in findings if f["id"] == "INFO-002"]
            self.assertEqual(info002[0]["severity"], "Low")

        def test_no_disclosure_headers_returns_empty(self):
            scanner = self._scanner()
            findings = scanner._audit_information_disclosure(self._headers({}))
            self.assertEqual(findings, [])

    class TestHeaderScannerScanMethod(unittest.TestCase):
        """Integration tests for HeaderScanner.scan() using mocked HTTP."""

        def _mock_response(
            self, headers_dict: dict, status: int = 200
        ) -> MagicMock:
            from requests.structures import CaseInsensitiveDict
            resp = MagicMock()
            resp.status_code = status
            resp.headers = CaseInsensitiveDict(headers_dict)
            resp.elapsed.total_seconds.return_value = 0.1
            resp.raw.headers.getlist.return_value = []
            return resp

        @patch("__main__.HeaderScanner._fetch")
        def test_scan_returns_expected_shape(self, mock_fetch):
            mock_fetch.return_value = (self._mock_response({}), None)
            hs = HeaderScanner("https://example.com")
            result = hs.scan()
            for key in ("target", "status_code", "response_time_ms", "findings", "error"):
                self.assertIn(key, result)

        @patch("__main__.HeaderScanner._fetch")
        def test_scan_error_returns_error_key(self, mock_fetch):
            mock_fetch.return_value = (None, "Connection refused")
            hs = HeaderScanner("https://example.com")
            result = hs.scan()
            self.assertEqual(result["error"], "Connection refused")
            self.assertEqual(result["findings"], [])

        @patch("__main__.HeaderScanner._fetch")
        def test_scan_missing_headers_generates_findings(self, mock_fetch):
            mock_fetch.return_value = (self._mock_response({}), None)
            hs = HeaderScanner("https://example.com")
            result = hs.scan()
            non_info = [f for f in result["findings"] if f["severity"] != "Info"]
            self.assertGreater(len(non_info), 0)

    # ─────────────────────────────────────────────────────────────────────────
    # PortScanner Tests
    # ─────────────────────────────────────────────────────────────────────────

    class TestPortScannerInit(unittest.TestCase):
        def test_hostname_parsed(self):
            ps = PortScanner("example.com")
            self.assertEqual(ps.target, "example.com")

        def test_scheme_stripped(self):
            ps = PortScanner("https://example.com")
            self.assertEqual(ps.target, "example.com")

        def test_default_ports_set(self):
            ps = PortScanner("example.com")
            self.assertEqual(sorted(ps.ports), sorted(COMMON_PORTS.keys()))

        def test_custom_ports(self):
            ps = PortScanner("example.com", ports=[80, 443])
            self.assertEqual(ps.ports, [80, 443])

    class TestPortScannerSeverity(unittest.TestCase):
        def test_telnet_is_high(self):
            self.assertEqual(PortScanner._port_severity(23), "High")

        def test_mysql_is_high(self):
            self.assertEqual(PortScanner._port_severity(3306), "High")

        def test_redis_is_high(self):
            self.assertEqual(PortScanner._port_severity(6379), "High")

        def test_ssh_is_medium(self):
            self.assertEqual(PortScanner._port_severity(22), "Medium")

        def test_http_is_low(self):
            self.assertEqual(PortScanner._port_severity(80), "Low")

        def test_https_is_low(self):
            self.assertEqual(PortScanner._port_severity(443), "Low")

        def test_unknown_port_is_low(self):
            self.assertEqual(PortScanner._port_severity(12345), "Low")

    class TestPortScannerProbe(unittest.TestCase):
        """Tests for _probe_port without real network I/O."""

        def setUp(self):
            self.ps = PortScanner("example.com", ports=[80, 443], grab_banner=False)
            self.ps._ip = "93.184.216.34"

        @patch("socket.create_connection")
        def test_open_port_returns_finding(self, mock_conn):
            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = lambda s: mock_sock
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = self.ps._probe_port(80)
            self.assertIsNotNone(result)
            self.assertEqual(result["id"], "PORT-00080")
            self.assertIn("severity", result)

        @patch("socket.create_connection", side_effect=ConnectionRefusedError)
        def test_closed_port_returns_none(self, _):
            result = self.ps._probe_port(80)
            self.assertIsNone(result)

        @patch("socket.create_connection", side_effect=socket.timeout)
        def test_timeout_returns_none(self, _):
            result = self.ps._probe_port(443)
            self.assertIsNone(result)

    class TestPortScannerScanMethod(unittest.TestCase):
        """Integration tests for PortScanner.scan()."""

        @patch("socket.gethostbyname", return_value="93.184.216.34")
        @patch("socket.create_connection", side_effect=ConnectionRefusedError)
        def test_all_closed_ports(self, _conn, _dns):
            ps = PortScanner("example.com", ports=[80, 443], grab_banner=False)
            result = ps.scan()
            self.assertEqual(result["open_ports"], [])
            self.assertEqual(result["findings"], [])
            self.assertIsNone(result["error"])

        @patch("socket.gethostbyname", side_effect=socket.gaierror("Name resolution failed"))
        def test_dns_failure_returns_error(self, _):
            ps = PortScanner("nonexistent.invalid", ports=[80])
            result = ps.scan()
            self.assertIsNotNone(result["error"])
            self.assertIn("DNS", result["error"])

        @patch("socket.gethostbyname", return_value="93.184.216.34")
        @patch("socket.create_connection")
        def test_open_port_in_results(self, mock_conn, _dns):
            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = lambda s: mock_sock
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            ps = PortScanner("example.com", ports=[80], grab_banner=False)
            result = ps.scan()
            self.assertIn(80, result["open_ports"])
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["id"], "PORT-00080")

        @patch("socket.gethostbyname", return_value="93.184.216.34")
        @patch("socket.create_connection")
        def test_result_has_required_keys(self, mock_conn, _dns):
            mock_conn.side_effect = ConnectionRefusedError
            ps = PortScanner("example.com", ports=[80], grab_banner=False)
            result = ps.scan()
            for key in ("target", "ip", "ports_scanned", "open_ports", "findings", "error"):
                self.assertIn(key, result)

    # ── Run ────────────────────────────────────────────────────────────────────
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in (
        TestHeaderScannerInit,
        TestHeaderScannerSecurityHeaders,
        TestHeaderScannerCORS,
        TestHeaderScannerInfoDisclosure,
        TestHeaderScannerScanMethod,
        TestPortScannerInit,
        TestPortScannerSeverity,
        TestPortScannerProbe,
        TestPortScannerScanMethod,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
