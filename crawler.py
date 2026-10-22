"""
crawler.py
==========
WebCrawler — recursive web crawler for the WebScanner AI project.

Responsibilities
----------------
* Crawl a target URL up to a configurable depth (1–3).
* Stay within the same domain (internal links only).
* Extract all HTML <form> elements with actions, methods, and input fields.
* Honour robots.txt rules before fetching any page.
* Return structured output for downstream scanner modules.

Usage
-----
    from crawler import WebCrawler

    crawler = WebCrawler("https://example.com", depth=2)
    results = crawler.crawl()
    # results["pages"]  -> list of CrawledPage dicts
    # results["forms"]  -> list of FormData dicts
    # results["stats"]  -> summary counters
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

# ── Optional fast parser ──────────────────────────────────────────────────────
try:
    import lxml  # noqa: F401
    _LXML_AVAILABLE = True
except ImportError:
    _LXML_AVAILABLE = False

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT: int = 10          # seconds per request
DEFAULT_USER_AGENT: str = "WebScannerAI/1.0 (security-audit; authorised)"
MAX_DEPTH: int = 3
REDIRECT_LIMIT: int = 5


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class InputField:
    """Represents a single <input>, <textarea>, or <select> element."""
    name: str
    field_type: str          # text, password, hidden, email, submit …
    value: str = ""          # default value if present


@dataclass
class FormData:
    """All information extracted from a single <form> element."""
    page_url: str            # URL of the page the form was found on
    action: str              # resolved absolute action URL
    method: str              # GET or POST (upper-cased)
    inputs: list[InputField] = field(default_factory=list)


@dataclass
class CrawledPage:
    """Metadata collected for a single crawled URL."""
    url: str
    status_code: int
    content_type: str
    response_time_ms: float
    depth: int
    links_found: int
    forms_found: int
    error: Optional[str] = None


# ── WebCrawler ────────────────────────────────────────────────────────────────

class WebCrawler:
    """
    Recursive web crawler constrained to a single domain.

    Parameters
    ----------
    target_url : str
        The starting URL. Must include a scheme (http:// or https://).
    depth : int
        Maximum crawl depth (1–3). Defaults to 1.
    timeout : int
        Per-request timeout in seconds. Defaults to DEFAULT_TIMEOUT.
    user_agent : str
        User-Agent header sent with every request.
    delay : float
        Polite delay (seconds) between consecutive requests. Defaults to 0.5.
    """

    def __init__(
        self,
        target_url: str,
        depth: int = 1,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        delay: float = 0.5,
    ) -> None:
        if depth < 1 or depth > MAX_DEPTH:
            raise ValueError(f"depth must be between 1 and {MAX_DEPTH}, got {depth}")

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"target_url must use http or https scheme, got: {target_url!r}")

        self.target_url: str = target_url.rstrip("/")
        self.depth: int = depth
        self.timeout: int = timeout
        self.delay: float = delay

        self._base: str = f"{parsed.scheme}://{parsed.netloc}"
        self._domain: str = parsed.netloc          # e.g. "example.com"

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})
        self._session.max_redirects = REDIRECT_LIMIT

        self._visited: set[str] = set()            # normalised URLs already fetched
        self._pages: list[CrawledPage] = []
        self._forms: list[FormData] = []

        self._robots: RobotFileParser = self._load_robots()

    # ── robots.txt ────────────────────────────────────────────────────────────

    def _load_robots(self) -> RobotFileParser:
        """Fetch and parse robots.txt for the target domain."""
        rp = RobotFileParser()
        robots_url = f"{self._base}/robots.txt"
        try:
            rp.set_url(robots_url)
            rp.read()
            logger.debug("robots.txt loaded from %s", robots_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not fetch robots.txt (%s): %s — proceeding without.", robots_url, exc)
        return rp

    def _is_allowed(self, url: str) -> bool:
        """Return True if robots.txt permits crawling *url*."""
        agent = self._session.headers.get("User-Agent", "*")
        return self._robots.can_fetch(agent, url)

    # ── URL helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _normalise(url: str) -> str:
        """Remove fragment and trailing slash; lower-case the scheme+host."""
        parsed = urlparse(url)
        normalised = parsed._replace(fragment="", scheme=parsed.scheme.lower())
        clean = urlunparse(normalised).rstrip("/")
        return clean

    def _is_internal(self, url: str) -> bool:
        """Return True if *url* belongs to the same domain as the target."""
        host = urlparse(url).netloc
        # allow "www.example.com" and "example.com" to be treated as same domain
        return host == self._domain or host == f"www.{self._domain}" or f"www.{host}" == self._domain

    def _resolve(self, base: str, href: str) -> Optional[str]:
        """
        Resolve *href* against *base*, returning a normalised absolute URL.
        Returns None if the result is not an HTTP/HTTPS link.
        """
        try:
            absolute = urljoin(base, href.strip())
            scheme = urlparse(absolute).scheme
            if scheme not in ("http", "https"):
                return None
            return self._normalise(absolute)
        except Exception:  # noqa: BLE001
            return None

    # ── HTTP fetch ────────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> tuple[Optional[requests.Response], Optional[str]]:
        """
        Perform a GET request for *url*.

        Returns
        -------
        (response, error_message)
            *error_message* is None on success.
        """
        try:
            start = time.perf_counter()
            resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
            resp.elapsed_ms = (time.perf_counter() - start) * 1000  # type: ignore[attr-defined]
            return resp, None
        except requests.exceptions.SSLError as exc:
            return None, f"SSL error: {exc}"
        except requests.exceptions.ConnectionError as exc:
            return None, f"Connection error: {exc}"
        except requests.exceptions.Timeout:
            return None, f"Timed out after {self.timeout}s"
        except requests.exceptions.TooManyRedirects:
            return None, f"Too many redirects (limit: {REDIRECT_LIMIT})"
        except requests.exceptions.RequestException as exc:
            return None, f"Request failed: {exc}"

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        """Return de-duplicated internal absolute URLs found in *soup*."""
        seen: set[str] = set()
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            resolved = self._resolve(page_url, tag["href"])
            if resolved and self._is_internal(resolved) and resolved not in seen:
                seen.add(resolved)
                links.append(resolved)
        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[FormData]:
        """Parse all <form> elements on *page_url* into FormData objects."""
        forms: list[FormData] = []
        for form_tag in soup.find_all("form"):
            raw_action = form_tag.get("action", "")
            action = self._resolve(page_url, raw_action) or page_url
            method = (form_tag.get("method", "GET") or "GET").upper()

            inputs: list[InputField] = []
            # Collect <input>, <textarea>, <select>
            for tag in form_tag.find_all(["input", "textarea", "select"]):
                name = tag.get("name") or tag.get("id", "")
                if not name:
                    continue
                ftype = tag.get("type", tag.name).lower()  # textarea → "textarea"
                value = tag.get("value", "")
                inputs.append(InputField(name=name, field_type=ftype, value=value))

            forms.append(FormData(page_url=page_url, action=action, method=method, inputs=inputs))
        return forms

    # ── Core crawl logic ──────────────────────────────────────────────────────

    def _crawl_page(self, url: str, current_depth: int) -> list[str]:
        """
        Fetch *url*, parse it, record results, and return child links.
        Returns an empty list if the page could not be fetched or is disallowed.
        """
        if url in self._visited:
            return []
        self._visited.add(url)

        if not self._is_allowed(url):
            logger.info("Blocked by robots.txt: %s", url)
            self._pages.append(CrawledPage(
                url=url, status_code=0, content_type="", response_time_ms=0.0,
                depth=current_depth, links_found=0, forms_found=0,
                error="Disallowed by robots.txt",
            ))
            return []

        logger.debug("Fetching [depth=%d]: %s", current_depth, url)
        resp, error = self._fetch(url)

        if error or resp is None:
            logger.warning("Failed to fetch %s — %s", url, error)
            self._pages.append(CrawledPage(
                url=url, status_code=0, content_type="", response_time_ms=0.0,
                depth=current_depth, links_found=0, forms_found=0, error=error,
            ))
            return []

        content_type = resp.headers.get("Content-Type", "")
        elapsed_ms = getattr(resp, "elapsed_ms", resp.elapsed.total_seconds() * 1000)

        # Only parse HTML responses
        if "text/html" not in content_type:
            self._pages.append(CrawledPage(
                url=url, status_code=resp.status_code, content_type=content_type,
                response_time_ms=elapsed_ms, depth=current_depth,
                links_found=0, forms_found=0,
            ))
            return []

        # Prefer lxml for speed when available; fall back to the stdlib parser.
        _parser = "lxml" if _LXML_AVAILABLE else "html.parser"
        try:
            soup = BeautifulSoup(resp.text, _parser)
        except Exception as exc:  # noqa: BLE001
            logger.warning("HTML parse error on %s: %s", url, exc)
            soup = BeautifulSoup(resp.text, "html.parser")

        links = self._extract_links(soup, url)
        forms = self._extract_forms(soup, url)
        self._forms.extend(forms)

        self._pages.append(CrawledPage(
            url=url, status_code=resp.status_code, content_type=content_type,
            response_time_ms=elapsed_ms, depth=current_depth,
            links_found=len(links), forms_found=len(forms),
        ))

        time.sleep(self.delay)
        return links

    def crawl(self) -> dict:
        """
        Start the crawl from *target_url* up to *depth* levels deep.

        Returns
        -------
        dict with keys:
            "pages"  : list[dict]  — one entry per crawled URL
            "forms"  : list[dict]  — one entry per discovered form
            "stats"  : dict        — summary counters
        """
        # BFS queue: (url, depth_level)
        queue: list[tuple[str, int]] = [(self.target_url, 1)]

        while queue:
            url, level = queue.pop(0)
            child_links = self._crawl_page(url, level)

            if level < self.depth:
                for link in child_links:
                    if link not in self._visited:
                        queue.append((link, level + 1))

        return self._build_result()

    # ── Result builder ────────────────────────────────────────────────────────

    def _build_result(self) -> dict:
        """Serialise internal state to a plain-dict structure."""
        pages_out = [
            {
                "url": p.url,
                "status_code": p.status_code,
                "content_type": p.content_type,
                "response_time_ms": round(p.response_time_ms, 2),
                "depth": p.depth,
                "links_found": p.links_found,
                "forms_found": p.forms_found,
                "error": p.error,
            }
            for p in self._pages
        ]

        forms_out = [
            {
                "page_url": f.page_url,
                "action": f.action,
                "method": f.method,
                "inputs": [
                    {"name": i.name, "type": i.field_type, "value": i.value}
                    for i in f.inputs
                ],
            }
            for f in self._forms
        ]

        successful = [p for p in self._pages if p.error is None]
        return {
            "pages": pages_out,
            "forms": forms_out,
            "stats": {
                "total_urls_crawled": len(self._pages),
                "successful_fetches": len(successful),
                "failed_fetches": len(self._pages) - len(successful),
                "total_forms_found": len(self._forms),
                "total_inputs_found": sum(len(f.inputs) for f in self._forms),
                "depth_configured": self.depth,
                "domain": self._domain,
            },
        }


# ── Unit tests ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Standalone unit tests — run with:  python crawler.py

    Tests use unittest.mock to avoid real network calls.
    """
    import sys
    import unittest
    from unittest.mock import MagicMock, patch

    class TestWebCrawlerInit(unittest.TestCase):
        """Constructor validation tests."""

        def test_valid_construction(self):
            c = WebCrawler("https://example.com", depth=2)
            self.assertEqual(c.depth, 2)
            self.assertEqual(c._domain, "example.com")

        def test_invalid_depth_low(self):
            with self.assertRaises(ValueError):
                WebCrawler("https://example.com", depth=0)

        def test_invalid_depth_high(self):
            with self.assertRaises(ValueError):
                WebCrawler("https://example.com", depth=4)

        def test_invalid_scheme(self):
            with self.assertRaises(ValueError):
                WebCrawler("ftp://example.com")

        def test_trailing_slash_stripped(self):
            c = WebCrawler("https://example.com/", depth=1)
            self.assertEqual(c.target_url, "https://example.com")

    class TestURLHelpers(unittest.TestCase):
        """Tests for normalise, is_internal, and resolve helpers."""

        def setUp(self):
            with patch.object(WebCrawler, "_load_robots", return_value=MagicMock(can_fetch=lambda *_: True)):
                self.crawler = WebCrawler("https://example.com", depth=1)

        def test_normalise_strips_fragment(self):
            url = WebCrawler._normalise("https://example.com/page#section")
            self.assertNotIn("#", url)

        def test_normalise_strips_trailing_slash(self):
            url = WebCrawler._normalise("https://example.com/page/")
            self.assertFalse(url.endswith("/"))

        def test_is_internal_same_domain(self):
            self.assertTrue(self.crawler._is_internal("https://example.com/about"))

        def test_is_internal_www_prefix(self):
            self.assertTrue(self.crawler._is_internal("https://www.example.com/about"))

        def test_is_internal_external_domain(self):
            self.assertFalse(self.crawler._is_internal("https://other.com/page"))

        def test_resolve_absolute(self):
            result = self.crawler._resolve("https://example.com/", "/contact")
            self.assertEqual(result, "https://example.com/contact")

        def test_resolve_relative(self):
            result = self.crawler._resolve("https://example.com/blog/", "post.html")
            self.assertEqual(result, "https://example.com/blog/post.html")

        def test_resolve_non_http_returns_none(self):
            result = self.crawler._resolve("https://example.com/", "mailto:a@b.com")
            self.assertIsNone(result)

    class TestLinkExtraction(unittest.TestCase):
        """BeautifulSoup link extraction tests."""

        def setUp(self):
            with patch.object(WebCrawler, "_load_robots", return_value=MagicMock(can_fetch=lambda *_: True)):
                self.crawler = WebCrawler("https://example.com", depth=1)

        def _soup(self, html: str) -> BeautifulSoup:
            return BeautifulSoup(html, "html.parser")

        def test_internal_links_extracted(self):
            html = '<a href="/about">About</a><a href="/contact">Contact</a>'
            links = self.crawler._extract_links(self._soup(html), "https://example.com")
            self.assertIn("https://example.com/about", links)
            self.assertIn("https://example.com/contact", links)

        def test_external_links_excluded(self):
            html = '<a href="https://evil.com/steal">Click</a>'
            links = self.crawler._extract_links(self._soup(html), "https://example.com")
            self.assertEqual(links, [])

        def test_no_duplicate_links(self):
            html = '<a href="/page">A</a><a href="/page">B</a>'
            links = self.crawler._extract_links(self._soup(html), "https://example.com")
            self.assertEqual(links.count("https://example.com/page"), 1)

        def test_mailto_excluded(self):
            html = '<a href="mailto:user@example.com">Email</a>'
            links = self.crawler._extract_links(self._soup(html), "https://example.com")
            self.assertEqual(links, [])

    class TestFormExtraction(unittest.TestCase):
        """Form parsing tests."""

        def setUp(self):
            with patch.object(WebCrawler, "_load_robots", return_value=MagicMock(can_fetch=lambda *_: True)):
                self.crawler = WebCrawler("https://example.com", depth=1)

        def _soup(self, html: str) -> BeautifulSoup:
            return BeautifulSoup(html, "html.parser")

        def test_form_action_and_method(self):
            html = '<form action="/login" method="POST"><input name="user" type="text"></form>'
            forms = self.crawler._extract_forms(self._soup(html), "https://example.com")
            self.assertEqual(len(forms), 1)
            self.assertEqual(forms[0].action, "https://example.com/login")
            self.assertEqual(forms[0].method, "POST")

        def test_form_default_method_is_get(self):
            html = '<form action="/search"><input name="q" type="text"></form>'
            forms = self.crawler._extract_forms(self._soup(html), "https://example.com")
            self.assertEqual(forms[0].method, "GET")

        def test_form_inputs_captured(self):
            html = (
                '<form action="/submit" method="post">'
                '<input name="username" type="text" value="admin">'
                '<input name="password" type="password">'
                '<input name="token" type="hidden" value="abc123">'
                '</form>'
            )
            forms = self.crawler._extract_forms(self._soup(html), "https://example.com")
            names = [i.name for i in forms[0].inputs]
            self.assertIn("username", names)
            self.assertIn("password", names)
            self.assertIn("token", names)

        def test_form_no_action_uses_page_url(self):
            html = '<form><input name="q" type="text"></form>'
            page = "https://example.com/search"
            forms = self.crawler._extract_forms(self._soup(html), page)
            self.assertEqual(forms[0].action, page)

        def test_multiple_forms(self):
            html = (
                '<form action="/login" method="post"><input name="u"></form>'
                '<form action="/register" method="post"><input name="email"></form>'
            )
            forms = self.crawler._extract_forms(self._soup(html), "https://example.com")
            self.assertEqual(len(forms), 2)

        def test_inputs_without_name_skipped(self):
            html = '<form action="/go"><input type="submit"></form>'
            forms = self.crawler._extract_forms(self._soup(html), "https://example.com")
            self.assertEqual(forms[0].inputs, [])

    class TestRobotsRespected(unittest.TestCase):
        """Ensure disallowed URLs are not fetched."""

        def setUp(self):
            with patch.object(WebCrawler, "_load_robots", return_value=MagicMock(can_fetch=lambda *_: True)):
                self.crawler = WebCrawler("https://example.com", depth=1, delay=0)

        @patch("__main__.WebCrawler._fetch")
        def test_robots_blocked_url_not_fetched(self, mock_fetch):
            self.crawler._robots.can_fetch = lambda agent, url: False
            self.crawler._crawl_page("https://example.com/secret", 1)
            mock_fetch.assert_not_called()
            self.assertEqual(self.crawler._pages[0].error, "Disallowed by robots.txt")

    class TestCrawlResult(unittest.TestCase):
        """Integration-style test for build_result output shape."""

        def setUp(self):
            with patch.object(WebCrawler, "_load_robots", return_value=MagicMock(can_fetch=lambda *_: True)):
                self.crawler = WebCrawler("https://example.com", depth=1, delay=0)

        def _make_mock_response(self, html: str, status: int = 200) -> MagicMock:
            resp = MagicMock()
            resp.status_code = status
            resp.headers = {"Content-Type": "text/html; charset=utf-8"}
            resp.text = html
            resp.elapsed.total_seconds.return_value = 0.1
            resp.elapsed_ms = 100.0
            return resp

        @patch("__main__.WebCrawler._fetch")
        def test_result_keys_present(self, mock_fetch):
            html = '<a href="/about">About</a>'
            mock_fetch.return_value = (self._make_mock_response(html), None)
            result = self.crawler.crawl()
            self.assertIn("pages", result)
            self.assertIn("forms", result)
            self.assertIn("stats", result)

        @patch("__main__.WebCrawler._fetch")
        def test_stats_counts(self, mock_fetch):
            html = (
                '<a href="/about">A</a>'
                '<form action="/login" method="post"><input name="u"></form>'
            )
            mock_fetch.return_value = (self._make_mock_response(html), None)
            result = self.crawler.crawl()
            self.assertEqual(result["stats"]["total_urls_crawled"], 1)
            self.assertEqual(result["stats"]["total_forms_found"], 1)
            self.assertEqual(result["stats"]["domain"], "example.com")

        @patch("__main__.WebCrawler._fetch")
        def test_fetch_error_recorded(self, mock_fetch):
            mock_fetch.return_value = (None, "Connection error: [Errno 111]")
            result = self.crawler.crawl()
            self.assertEqual(result["stats"]["failed_fetches"], 1)
            self.assertIsNotNone(result["pages"][0]["error"])

    # ── Run all tests ──────────────────────────────────────────────────────────
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in (
        TestWebCrawlerInit,
        TestURLHelpers,
        TestLinkExtraction,
        TestFormExtraction,
        TestRobotsRespected,
        TestCrawlResult,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
