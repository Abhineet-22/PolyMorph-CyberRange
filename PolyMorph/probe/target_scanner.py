"""
target_scanner.py
=================
General-purpose passive web reconnaissance module for PolyMorph.

Design principles
-----------------
* Technology-agnostic: fingerprinting is evidence-based (headers, cookies,
  HTML markers, JS paths, URL path patterns).  No hardcoded if/else per
  runtime tier.
* Passive: only standard HTTP requests.  No active exploitation or brute-force.
* Crawls same-origin links up to a configurable depth.
* Produces a structured ScanReport (dataclass) + serialisable dict.
* Feeds directly into the PolyMorph strategy-suggestion layer.

Usage (programmatic)
--------------------
    from PolyMorph.probe.target_scanner import TargetScanner, ScanOptions

    opts  = ScanOptions(max_depth=2, timeout=10, max_pages=50)
    scanner = TargetScanner(opts)
    report  = scanner.scan("http://localhost:8081")
    print(report.as_json())

Usage (CLI wrapper — see cli.py `scan` command)
-----------------------------------------------
    python -m PolyMorph scan --url http://target --depth 2 --out report.json
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse
import datetime

# ── Optional deps (graceful degradation) ──────────────────────────────────────
try:
    import requests
    from requests import Session
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    import certifi
    _CERTIFI_BUNDLE: str | bool = certifi.where()
except ImportError:
    _CERTIFI_BUNDLE = True

try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UploadEndpoint:
    """A discovered file-upload surface."""
    url:          str
    method:       str = "POST"                 # inferred from <form method>
    enctype:      str = "multipart/form-data"  # <form enctype>
    accept:       list[str] = field(default_factory=list)  # <input accept=>
    field_name:   str = "file"                 # name of the file input
    extra_inputs: dict[str, str] = field(default_factory=dict)  # hidden fields
    source_page:  str = ""                     # page where the form was found
    notes:        str = ""


@dataclass
class TechEvidence:
    """
    One observed piece of technology evidence.
    Multiple TechEvidence objects accumulate per technology label.
    """
    tech:     str
    category: str    # webserver | runtime | framework | frontend | cms | api | exposure | upload
    weight:   int
    source:   str    # e.g. "header:server", "path:/phpinfo", "html:wp-content"
    value:    str    # the raw observed value that triggered the match


@dataclass
class SecurityGap:
    """A missing or misconfigured security header."""
    header:   str
    gap:      str
    severity: str = "medium"   # low | medium | high


@dataclass
class ContentSurface:
    """
    A discovered content processing surface beyond traditional upload forms.
    Represents any point where the target ingests, processes, or serves
    external/user-influenced content — each of which may be exploitable
    via polyglot parser differentials even without an explicit upload form.
    """
    category:    str    # media_serving | doc_processing | content_embed |
                        # api_ingestion | cloud_storage | download_serve
    label:       str    # human-readable label (e.g. "Inline Image Serving")
    url:         str    # the URL or resource where the surface was observed
    evidence:    str    # what was observed (tag, header, pattern)
    risk_note:   str    # why this matters for polyglots
    severity:       str = "medium"   # low | medium | high
    cve_ref:        str = ""         # CVE or CWE reference identifier (e.g. "CVE-2025-64512")
    endpoints:      list[str] = field(default_factory=list)  # Concrete mapped target endpoint URLs / paths
    exploitability: str = "active"   # active (source+sink confirmed) | latent (sink only, requires supply-chain)
    delivery_chain: str = ""         # Concrete explanation of delivery path


@dataclass
class PolyglotRecommendation:
    """
    A recommended polyglot strategy derived from the discovered evidence.
    Maps directly to PolyMorph's constructor interface.
    """
    trigger:        str    # what evidence triggered this recommendation
    strategy:       str    # append | inject
    host_formats:   list[str]
    payload_note:   str
    risk:           str
    payload_format: str = "zip"
    endpoints:      list[str] = field(default_factory=list)  # Triggering target endpoints / evidence paths
    exploitability: str = "active"   # active | latent


@dataclass
class PageInfo:
    """Metadata captured for each crawled page."""
    url:          str
    status_code:  int
    content_type: str
    response_headers: dict[str, str]
    redirect_chain:   list[str] = field(default_factory=list)
    links_found:      list[str] = field(default_factory=list)
    forms_found:      int = 0
    crawl_depth:      int = 0
    error:            str = ""


@dataclass
class ScanReport:
    """
    Top-level reconnaissance report.
    Produced by TargetScanner.scan() and consumed by the CLI renderer.
    """
    target:              str
    scan_time_utc:       str
    duration_seconds:    float
    pages_crawled:       int
    tech_summary:        dict[str, int]       # tech label -> accumulated weight
    tech_evidence:       list[TechEvidence]
    upload_endpoints:    list[UploadEndpoint]
    content_surfaces:    list[ContentSurface]  # non-upload content processing surfaces
    security_gaps:       list[SecurityGap]
    recommendations:     list[PolyglotRecommendation]
    server_info:         dict[str, str]       # raw key headers from root page
    crawled_pages:       list[PageInfo]
    exposed_paths:       list[str]            # paths with high-exposure weight
    error:               str = ""

    # ── Serialisation ──────────────────────────────────────────────────────────
    def as_dict(self) -> dict:
        return asdict(self)

    def as_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, default=str)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.as_json(), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Scanner options
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanOptions:
    max_depth:   int   = 2       # BFS crawl depth
    timeout:     int   = 10      # per-request timeout for crawling (seconds)
    probe_timeout: int = 3       # per-request timeout for discovery probing (shorter)
    probe_workers: int = 20      # parallel threads for discovery-path probing
    max_pages:   int   = 50      # hard cap on pages crawled
    user_agent:  str   = (
        "Mozilla/5.0 (compatible; PolyMorphRecon/1.0; research-scanner)"
    )
    follow_redirects: bool  = True
    probe_common_paths: bool = True  # probe a list of well-known discovery paths
    respect_robots:     bool = False # future: parse robots.txt exclusions
    verify_tls:         bool | str = True # verify TLS with certifi CA bundle by default
    ca_bundle:          Optional[str] = None # custom CA certificate bundle if specified


# ─────────────────────────────────────────────────────────────────────────────
# Well-known discovery paths probed when probe_common_paths=True
# These are probed as HEAD requests; only the HTTP status and headers matter.
# ─────────────────────────────────────────────────────────────────────────────

DISCOVERY_PATHS: list[str] = [
    # Admin / management panels
    "/admin", "/administrator", "/admin.php", "/wp-admin",
    "/wp-login.php", "/wp-content", "/wp-includes",
    "/phpMyAdmin", "/phpmyadmin", "/adminer.php", "/adminer",
    "/django-admin",
    # API surfaces
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
    "/swagger-ui.html", "/openapi.json", "/docs", "/redoc",
    "/actuator", "/actuator/health", "/health", "/status",
    "/metrics",
    # Debug / info endpoints
    "/phpinfo.php", "/info.php", "/debug", "/console",
    "/_debug_toolbar", "/server-status", "/.env", "/.git",
    "/__pycache__", "/__debug__",
    # Upload surfaces
    "/upload", "/uploads", "/files", "/media/upload",
    "/file-upload", "/attachments",
    # Configuration / secrets
    "/.htaccess", "/config.php", "/config.json", "/settings.py",
    "/web.config", "/robots.txt", "/sitemap.xml",
    # Cloud / serverless indicators
    "/.well-known", "/.well-known/security.txt",
    "/favicon.ico",
]


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner class
# ─────────────────────────────────────────────────────────────────────────────

class TargetScanner:
    """
    General-purpose passive web reconnaissance scanner.

    Completely technology-agnostic — detection is driven by
    fingerprint_signatures.json (evidence patterns, NOT tier names).
    """

    _SIGNATURES_PATH = Path(__file__).parent / "fingerprint_signatures.json"

    def __init__(self, options: Optional[ScanOptions] = None) -> None:
        if not _REQUESTS_OK:
            raise ImportError(
                "TargetScanner requires 'requests'. "
                "Install it: pip install requests"
            )
        self.opts = options or ScanOptions()
        self._sigs = self._load_signatures()
        self._session = self._build_session()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, url: str) -> ScanReport:
        """
        Run a complete reconnaissance scan against *url*.

        Parameters
        ----------
        url : str
            The base URL to scan (scheme required, e.g. "http://localhost:8081").

        Returns
        -------
        ScanReport
            Fully populated report dataclass.
        """
        t0 = time.monotonic()
        url = url.rstrip("/")
        origin = self._origin(url)

        evidence_accumulator: list[TechEvidence]       = []
        upload_endpoints:     list[UploadEndpoint]     = []
        content_surfaces:     list[ContentSurface]     = []
        crawled_pages:        list[PageInfo]            = []
        exposed_paths:        list[str]                 = []
        server_info:          dict[str, str]            = {}
        # html bodies keyed by url for surface analysis after crawl
        _html_bodies:         dict[str, str]            = {}

        visited:   set[str]            = set()
        queue:     deque[tuple[str, int]] = deque([(url, 0)])

        # ── BFS crawl ─────────────────────────────────────────────────────────
        while queue and len(crawled_pages) < self.opts.max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited:
                continue
            visited.add(current_url)

            page = self._fetch_page(current_url, depth)
            crawled_pages.append(page)

            if page.error:
                continue

            # Collect server info from root page
            if current_url == url and not server_info:
                server_info = self._extract_server_info(page.response_headers)

            # Evidence from HTTP headers
            evidence_accumulator.extend(
                self._match_header_signatures(page.response_headers, current_url)
            )

            # Evidence from URL path
            evidence_accumulator.extend(
                self._match_path_signatures(current_url)
            )

            # Track high-exposure paths
            if self._is_exposure_path(current_url) and page.status_code not in (404, 410):
                exposed_paths.append(f"{current_url} [{page.status_code}]")

            # Parse HTML body
            if _BS4_OK and "html" in page.content_type:
                html_body = self._fetch_body(current_url)
                if html_body:
                    _html_bodies[current_url] = html_body
                    # HTML evidence
                    evidence_accumulator.extend(
                        self._match_html_signatures(html_body, current_url)
                    )
                    # Upload forms
                    upload_endpoints.extend(
                        self._extract_upload_forms(html_body, current_url, origin)
                    )
                    # Enqueue same-origin links
                    if depth < self.opts.max_depth:
                        new_links = self._extract_links(html_body, current_url, origin)
                        page.links_found = new_links
                        for link in new_links:
                            if link not in visited:
                                queue.append((link, depth + 1))

        # ── Probe discovery paths ─────────────────────────────────────────────
        if self.opts.probe_common_paths:
            probe_results = self._probe_discovery_paths(url, origin)
            for ev, exposed in probe_results:
                evidence_accumulator.extend(ev)
                exposed_paths.extend(exposed)

        # ── Security gap analysis ─────────────────────────────────────────────
        # Use headers from the root page response
        root_page = next((p for p in crawled_pages if p.url == url), None)
        root_headers = root_page.response_headers if root_page else {}
        security_gaps = self._check_security_gaps(root_headers)

        # ── Ingress source correlation check ──────────────────────────────────
        has_upload_forms = len(upload_endpoints) > 0
        has_api_ingestion = False
        has_param_reflection = False
        for html in _html_bodies.values():
            html_l = html.lower()
            if any(route in html_l for route in ["/api/upload", "/api/ingest", "/api/import", "/api/convert", "/api/parse"]):
                has_api_ingestion = True
                break
            if "filereader" in html_l or "readasarraybuffer" in html_l or "readasbinarystring" in html_l:
                has_api_ingestion = True
                break
            if "formdata" in html_l and any(k in html_l for k in [".files", "type='file'", 'type="file"', ".append("]):
                has_api_ingestion = True
                break
            if any(p in html_l for p in ["urlsearchparams", "location.search", "location.hash", "window.location.search"]):
                if any(sink in html_l for sink in ["<object", "<embed", "<iframe", "createelement('object')", 'createelement("object")', "createelement('embed')", 'createelement("embed")', "createelement('iframe')", 'createelement("iframe")', ".data =", ".data=", ".src =", ".src="]):
                    has_param_reflection = True
                    break
        has_ingress_sources = has_upload_forms or has_api_ingestion or has_param_reflection

        # ── Content processing surface analysis ───────────────────────────────
        for page_url, html_body in _html_bodies.items():
            page_obj = next((p for p in crawled_pages if p.url == page_url), None)
            page_headers = page_obj.response_headers if page_obj else {}
            content_surfaces.extend(
                self._detect_content_surfaces(
                    html_body, page_url, page_headers, origin, has_ingress=has_ingress_sources
                )
            )
        # Also check response headers of non-HTML endpoints (download, API)
        for page_obj in crawled_pages:
            if "html" not in page_obj.content_type and not page_obj.error:
                content_surfaces.extend(
                    self._detect_content_surfaces_from_headers(
                        page_obj.url, page_obj.response_headers, has_ingress=has_ingress_sources
                    )
                )
        # Deduplicate surfaces by (category + evidence) and merge endpoints
        seen_surfaces: dict[str, ContentSurface] = {}
        for s in content_surfaces:
            key = s.category + s.evidence[:60]
            if key not in seen_surfaces:
                seen_surfaces[key] = s
            else:
                for ep in s.endpoints:
                    if ep not in seen_surfaces[key].endpoints:
                        seen_surfaces[key].endpoints.append(ep)
        content_surfaces = list(seen_surfaces.values())

        # ── Aggregate tech evidence ───────────────────────────────────────────
        tech_summary = self._aggregate_tech(evidence_accumulator)

        # ── Generate polyglot recommendations ────────────────────────────────
        recommendations = self._generate_recommendations(
            tech_summary,
            security_gaps,
            upload_endpoints,
            content_surfaces,
            target_url=url,
            tech_evidence=evidence_accumulator,
            has_ingress=has_ingress_sources,
        )

        duration = time.monotonic() - t0

        return ScanReport(
            target=url,
            scan_time_utc=datetime.datetime.utcnow().isoformat() + "Z",
            duration_seconds=round(duration, 2),
            pages_crawled=len(crawled_pages),
            tech_summary=dict(sorted(tech_summary.items(), key=lambda x: x[1], reverse=True)),
            tech_evidence=evidence_accumulator,
            upload_endpoints=upload_endpoints,
            content_surfaces=content_surfaces,
            security_gaps=security_gaps,
            recommendations=recommendations,
            server_info=server_info,
            crawled_pages=crawled_pages,
            exposed_paths=list(dict.fromkeys(exposed_paths)),  # dedup, preserve order
        )

    # ── Internal: HTTP layer ───────────────────────────────────────────────────

    def _get_verify_target(self) -> str | bool:
        """
        Return the TLS certificate bundle to use for requests.
        Uses certifi's trusted Mozilla root CA store by default when verify_tls=True.
        Avoids InsecureRequestWarning and enforces transport compliance.
        """
        if self.opts.ca_bundle:
            return self.opts.ca_bundle
        if self.opts.verify_tls is True:
            return _CERTIFI_BUNDLE
        return self.opts.verify_tls

    def _build_session(self) -> "Session":
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://",  adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": self.opts.user_agent})
        s.verify = self._get_verify_target()
        return s

    def _fetch_page(self, url: str, depth: int = 0) -> PageInfo:
        """Fetch page metadata via GET (no body stored here — _fetch_body for that)."""
        try:
            r = self._session.get(
                url,
                timeout=(5, self.opts.timeout),  # (connect_timeout, read_timeout)
                allow_redirects=self.opts.follow_redirects,
                verify=self._get_verify_target(),
                stream=True,
            )
            headers_lc = {k.lower(): v for k, v in r.headers.items()}
            redirect_chain = [resp.url for resp in r.history]
            ct = headers_lc.get("content-type", "")
            r.raw.read(1)
            return PageInfo(
                url=url,
                status_code=r.status_code,
                content_type=ct,
                response_headers=headers_lc,
                redirect_chain=redirect_chain,
                crawl_depth=depth,
            )
        except Exception as exc:
            return PageInfo(
                url=url,
                status_code=0,
                content_type="",
                response_headers={},
                crawl_depth=depth,
                error=str(exc),
            )

    def _fetch_body(self, url: str) -> str:
        """Fetch and return full HTML body text (UTF-8, capped at 512 KB)."""
        try:
            r = self._session.get(
                url,
                timeout=self.opts.timeout,
                allow_redirects=self.opts.follow_redirects,
                verify=self._get_verify_target(),
            )
            raw = r.content[:524288]   # 512 KB cap
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _probe_discovery_paths(
        self, base: str, origin: str
    ) -> list[tuple[list[TechEvidence], list[str]]]:
        """
        Parallel HEAD-probe each path in DISCOVERY_PATHS using a thread pool.
        Uses a short probe_timeout to avoid stalling on closed ports.
        Returns list of (evidence_list, exposed_paths) tuples.
        """
        results: list[tuple[list[TechEvidence], list[str]]] = []

        def _probe_one(path: str) -> tuple[list[TechEvidence], list[str]]:
            probe_url = base + path
            evs: list[TechEvidence] = []
            exposed: list[str] = []
            try:
                r = self._session.head(
                    probe_url,
                    timeout=self.opts.probe_timeout,
                    allow_redirects=True,
                    verify=self._get_verify_target(),
                )
                if r.status_code not in (404, 410):
                    headers_lc = {k.lower(): v for k, v in r.headers.items()}
                    evs.extend(self._match_path_signatures(probe_url))
                    evs.extend(self._match_header_signatures(headers_lc, probe_url))
                    if r.status_code in (200, 301, 302, 403):
                        if self._is_exposure_path(probe_url):
                            exposed.append(f"{probe_url} [{r.status_code}]")
                        if any(kw in path for kw in ("/upload", "/files", "/media/upload")):
                            evs.append(TechEvidence(
                                tech="File Upload Endpoint",
                                category="upload",
                                weight=4,
                                source=f"path_probe:{path}",
                                value=f"HTTP {r.status_code}",
                            ))
            except Exception:
                pass   # closed port / timeout — silently skip
            return (evs, exposed)

        with ThreadPoolExecutor(max_workers=self.opts.probe_workers) as pool:
            futures = {pool.submit(_probe_one, path): path for path in DISCOVERY_PATHS}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    results.append(([], []))

        return results

    # ── Internal: Signature matching ───────────────────────────────────────────

    def _match_header_signatures(
        self, headers: dict[str, str], source_url: str
    ) -> list[TechEvidence]:
        evs: list[TechEvidence] = []
        for sig in self._sigs.get("header_signatures", []):
            hdr = sig["header"]
            val = headers.get(hdr, "")
            if val == "" and sig["pattern"] == "":
                # Header present but pattern is empty → presence-only match
                if hdr in headers:
                    evs.append(TechEvidence(
                        tech=sig["tech"],
                        category=sig["category"],
                        weight=sig["weight"],
                        source=f"header:{hdr}",
                        value=headers[hdr][:120],
                    ))
            elif val and sig["pattern"] and sig["pattern"].lower() in val.lower():
                evs.append(TechEvidence(
                    tech=sig["tech"],
                    category=sig["category"],
                    weight=sig["weight"],
                    source=f"header:{hdr}",
                    value=val[:120],
                ))
        return evs

    def _match_path_signatures(self, url: str) -> list[TechEvidence]:
        evs: list[TechEvidence] = []
        path = urlparse(url).path.lower()
        for sig in self._sigs.get("path_signatures", []):
            pat = sig["pattern"].lower()
            if pat and pat in path:
                evs.append(TechEvidence(
                    tech=sig["tech"],
                    category=sig["category"],
                    weight=sig["weight"],
                    source=f"path:{path}",
                    value=path,
                ))
        return evs

    def _match_html_signatures(self, html: str, source_url: str) -> list[TechEvidence]:
        evs: list[TechEvidence] = []
        html_lower = html.lower()
        for sig in self._sigs.get("html_signatures", []):
            pat = sig["pattern"].lower()
            if pat and re.search(pat, html_lower):
                # Extract a short snippet for context
                m = re.search(pat, html_lower)
                snippet = html[max(0, m.start()-20): m.end()+40].replace("\n", " ").strip() if m else ""
                evs.append(TechEvidence(
                    tech=sig["tech"],
                    category=sig["category"],
                    weight=sig["weight"],
                    source=f"html:{source_url}",
                    value=snippet[:100],
                ))
        # Match JS bundle paths in HTML
        for sig in self._sigs.get("js_path_signatures", []):
            pat = sig["pattern"].lower()
            if pat and pat in html_lower:
                evs.append(TechEvidence(
                    tech=sig["tech"],
                    category=sig["category"],
                    weight=sig["weight"],
                    source=f"html_script:{source_url}",
                    value=pat,
                ))
        return evs

    def _extract_upload_forms(
        self, html: str, page_url: str, origin: str
    ) -> list[UploadEndpoint]:
        """Extract all multipart file-upload forms from HTML."""
        if not _BS4_OK:
            return []
        eps: list[UploadEndpoint] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                # Only care about forms with file inputs
                file_inputs = form.find_all("input", {"type": "file"})
                if not file_inputs:
                    continue
                action = form.get("action", "")
                action_url = urljoin(page_url, action) if action else page_url
                method  = (form.get("method", "post") or "post").upper()
                enctype = form.get("enctype", "application/x-www-form-urlencoded")

                # Collect accept attributes
                accept_vals: list[str] = []
                field_name = "file"
                for fi in file_inputs:
                    acc = fi.get("accept", "")
                    if acc:
                        accept_vals.extend(a.strip() for a in acc.split(","))
                    nm = fi.get("name", "")
                    if nm:
                        field_name = nm

                # Collect hidden / text inputs (useful for CSRF tokens etc.)
                extra: dict[str, str] = {}
                for inp in form.find_all("input"):
                    t = (inp.get("type", "text") or "text").lower()
                    nm = inp.get("name", "")
                    val = inp.get("value", "")
                    if nm and t in ("hidden", "text", "email"):
                        extra[nm] = val

                eps.append(UploadEndpoint(
                    url=action_url,
                    method=method,
                    enctype=enctype,
                    accept=accept_vals,
                    field_name=field_name,
                    extra_inputs=extra,
                    source_page=page_url,
                    notes=f"Form with {len(file_inputs)} file input(s)",
                ))
        except Exception:
            pass
        return eps

    def _extract_links(
        self, html: str, page_url: str, origin: str
    ) -> list[str]:
        """Extract same-origin href links from HTML."""
        if not _BS4_OK:
            return []
        links: list[str] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if not href or href.startswith("#") or href.startswith("javascript:"):
                    continue
                abs_url = urljoin(page_url, href).split("#")[0].split("?")[0]
                if self._origin(abs_url) == origin:
                    links.append(abs_url)
        except Exception:
            pass
        return links

    # ── Internal: Security / exposure analysis ────────────────────────────────

    def _check_security_gaps(self, headers: dict[str, str]) -> list[SecurityGap]:
        gaps: list[SecurityGap] = []
        severity_map = {
            "x-content-type-options":    "high",
            "content-security-policy":    "high",
            "x-frame-options":            "medium",
            "strict-transport-security":  "medium",
            "referrer-policy":            "low",
            "permissions-policy":         "low",
            "x-xss-protection":           "low",
        }
        for check in self._sigs.get("security_checks", []):
            hdr       = check["header"]
            expected  = check["expected"]
            gap_text  = check["gap"]
            val = headers.get(hdr, "")
            if expected == "nosniff":
                if "nosniff" not in val.lower():
                    gaps.append(SecurityGap(
                        header=hdr, gap=gap_text,
                        severity=severity_map.get(hdr, "medium")
                    ))
            elif expected == "any":
                if not val:
                    gaps.append(SecurityGap(
                        header=hdr, gap=gap_text,
                        severity=severity_map.get(hdr, "medium")
                    ))
        return gaps

    def _is_exposure_path(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        exposure_patterns = [
            "/.env", "/.git", "/phpinfo", "/.htaccess", "/__pycache__",
            "/phpMyAdmin", "/phpmyadmin", "/adminer", "/debug", "/console",
            "/_debug_toolbar", "/server-status", "/config.php", "/web.config",
            "/settings.py", "/actuator",
        ]
        return any(p.lower() in path for p in exposure_patterns)

    def _extract_server_info(self, headers: dict[str, str]) -> dict[str, str]:
        interesting = [
            "server", "x-powered-by", "x-aspnet-version",
            "x-aspnetmvc-version", "x-generator", "via",
            "x-runtime", "x-frame-options",
            "x-content-type-options", "content-security-policy",
            "strict-transport-security",
        ]
        return {h: headers[h] for h in interesting if h in headers}

    # ── Internal: Tech aggregation ────────────────────────────────────────────

    def _aggregate_tech(self, evidence: list[TechEvidence]) -> dict[str, int]:
        """Aggregate evidence weights by technology label."""
        totals: dict[str, int] = defaultdict(int)
        for ev in evidence:
            totals[ev.tech] += ev.weight
        return dict(totals)

    # ── Internal: Recommendation engine ───────────────────────────────────────

    def _generate_recommendations(
        self,
        tech_summary:     dict[str, int],
        security_gaps:    list[SecurityGap],
        upload_endpoints: list[UploadEndpoint],
        content_surfaces: Optional[list["ContentSurface"]] = None,
        target_url:       str = "",
        tech_evidence:    Optional[list[TechEvidence]] = None,
        has_ingress:      bool = True,
    ) -> list[PolyglotRecommendation]:
        """
        Map discovered evidence to polyglot strategy recommendations.
        Driven by fingerprint_signatures.json[polyglot_strategy_map] and
        enriched by content surface detections with Source-Sink exploitability correlation.
        """
        recs: list[PolyglotRecommendation] = []
        seen: set[str] = set()
        strategy_map = self._sigs.get("polyglot_strategy_map", {})

        def _add(
            trigger: str,
            mapping: dict,
            endpoints: Optional[list[str]] = None,
            exploitability: str = "active",
        ) -> None:
            key = trigger + mapping.get("strategy", "")
            if key in seen:
                existing = next(r for r in recs if (r.trigger + r.strategy) == key)
                for ep in (endpoints or []):
                    if ep and ep not in existing.endpoints:
                        existing.endpoints.append(ep)
                return
            seen.add(key)

            p_fmt = mapping.get("payload_format")
            if not p_fmt:
                t_lower = trigger.lower() + " " + mapping.get("payload_note", "").lower()
                if "php" in t_lower:
                    p_fmt = "php"
                elif "html" in t_lower or "xss" in t_lower or "mime-sniff" in t_lower or "csp" in t_lower:
                    p_fmt = "html"
                elif "zip" in t_lower or "archive" in t_lower:
                    p_fmt = "zip"
                else:
                    p_fmt = "zip"

            rec_eps = list(dict.fromkeys([ep for ep in (endpoints or []) if ep]))
            if not rec_eps and target_url:
                rec_eps = [target_url]

            payload_note = mapping.get("payload_note", "")
            risk_label = mapping.get("risk", "")
            if exploitability == "latent":
                payload_note = (
                    f"[LATENT / SUPPLY-CHAIN VECTOR — 0 upload endpoints]: {payload_note} "
                    "Direct web delivery is blocked. Demonstration requires asset supply-chain "
                    "poisoning (Git/CDN) or client-side URL reflection."
                )
                if "Latent" not in risk_label:
                    risk_label = f"{risk_label} (Latent / Supply-Chain)"

            recs.append(PolyglotRecommendation(
                trigger=trigger,
                strategy=mapping["strategy"],
                host_formats=mapping["host_formats"],
                payload_note=payload_note,
                risk=risk_label,
                payload_format=p_fmt,
                endpoints=rec_eps,
                exploitability=exploitability,
            ))

        # From detected techs
        for tech in tech_summary:
            if tech in strategy_map:
                tech_eps = []
                if tech_evidence:
                    for ev in tech_evidence:
                        if ev.tech.lower() == tech.lower():
                            if ev.source.startswith("path:"):
                                tech_eps.append(urljoin(target_url, ev.source.split("path:", 1)[1].strip()))
                            elif ev.source.startswith("html:"):
                                tech_eps.append(ev.source.split("html:", 1)[1].strip())
                            elif ev.source.startswith("html_script:"):
                                tech_eps.append(ev.source.split("html_script:", 1)[1].strip())
                if upload_endpoints:
                    tech_eps.extend([ep.action_url for ep in upload_endpoints])
                if not tech_eps and target_url:
                    tech_eps = [target_url]
                _add(
                    tech,
                    strategy_map[tech],
                    endpoints=tech_eps,
                    exploitability="active" if has_ingress else "latent",
                )

        # From security gaps
        for gap in security_gaps:
            gap_eps = []
            is_latent_gap = False
            if "mime-sniff" in gap.gap.lower():
                for s in (content_surfaces or []):
                    if s.category in ("media_serving", "download_serve"):
                        gap_eps.extend(s.endpoints or [s.url])
                if upload_endpoints:
                    gap_eps.extend([ep.action_url for ep in upload_endpoints])
                elif not has_ingress:
                    is_latent_gap = True
            elif "csp" in gap.gap.lower():
                for s in (content_surfaces or []):
                    if s.category in ("content_embed", "media_serving"):
                        gap_eps.extend(s.endpoints or [s.url])
                if not has_ingress:
                    is_latent_gap = True
            if not gap_eps and target_url:
                gap_eps = [target_url]

            exploit_mode = "latent" if (is_latent_gap or not has_ingress) else "active"
            if gap.gap in strategy_map:
                _add(gap.gap, strategy_map[gap.gap], endpoints=gap_eps, exploitability=exploit_mode)
            else:
                for k, v in strategy_map.items():
                    if k.lower() in gap.gap.lower():
                        _add(gap.gap, v, endpoints=gap_eps, exploitability=exploit_mode)
                        break

        # If upload endpoints found — flag archive-worker possibility
        if upload_endpoints and "Archive worker detected" in strategy_map:
            _add(
                "Archive worker detected",
                strategy_map["Archive worker detected"],
                endpoints=[ep.action_url for ep in upload_endpoints],
                exploitability="active",
            )

        # From content processing surfaces (the key addition)
        surface_strategy_map = self._sigs.get("surface_strategy_map", {})
        for surface in (content_surfaces or []):
            if surface.category in surface_strategy_map:
                mapping = surface_strategy_map[surface.category]
                surf_eps = (
                    surface.endpoints
                    if surface.endpoints
                    else ([surface.url] if surface.url else ([target_url] if target_url else []))
                )
                _add(
                    f"{surface.label} [{surface.category}]",
                    mapping,
                    endpoints=surf_eps,
                    exploitability=surface.exploitability,
                )

        return recs

    # ── Internal: Content surface analysis ────────────────────────────────────

    def _detect_content_surfaces(
        self,
        html: str,
        page_url: str,
        headers: dict[str, str],
        origin: str,
        has_ingress: bool = True,
    ) -> list[ContentSurface]:
        """
        Analyse an HTML page body for content processing surfaces that
        represent polyglot attack vectors beyond traditional upload forms.
        Applies Source-Sink correlation to differentiate Active exploit chains
        from Latent / Supply-Chain pre-conditions.
        """
        if not _BS4_OK:
            return []

        surfaces: list[ContentSurface] = []
        nosniff = "nosniff" in headers.get("x-content-type-options", "").lower()

        try:
            soup = BeautifulSoup(html, "html.parser")
            html_lower = html.lower()

            # ── 1. Media serving (img / video / audio) without nosniff ────────
            media_tags = soup.find_all(["img", "video", "audio", "source", "picture"])
            same_origin_media = []
            media_endpoints = []
            for tag in media_tags:
                src = tag.get("src") or tag.get("srcset") or ""
                if src:
                    abs_src = urljoin(page_url, str(src).split(",")[0].strip().split(" ")[0])
                    if self._origin(abs_src) == origin:
                        same_origin_media.append(tag.name + ": " + str(src)[:60])
                        if abs_src not in media_endpoints:
                            media_endpoints.append(abs_src)
            if same_origin_media and not nosniff:
                if has_ingress:
                    surfaces.append(ContentSurface(
                        category="media_serving",
                        label="Inline Media Serving (Active Delivery Chain)",
                        url=media_endpoints[0] if media_endpoints else page_url,
                        evidence=f"{len(media_endpoints)} media item(s) without nosniff: {same_origin_media[0]}",
                        risk_note=(
                            "Same-origin images/media served without X-Content-Type-Options: nosniff. "
                            "ACTIVE VECTOR: Target has verified upload/ingestion endpoint(s) — an uploaded polyglot "
                            "image (PNG/JPEG+HTML) is served with image Content-Type, triggering browser "
                            "MIME-sniffing to execute embedded JavaScript within the origin."
                        ),
                        severity="high",
                        cve_ref="CWE-430 (MIME Confusion / XSS)",
                        endpoints=media_endpoints,
                        exploitability="active",
                        delivery_chain="Direct HTTP Upload / API → Server Storage → Media Served without nosniff → Browser MIME Confusion XSS",
                    ))
                else:
                    surfaces.append(ContentSurface(
                        category="media_serving",
                        label="Inline Media Serving (Latent Supply-Chain Vector)",
                        url=media_endpoints[0] if media_endpoints else page_url,
                        evidence=f"{len(media_endpoints)} media item(s) without nosniff: {same_origin_media[0]}",
                        risk_note=(
                            "Same-origin images/media served without X-Content-Type-Options: nosniff. "
                            "LATENT VECTOR: Target is an immutable static site with 0 upload or API ingestion endpoints. "
                            "Direct external HTTP upload is blocked. Delivery requires: (1) Asset Supply-Chain Poisoning "
                            "(committing a polyglot asset into the Git repository or CDN build pipeline), or (2) Client-Side "
                            "Reflection if user-controlled parameters dynamically load media."
                        ),
                        severity="medium",
                        cve_ref="CWE-430 (MIME Confusion / XSS)",
                        endpoints=media_endpoints,
                        exploitability="latent",
                        delivery_chain="Git Commit / Asset Supply Chain → CDN Build Deploy → Media Direct URL Access → Browser MIME Confusion XSS",
                    ))

            # ── 2. Document processing indicators ────────────────────────────
            doc_indicators = {
                "pdf.js":          ("PDF.js client-side renderer", "pdfminer / pdf.js"),
                "pdfminer":        ("pdfminer.six server-side PDF parser", "pdfminer.six"),
                "pdfplumber":      ("pdfplumber PDF parser", "pdfplumber"),
                "markitdown":      ("MarkItDown document converter", "markitdown"),
                "ghostscript":     ("Ghostscript PDF/PS processor", "Ghostscript"),
                "libreoffice":     ("LibreOffice document converter", "LibreOffice"),
                "pandoc":          ("Pandoc document converter", "Pandoc"),
                "docx":            ("DOCX/Office document processing", "python-docx/Office"),
                "mammoth":         ("Mammoth DOCX converter", "mammoth"),
                "textract":        ("AWS Textract document AI", "Textract"),
                "tika":            ("Apache Tika document parser", "Apache Tika"),
                "antiword":        ("antiword DOC parser", "antiword"),
                "pdfkit":          ("pdfkit/wkhtmltopdf renderer", "pdfkit"),
                "weasyprint":      ("WeasyPrint HTML→PDF renderer", "WeasyPrint"),
                "html2pdf":        ("html2pdf renderer", "html2pdf"),
                "jspdf":           ("jsPDF client-side PDF", "jsPDF"),
                "pdfmake":         ("pdfmake client-side PDF", "pdfmake"),
            }
            for token, (desc, lib_name) in doc_indicators.items():
                if token in html_lower:
                    cve = "CVE-2025-64512" if any(p in token for p in ("pdfminer", "pdf")) else "CWE-434 (Parser Differential)"
                    doc_endpoints = [page_url]
                    for s_tag in soup.find_all("script", src=True):
                        s_src = s_tag["src"]
                        if token in s_src.lower():
                            doc_endpoints.append(urljoin(page_url, s_src))
                    doc_endpoints = list(dict.fromkeys(doc_endpoints))
                    if has_ingress:
                        surfaces.append(ContentSurface(
                            category="doc_processing",
                            label=f"Document Processing Pipeline ({lib_name}) [Active]",
                            url=page_url,
                            evidence=f"Library indicator: '{token}' found in page source",
                            risk_note=(
                                f"{desc} detected. Applications using {lib_name} to parse "
                                "user-supplied files are vulnerable to polyglot-based parser "
                                "differential attacks — a file valid as GZIP+PDF can embed "
                                "malicious pickled payloads (ref: CVE-2025-64512 pattern). "
                                "Active ingress routes allow direct document submission."
                            ),
                            severity="high",
                            cve_ref=cve,
                            endpoints=doc_endpoints,
                            exploitability="active",
                            delivery_chain="Document Ingestion (Upload/API) → Parser Pipeline (pdfminer/etc.) → GZIP/Pickle Deserialization RCE",
                        ))
                    else:
                        surfaces.append(ContentSurface(
                            category="doc_processing",
                            label=f"Document Processing Pipeline ({lib_name}) [Supply-Chain]",
                            url=page_url,
                            evidence=f"Library indicator: '{token}' found in page source",
                            risk_note=(
                                f"{desc} detected on static target without upload forms. "
                                "LATENT VECTOR: Direct document upload is unavailable. Exploitation requires "
                                "pre-packaged document ingestion via asset repository, build artifacts, or "
                                "client-side document loading."
                            ),
                            severity="medium",
                            cve_ref=cve,
                            endpoints=doc_endpoints,
                            exploitability="latent",
                            delivery_chain="Static Document / Asset Bundled in Repository → Client/Build Pipeline Parser Differential",
                        ))
                    break  # one doc_processing surface per page

            # ── 3. Content embedding (iframe / object / embed) ────────────────
            embed_tags = soup.find_all(["iframe", "object", "embed"])
            same_origin_embeds = []
            embed_endpoints = []
            for tag in embed_tags:
                src = tag.get("src") or tag.get("data") or ""
                if src:
                    abs_src = urljoin(page_url, str(src))
                    if self._origin(abs_src) == origin:
                        same_origin_embeds.append(tag.name + ": " + str(src)[:60])
                        if abs_src not in embed_endpoints:
                            embed_endpoints.append(abs_src)
            if same_origin_embeds:
                if has_ingress:
                    surfaces.append(ContentSurface(
                        category="content_embed",
                        label="Same-Origin Content Embedding (Active)",
                        url=embed_endpoints[0] if embed_endpoints else page_url,
                        evidence=f"{len(embed_endpoints)} embedded resource(s): {same_origin_embeds[0]}",
                        risk_note=(
                            "Same-origin <iframe>, <object> or <embed> tag found loading content "
                            "without sandboxing. A polyglot file (e.g. PDF+HTML) served through this "
                            "embedding point executes its HTML/JS payload within the page origin, "
                            "bypassing same-origin restrictions."
                        ),
                        severity="medium",
                        cve_ref="CWE-1021 / CWE-79",
                        endpoints=embed_endpoints,
                        exploitability="active",
                        delivery_chain="User Content Upload → iframe/object/embed Rendering → Same-Origin Script Execution",
                    ))
                else:
                    surfaces.append(ContentSurface(
                        category="content_embed",
                        label="Same-Origin Content Embedding (Latent Supply-Chain)",
                        url=embed_endpoints[0] if embed_endpoints else page_url,
                        evidence=f"{len(embed_endpoints)} embedded resource(s): {same_origin_embeds[0]}",
                        risk_note=(
                            "Same-origin embedding tag without sandboxing. LATENT VECTOR: No upload endpoints "
                            "exist to inject dynamic files. Delivery relies on repository asset replacement "
                            "or external cross-origin embedding."
                        ),
                        severity="low",
                        cve_ref="CWE-1021 / CWE-79",
                        endpoints=embed_endpoints,
                        exploitability="latent",
                        delivery_chain="Asset Repository Injection → Unsandboxed Embedding → Same-Origin Execution",
                    ))

            # ── 4. API ingestion (fetch/XHR endpoints hinting at binary accept) ─
            api_patterns = [
                ("formdata", "FormData construction — JavaScript binary/file submission"),
                ("multipart", "multipart content hinted in JS source"),
                ("application/octet-stream", "Raw binary MIME type referenced in JS"),
                ("base64", "Base64 encoding — likely binary-to-text file transfer"),
                ("/api/upload", "API upload route referenced in JS"),
                ("/api/import", "API import route referenced in JS"),
                ("/api/ingest", "API ingest route referenced in JS"),
                ("/api/parse", "API parse route referenced in JS"),
                ("/api/convert", "API conversion route referenced in JS"),
                ("filereader", "FileReader API — client reads local files for upload"),
                ("arraybuffer", "ArrayBuffer — raw binary processing in JS"),
                ("blob:", "Blob URL — in-memory binary object handling"),
            ]
            api_endpoints = []
            matched_evidence = []
            api_matches = re.findall(r"['\"](/api/[a-zA-Z0-9_\-\/]+)['\"]", html)
            for m_path in api_matches:
                full_api = urljoin(page_url, m_path)
                if full_api not in api_endpoints:
                    api_endpoints.append(full_api)
            for pattern, desc in api_patterns:
                if pattern in html_lower:
                    if pattern == "formdata" and not any(k in html_lower for k in [".files", "type='file'", 'type="file"', ".append("]):
                        continue
                    matched_evidence.append(desc)
                    if pattern.startswith("/api/"):
                        full_p = urljoin(page_url, pattern)
                        if full_p not in api_endpoints:
                            api_endpoints.append(full_p)
            if not api_endpoints:
                api_endpoints = [page_url]
            if matched_evidence:
                surfaces.append(ContentSurface(
                    category="api_ingestion",
                    label="API Binary Ingestion Endpoint",
                    url=api_endpoints[0],
                    evidence=f"{matched_evidence[0]} (pattern: '{api_patterns[0][0]}')",
                    risk_note=(
                        "JavaScript source indicates binary file ingestion through a "
                        "non-form API path. These endpoints often lack the MIME validation "
                        "applied to traditional form uploads — polyglot payloads submitted "
                        "as raw binary or base64 bypass file-type checks applied only "
                        "at the HTML form layer."
                    ),
                    severity="medium",
                    cve_ref="CWE-434 (Unrestricted Ingestion)",
                    endpoints=api_endpoints,
                    exploitability="active",
                    delivery_chain="Direct HTTP API Request (JSON/FormData/Binary) → Direct Payload Ingestion",
                ))

            # ── 5. Cloud storage references ───────────────────────────────────
            cloud_patterns = [
                ("s3.amazonaws.com",       "AWS S3 bucket URL"),
                ("storage.googleapis.com", "Google Cloud Storage URL"),
                ("blob.core.windows.net",  "Azure Blob Storage URL"),
                ("cloudfront.net",         "AWS CloudFront CDN"),
                ("r2.dev",                 "Cloudflare R2 storage"),
                ("cdn.jsdelivr.net",       "jsDelivr CDN"),
                ("digitaloceanspaces.com", "DigitalOcean Spaces"),
                ("backblazeb2.com",        "Backblaze B2 storage"),
            ]
            for pattern, desc in cloud_patterns:
                if pattern in html_lower:
                    cloud_endpoints = []
                    urls_found = re.findall(rf"https?://[^\s'\"<>()]+{re.escape(pattern)}[^\s'\"<>()]*", html, re.IGNORECASE)
                    for u in urls_found:
                        if u not in cloud_endpoints:
                            cloud_endpoints.append(u)
                    if not cloud_endpoints:
                        cloud_endpoints = [page_url]
                    surfaces.append(ContentSurface(
                        category="cloud_storage",
                        label=f"Cloud Storage Content ({desc})",
                        url=cloud_endpoints[0],
                        evidence=f"{desc} URL referenced in page source",
                        risk_note=(
                            f"{desc} detected. Files stored in cloud buckets and served "
                            "via CDN typically bypass server-side content validation — the "
                            "cloud storage layer stores objects verbatim. A polyglot uploaded "
                            "to the bucket is served as-is; if the CDN does not enforce "
                            "Content-Type or Content-Disposition headers, browsers will "
                            "execute the embedded payload."
                        ),
                        severity="medium",
                        cve_ref="CWE-829 (Cloud/CDN Ingestion)",
                        endpoints=cloud_endpoints,
                        exploitability="latent",
                        delivery_chain="Direct S3/GCS Upload or Bucket Write Access → CDN Distribution → Unvalidated Asset Ingestion",
                    ))
                    break  # one cloud_storage surface per page

            # ── 6. Download/serve routes without Content-Disposition: attachment ─
            download_links = []
            for tag in soup.find_all("a", href=True):
                href = str(tag.get("href", "")).lower()
                if any(p in href for p in ["/download", "/export", "/files/", "/media/", "/assets/"]):
                    abs_href = urljoin(page_url, tag["href"])
                    if self._origin(abs_href) == origin and abs_href not in download_links:
                        download_links.append(abs_href)
            if download_links:
                if has_ingress:
                    surfaces.append(ContentSurface(
                        category="download_serve",
                        label="File Download / Serve Endpoint (Active Delivery)",
                        url=download_links[0],
                        evidence=f"{len(download_links)} download link(s): {download_links[0][:80]}",
                        risk_note=(
                            "File download/serve endpoints detected. If responses lack "
                            "'Content-Disposition: attachment', the browser renders the file "
                            "inline. ACTIVE: Combined with upload endpoints, a polyglot uploaded "
                            "and served here executes its embedded script payload within the site's origin."
                        ),
                        severity="high",
                        cve_ref="CWE-430 (Inline File Execution)",
                        endpoints=download_links,
                        exploitability="active",
                        delivery_chain="File Upload → File Served via /download without C-D: attachment → Inline Browser Rendering",
                    ))
                else:
                    surfaces.append(ContentSurface(
                        category="download_serve",
                        label="File Download / Serve Endpoint (Latent Supply-Chain)",
                        url=download_links[0],
                        evidence=f"{len(download_links)} download link(s): {download_links[0][:80]}",
                        risk_note=(
                            "File download/serve endpoints detected without attachment disposition. "
                            "LATENT: In the absence of upload forms, exploitation requires asset "
                            "substitution in the repository/CDN."
                        ),
                        severity="medium",
                        cve_ref="CWE-430 (Inline File Execution)",
                        endpoints=download_links,
                        exploitability="latent",
                        delivery_chain="Asset Bundled in Repository → Served via Download Route without C-D: attachment → Inline Browser Rendering",
                    ))


            # ── 7. SVG upload / serving surfaces ─────────────────────
            svg_endpoints = []
            for _tag in soup.find_all(["img", "object", "embed", "source"]):
                _src = str(_tag.get("src", "") or _tag.get("data", ""))
                if _src.lower().endswith(".svg") or "image/svg" in _src.lower():
                    _abs_src = urljoin(page_url, _src)
                    if _abs_src not in svg_endpoints:
                        svg_endpoints.append(_abs_src)
            has_inline_svg = "<svg" in html_lower
            svg_upload_forms = [
                _f for _f in soup.find_all("form")
                if any(
                    "svg" in str(_inp.get("accept", "")).lower() or
                    "image" in str(_inp.get("accept", "")).lower()
                    for _inp in _f.find_all("input", {"type": "file"})
                )
            ]
            has_svg_upload = len(svg_upload_forms) > 0
            _avatar_pats = ["avatar", "logo", "icon", "profile", "picture", "photo"]
            has_avatar_upload = any(
                any(_ap in str(_inp.get("name", "")).lower() or _ap in str(_inp.get("id", "")).lower()
                    for _ap in _avatar_pats)
                for _f in soup.find_all("form")
                for _inp in _f.find_all("input", {"type": "file"})
            )
            if svg_endpoints or has_svg_upload or has_avatar_upload or has_inline_svg:
                _csp_header = headers.get("content-security-policy", "")
                _script_blocked = "script-src" in _csp_header.lower() and "'none'" in _csp_header
                _svg_severity = "medium" if _script_blocked else "high"
                _svg_evidence = []
                if svg_endpoints:
                    _svg_evidence.append(f"{len(svg_endpoints)} SVG asset(s) referenced")
                if has_inline_svg:
                    _svg_evidence.append("inline SVG element in page source")
                if has_svg_upload:
                    _svg_evidence.append("file upload form accepting images (SVG capable)")
                if has_avatar_upload:
                    _svg_evidence.append("avatar/profile image upload field detected")
                _svg_eps = svg_endpoints if svg_endpoints else [page_url]
                surfaces.append(ContentSurface(
                    category="svg_serving",
                    label="SVG Vector Asset Endpoint (DOM Scripting Surface)",
                    url=_svg_eps[0],
                    evidence="; ".join(_svg_evidence) if _svg_evidence else "SVG indicator in page",
                    risk_note=(
                        "SVG (Scalable Vector Graphics) is an XML-based vector format that natively "
                        "supports script elements and event-handler attributes (onload, onerror) "
                        "per the W3C SVG specification. CRITICAL DISTINCTION from raster images: "
                        "PNG/JPEG/GIF are binary pixel matrices decoded in an isolated image pipeline "
                        "where scripting is impossible. SVG is an XML DOM - the browser builds a full "
                        "DOM tree and executes embedded scripts. ACTIVE VECTOR: When a user-supplied SVG "
                        "is served via object, embed, iframe, or direct URL navigation without a "
                        "restrictive CSP (script-src none) or origin sandboxing, embedded script "
                        "and onload= handlers execute in the full serving origin (Stored XSS). "
                        "SVG has NO binary magic bytes - trivially bypasses magic-byte upload filters."
                    ),
                    severity=_svg_severity,
                    cve_ref="CWE-79 (Stored XSS via SVG W3C Native Scripting)",
                    endpoints=_svg_eps,
                    exploitability="active" if (has_svg_upload or has_avatar_upload or has_inline_svg) else "latent",
                    delivery_chain=(
                        "SVG Upload (bypasses binary magic-byte filter) "
                        "-> Served via object/embed/iframe or direct URL "
                        "-> Browser builds SVG DOM -> script/onload executes in origin "
                        "-> Stored XSS / DOM Origin Execution"
                    ),
                ))


            # ── 8. Client-side parameter reflection (URLSearchParams -> DOM Sink) ─
            has_url_params = any(p in html_lower for p in ["urlsearchparams", "location.search", "location.hash", "window.location.search"])
            has_dom_sink = any(s in html_lower for s in [
                "<object", "<embed", "<iframe",
                "createelement('object')", 'createelement("object")',
                "createelement('embed')", 'createelement("embed")',
                "createelement('iframe')", 'createelement("iframe")',
                ".data =", ".data=", ".src =", ".src="
            ])
            if has_url_params and has_dom_sink:
                param_names = []
                for m in re.finditer(r"params\.get\(['\"]([a-zA-Z0-9_\-]+)['\"]\)", html_lower):
                    param_names.append(m.group(1))
                if not param_names:
                    for m in re.finditer(r"searchparams\.get\(['\"]([a-zA-Z0-9_\-]+)['\"]\)", html_lower):
                        param_names.append(m.group(1))
                if not param_names:
                    param_names = ["preview"]

                unique_params = list(dict.fromkeys(param_names))
                param_eps = [f"{page_url}?{p}=" for p in unique_params]
                surfaces.append(ContentSurface(
                    category="param_reflection",
                    label="Client-Side Parameter Reflection (DOM Media/Object Viewer)",
                    url=param_eps[0],
                    evidence=f"URL query parameters ({', '.join(unique_params)}) dynamically loaded into DOM browsing sink (<object>/<embed>/<iframe>)",
                    risk_note=(
                        f"Client-side script parses query parameter(s) (?{', '.join(unique_params)}=) "
                        "and renders the target resource into a DOM browsing context (<object>, <embed>, or <iframe>). "
                        "ACTIVE EXPLOIT VECTOR: In the absence of X-Content-Type-Options: nosniff and CSP, an attacker "
                        "can craft a malicious URL referencing a polyglot file (e.g. ?preview=polyglot.png). The browser's "
                        "MIME-sniffing algorithm sniffs the polyglot file, renders the embedded HTML, and executes JavaScript "
                        "within the application's origin (DOM-Based MIME Confusion XSS)."
                    ),
                    severity="high" if not nosniff else "medium",
                    cve_ref="CWE-79 / CWE-430 (DOM MIME Confusion)",
                    endpoints=param_eps,
                    exploitability="active",
                    delivery_chain=f"Malicious Link (?{unique_params[0]}=polyglot.png) → Client DOM Parsing (URLSearchParams) → <object> Embedding without nosniff → Browser MIME Confusion XSS",
                ))

        except Exception:
            pass

        return surfaces

    def _detect_content_surfaces_from_headers(
        self, url: str, headers: dict[str, str], has_ingress: bool = True
    ) -> list[ContentSurface]:
        """
        Detect content processing surfaces from HTTP response headers alone
        (used for non-HTML endpoints such as file serving routes, APIs).
        """
        surfaces: list[ContentSurface] = []
        path = urlparse(url).path.lower()
        ct = headers.get("content-type", "").lower()
        cd = headers.get("content-disposition", "").lower()

        # File served inline (no Content-Disposition: attachment) with a parseable MIME
        inline_mimes = ["image/", "application/pdf", "application/zip",
                        "application/octet-stream", "application/x-php"]
        if any(m in ct for m in inline_mimes) and "attachment" not in cd:
            user_paths = ["/upload", "/uploads", "/files", "/media", "/static",
                          "/assets", "/download", "/export", "/content", "/storage"]
            if any(p in path for p in user_paths):
                if has_ingress:
                    surfaces.append(ContentSurface(
                        category="download_serve",
                        label="Inline File Serving (Active Delivery)",
                        url=url,
                        evidence=f"Content-Type: {ct} served without attachment disposition",
                        risk_note=(
                            "A file endpoint serves content inline without forcing browser download. "
                            "If a polyglot file (e.g. PNG+HTML) reaches this endpoint, the browser "
                            "may render it as HTML, executing the embedded payload within the origin."
                        ),
                        severity="high",
                        cve_ref="CWE-430 (Inline Execution)",
                        endpoints=[url],
                        exploitability="active",
                        delivery_chain="File Upload → Direct File URL Access → Browser Inline Execution",
                    ))
                else:
                    surfaces.append(ContentSurface(
                        category="download_serve",
                        label="Inline File Serving (Latent Supply-Chain)",
                        url=url,
                        evidence=f"Content-Type: {ct} served without attachment disposition",
                        risk_note=(
                            "A file endpoint serves content inline without forcing browser download. "
                            "LATENT: In the absence of upload endpoints, exploitation requires asset "
                            "poisoning in repository or CDN."
                        ),
                        severity="medium",
                        cve_ref="CWE-430 (Inline Execution)",
                        endpoints=[url],
                        exploitability="latent",
                        delivery_chain="Pre-existing Static Asset on Host → Direct File URL Access → Browser Inline Execution",
                    ))

        # API endpoint accepting or returning binary
        api_paths = ["/api/", "/v1/", "/v2/", "/graphql", "/rpc"]
        if any(p in path for p in api_paths) and "json" not in ct:
            if "multipart" in ct or "octet-stream" in ct or "form" in ct:
                surfaces.append(ContentSurface(
                    category="api_ingestion",
                    label="API Endpoint Accepting Binary Data",
                    url=url,
                    evidence=f"Content-Type: {ct} on API path {path}",
                    risk_note=(
                        "An API endpoint handles binary/multipart content. API-layer "
                        "file ingestion often skips the MIME validation applied at the "
                        "HTML form level — polyglots submitted as raw binary or in a "
                        "multipart field may bypass content-type checks entirely."
                    ),
                    severity="medium",
                    cve_ref="CWE-434 (API Binary Bypass)",
                    endpoints=[url],
                    exploitability="active",
                    delivery_chain="Direct API Call → Binary Ingestion Bypass",
                ))

        return surfaces

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _load_signatures(self) -> dict:
        try:
            return json.loads(self._SIGNATURES_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(
                f"Cannot load fingerprint signatures: {self._SIGNATURES_PATH}\n{exc}"
            ) from exc
