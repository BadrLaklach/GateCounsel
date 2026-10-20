"""Breadth-first HTTP crawler (fast first pass of the hybrid engine).

Discovers pages, links, HTML forms, SPA hash routes and API paths referenced
from JavaScript — all via GET requests only. POST endpoints seen in JS are
*recorded* but never auto-fired (only the operator-driven auto-login POSTs).
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, parse_qsl, urlencode, urlunsplit

from bs4 import BeautifulSoup

from agents.recon.core.http_client import FetchResult, ScopedHttpClient
from agents.recon.scanners.fingerprint import fingerprint
from agents.recon.core.models import Endpoint, FormInfo, Param, TechHint

log = logging.getLogger("gatecounsel.crawler")

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
    ".webm", ".pdf", ".zip", ".gz", ".tgz", ".tar", ".dmg", ".exe",
)

# --- JS API extraction --------------------------------------------------- #
RE_FETCH = re.compile(r"""fetch\(\s*['"`]([^'"`\s]+)['"`]""", re.I)
RE_AXIOS = re.compile(r"""axios(?:\.[a-z]+)?\(\s*['"`]([^'"`\s]+)['"`]""", re.I)
RE_AXIOS_VERB = re.compile(r"""\.\s*(?:get|post|put|patch|delete)\(\s*['"`]([^'"`\s]+)['"`]""", re.I)
RE_XHR = re.compile(r"""\.open\(\s*['"]([A-Z]+)['"]\s*,\s*['"]([^'"]+)['"]""", re.I)
RE_API_LITERAL = re.compile(r"""['"`](/(?:api|rest|graphql|v[1-9])(?:/api)?[/A-Za-z0-9_.\-{}]*)['"`]""")
RE_HASH_ROUTE = re.compile(r"""['"`]#/([A-Za-z0-9_\-/?=&.%]+)['"`]""")
RE_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")


@dataclass
class FetchObservation:
    """One fetch's harvest to fold into an endpoint record."""

    result: FetchResult | None = None
    params: list[Param] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)


def looks_like_page(url: str) -> bool:
    """Filter out static assets from the crawl queue."""
    path = urlsplit(url).path.lower()
    return not path.endswith(SKIP_EXTENSIONS)


def normalize_key(method: str, url: str) -> tuple[str, str]:
    """Dedupe key: (method, path-with-sorted-param-NAMES)."""
    parts = urlsplit(url)
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = urlencode([(n, "") for n in names])
    path = parts.path or "/"
    return method.upper(), f"{parts.scheme}://{parts.netloc}{path}?{query}".rstrip("?").rstrip("/")


class HttpCrawler:
    """Crawls same-origin pages BFS-style, harvesting endpoints and forms."""

    def __init__(self, client: ScopedHttpClient, base_url: str, *, max_pages: int = 60, max_depth: int = 3):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.origin = urlsplit(base_url)
        self.max_pages = max_pages
        self.max_depth = max_depth
        # (method, key) -> Endpoint
        self.endpoints: dict[tuple[str, str], Endpoint] = {}
        self.seen_urls: set[str] = set()
        self.hash_routes: set[str] = set()
        self.session_cookies: dict[str, str] = {}
        self.jwt_hits: list[str] = []
        self.tech_hints: list[TechHint] = []
        self.pages_crawled = 0
        self.fingerprints: list[tuple[str, str, str]] = []  # (kind, name, evidence) raw intel

    # ------------------------------------------------------------------ #
    def same_origin(self, url: str) -> bool:
        try:
            p = urlsplit(url)
        except ValueError:
            return False
        return p.scheme in ("http", "https") and p.netloc == self.origin.netloc

    def record(self, method: str, url: str, observation: FetchObservation | None = None,
               *, via: str = "link") -> Endpoint:
        method = method.upper()
        key = normalize_key(method, url)
        ep = self.endpoints.get(key)
        if ep is None:
            ep = Endpoint(url=url, method=method, discovered_via=via)  # type: ignore[arg-type]
            self.endpoints[key] = ep
        if observation is None:
            return ep
        result = observation.result
        if result is not None:
            if result.status and result.status not in ep.status_codes:
                ep.status_codes.append(result.status)
            if result.content_type and not ep.content_type:
                ep.content_type = result.content_type
            body_text = result.text[:300].strip()
            if body_text and not ep.response_snippet:
                ep.response_snippet = " ".join(body_text.split())[:200]
        for p in observation.params:
            ep._upsert_param(p)
        for f in observation.forms:
            if f.model_dump() not in [x.model_dump() for x in ep.forms]:
                ep.forms.append(f)
        return ep

    def params_from_url(self, url: str) -> list[Param]:
        parts = urlsplit(url)
        out: dict[str, Param] = {}
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            p = out.setdefault(k, Param(name=k, location="query", type_hint="unknown"))
            if v and len(p.examples) < 3 and v not in p.examples:
                p.examples.append(v)
            if v and v.lstrip("-+").isdigit() and p.type_hint == "unknown":
                p.type_hint = "number"
        return list(out.values())

    # ------------------------------------------------------------------ #
    def crawl(self) -> None:
        queue: deque[tuple[str, int]] = deque([(self.base_url + "/", 0)])
        self.seen_urls.add(normalize_key("GET", self.base_url + "/")[1])

        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            if not looks_like_page(url):
                continue
            result = self.client.get(url)
            if result.error or result.status is None:
                log.debug("fetch failed %s: %s", url, result.error)
                continue

            self.pages_crawled += 1
            ep = self.record("GET", url,
                             FetchObservation(result=result, params=self.params_from_url(url)))
            self._scan_common_headers(result)
            try:
                self.tech_hints.extend(fingerprint(result.headers, result.text))
            except Exception:  # fingerprinting must never break the crawl
                pass

            ctype = result.content_type or ""
            if "json" in ctype:
                self._ingest_json(url, result, ep)
            if "html" in ctype or "xml" in ctype:
                self._ingest_markup(url, result.text, depth)
            if "javascript" in ctype or path_is_js(url):
                self._ingest_javascript(result.text)
            if self._scan_jwt(result):
                pass  # hits appended internally

            if depth >= self.max_depth:
                continue
            for link in self._collect_links(url, result.text):
                if self.same_origin(link) and looks_like_page(link):
                    k = normalize_key("GET", link)[1]
                    if k not in self.seen_urls:
                        self.seen_urls.add(k)
                        queue.append((link, depth + 1))

    # ------------------------------------------------------------------ #
    def _collect_links(self, base: str, text: str) -> list[str]:
        links: list[str] = []
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception:  # malformed markup
            return links
        for tag in soup.find_all(["a", "area", "link"]):
            href = tag.get("href")
            if href:
                links.append(urljoin(base, href))
        for tag in soup.find_all(["script", "img", "iframe", "source"]):
            src = tag.get("src")
            if src:
                links.append(urljoin(base, src))
        return links

    def _ingest_markup(self, url: str, text: str, depth: int) -> None:
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            return

        # HTML forms -> endpoints + params
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "GET").upper()
            fields, ftypes = [], {}
            hidden_values: dict[str, str] = {}
            has_pw = False
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                ftype = (inp.get("type") or "text").lower()
                fields.append(name)
                ftypes[name] = ftype
                if ftype == "password":
                    has_pw = True
                if ftype == "hidden":  # CSRF tokens / nonces (snapshot; refreshed at login time)
                    hidden_values[name] = inp.get("value") or ""
            info = FormInfo(
                action=action, method=method, fields=fields, field_types=ftypes,
                hidden_values=hidden_values, page_url=url,
                has_password_field=has_pw, likely_login=has_pw,
            )
            self.record(method, action, FetchObservation(forms=[info]), via="form")
            loc = "body" if method == "POST" else "query"
            params = [Param(name=n, location=loc, type_hint="string")  # type: ignore[arg-type]
                      for n in fields]
            self.record(method, action, FetchObservation(params=params), via="form")

        # SPA hash routes (AngularJS-style #/routing)
        for m in RE_HASH_ROUTE.finditer(text):
            self.hash_routes.add("/#" + m.group(1))
        for tag in soup.find_all("a"):
            href = tag.get("href") or ""
            if href.startswith("#/"):
                self.hash_routes.add("/" + href)

    def _ingest_javascript(self, text: str) -> None:
        for regex in (RE_FETCH, RE_AXIOS):
            for m in regex.finditer(text):
                self._record_js_path(m.group(1), "GET")
        for m in RE_AXIOS_VERB.finditer(text):
            verb = re.search(r"""\.\s*(get|post|put|patch|delete)\(""", m.group(0), re.I)
            self._record_js_path(m.group(1), (verb.group(1) if verb else "GET").upper())
        for m in RE_XHR.finditer(text):
            self._record_js_path(m.group(2), m.group(1).upper())
        for m in RE_API_LITERAL.finditer(text):
            self._record_js_path(m.group(1), None, unverified=True)

    def _record_js_path(self, raw: str, method: str | None, unverified: bool = False) -> None:
        if not raw or raw.startswith(("http://", "https://", "//", "data:", "blob:")):
            return
        if "{" in raw and "}" in raw:
            raw = re.sub(r"\$\{[^}]*\}", "", raw)  # drop template interpolations
        url = urljoin(self.base_url + "/", raw)
        if not self.same_origin(url):
            return
        m = method or "GET"
        note = "seen in JS; not probed (method inferred)" if unverified else "referenced in JS"
        ep = self.record(m, url, via="js")
        ep.notes = f"{ep.notes or ''}; {note}".strip("; ")
        if unverified:
            ep.notes = f"{ep.notes or ''}; unverified".strip("; ")

    def _ingest_json(self, url: str, result: FetchResult, ep: Endpoint) -> None:
        data = result.json()
        if isinstance(data, dict):
            ep.response_snippet = "json keys: " + ", ".join(list(data.keys())[:10])
        elif isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                ep.response_snippet = f"json array[{len(data)}] item keys: " + ", ".join(list(first.keys())[:10])

    def _scan_common_headers(self, result: FetchResult) -> None:
        for name, value in result.headers.items():
            if name in ("server", "x-powered-by"):
                self.fingerprints.append(("header", name, value[:80]))
            if name == "set-cookie":
                cookie_name = value.split("=", 1)[0].strip()
                if cookie_name and cookie_name not in self.session_cookies:
                    self.session_cookies[cookie_name] = value[:120]
                self.fingerprints.append(("cookie", "set-cookie", value.split(";", 1)[0][:80]))
            if name == "content-security-policy":
                self.fingerprints.append(("header", "content-security-policy", value[:80]))

    def _scan_jwt(self, result: FetchResult) -> bool:
        hit = False
        for m in RE_JWT.finditer(result.text[:8192]):
            token = m.group(0)
            if token not in self.jwt_hits:
                self.jwt_hits.append(token)
                hit = True
        auth = result.headers.get("authorization", "")
        if RE_JWT.search(auth):
            hit = True
        return hit


def path_is_js(url: str) -> bool:
    return urlsplit(url).path.lower().endswith(".js")
