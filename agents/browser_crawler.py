"""Playwright pass of the hybrid crawl engine (spec: headless browser recon).

What the plain-httpx pass fundamentally cannot see:
  * XHR/fetch API calls fired by SPA JavaScript (e.g. Juice Shop's
    /rest/products/search?q=...) — captured here via page.on("request");
  * client-side routes rendered after hydration;
  * tokens stored in localStorage (Juice Shop keeps its JWT there).

Graceful degradation: if Playwright or its browser binary is missing the
caller receives a note instead of a crash, and the site map is still
produced from the httpx pass.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlsplit, parse_qsl

from agents.models import Endpoint, Param
from agents.crawler import RE_JWT

log = logging.getLogger("hackbot.browser")

JWT_LOCALSTORAGE_KEY_HINTS = ("token", "jwt", "auth", "session")


class BrowserCrawler:
    """Captures network traffic + client-side routes of an SPA target."""

    def __init__(self, base_url: str, *, max_spa_routes: int = 15, navigation_timeout: int = 15000):
        self.base_url = base_url.rstrip("/")
        self.max_spa_routes = max_spa_routes
        self.timeout = navigation_timeout
        self.captured: dict[tuple[str, str], Endpoint] = {}
        self.local_storage: dict[str, str] = {}
        self.cookies: list[dict] = []
        self.jwt_tokens: list[str] = []
        self.blocked_by_scope = 0
        self.errors: list[str] = []

    # ------------------------------------------------------------------ #
    def run(self, is_allowed, auth_cookies: list[dict] | None = None,
            auth_token: str | None = None) -> bool:
        """Run the browser pass. Returns True if it actually executed.

        is_allowed: callable(url) -> bool — scope enforcement callback; every
        captured request and every navigation target is filtered through it.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.errors.append("playwright not installed — browser pass skipped")
            return False

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    context = browser.new_context(ignore_https_errors=True)
                    if auth_cookies:
                        try:
                            context.add_cookies(auth_cookies)
                        except Exception as exc:  # bad cookie shapes etc.
                            self.errors.append(f"cookie injection failed: {exc}")
                    page = context.new_page()
                    page.set_default_timeout(self.timeout)

                    page.on("request", lambda req: self._on_request(req, is_allowed))
                    page.on("response", lambda resp: self._on_response(resp, is_allowed))

                    self._visit(page, self.base_url, is_allowed)
                    self._harvest_local_storage(page)

                    if auth_token:  # SPA token injection (e.g. Juice Shop JWT)
                        self._inject_token(page, auth_token)

                    routes = self._collect_anchors(page, is_allowed)
                    for route in routes[: self.max_spa_routes]:
                        self._visit(page, route, is_allowed)
                        self._harvest_local_storage(page)

                    self.cookies = context.cookies()
                finally:
                    browser.close()
        except Exception as exc:
            self.errors.append(f"browser pass failed: {type(exc).__name__}: {exc}")
            log.warning("Playwright pass failed: %s", exc)
            return False
        return True

    # ------------------------------------------------------------------ #
    def _visit(self, page, url: str, is_allowed) -> None:
        if not is_allowed(url):
            self.blocked_by_scope += 1
            return
        try:
            page.goto(url, wait_until="load", timeout=self.timeout)
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass  # long-polling apps never go idle — capture what we got
        except Exception as exc:
            self.errors.append(f"goto {url}: {type(exc).__name__}")

    def _on_request(self, request, is_allowed) -> None:
        try:
            url = request.url
            if not is_allowed(url):
                self.blocked_by_scope += 1
                return
            method = request.method.upper()
            if url.startswith("data:") or url.endswith((".png", ".jpg", ".woff2", ".ico", ".svg")):
                return
            params = self._params_from_request(request)
            self._record(method, url, params=params)
        except Exception:
            pass

    def _on_response(self, response, is_allowed) -> None:
        try:
            url = response.url
            if not is_allowed(url):
                return
            ep = self._record(response.request.method.upper(), url)
            if response.status not in ep.status_codes:
                ep.status_codes.append(response.status)
            ct = response.headers.get("content-type", "")
            if ct and not ep.content_type:
                ep.content_type = ct.split(";")[0].lower()
        except Exception:
            pass

    def _params_from_request(self, request) -> list[Param]:
        params: list[Param] = []
        try:
            qs = urlsplit(request.url).query
            for k, v in parse_qsl(qs, keep_blank_values=True):
                p = Param(name=k, location="query", type_hint="unknown")
                if v:
                    p.examples = [v]
                if v and v.lstrip("-+").isdigit():
                    p.type_hint = "number"
                params.append(p)
            body = request.post_data
            if body:
                import json as _json
                try:
                    data = _json.loads(body)
                    if isinstance(data, dict):
                        params.extend(Param(name=k, location="body", type_hint="string") for k in data)
                except ValueError:
                    pass
        except Exception:
            pass
        return params

    def _record(self, method: str, url: str, **kw) -> Endpoint:
        from agents.crawler import normalize_key
        key = normalize_key(method, url)
        ep = self.captured.get(key)
        if ep is None:
            ep = Endpoint(url=url, method=method, discovered_via="network")
            self.captured[key] = ep
        for p in kw.get("params", []):
            ep._upsert_param(p)
        return ep

    # ------------------------------------------------------------------ #
    def _harvest_local_storage(self, page) -> None:
        try:
            raw = page.evaluate("() => JSON.stringify(window.localStorage)")
            import json as _json
            data = _json.loads(raw or "{}")
            for k, v in data.items():
                self.local_storage[k] = str(v)[:300]
                if RE_JWT.search(str(v)):
                    token = RE_JWT.search(str(v)).group(0)  # type: ignore[union-attr]
                    if token not in self.jwt_tokens:
                        self.jwt_tokens.append(token)
        except Exception:
            pass

    def _inject_token(self, page, token: str) -> None:
        """Best-effort: store JWT under common SPA localStorage keys, then reload."""
        try:
            for key in ("token", "jwt", "auth_token", "id_token"):
                page.evaluate("([k, v]) => window.localStorage.setItem(k, v)", [key, token])
            page.reload(wait_until="load")
        except Exception as exc:
            self.errors.append(f"token injection: {type(exc).__name__}")

    def _collect_anchors(self, page, is_allowed) -> list[str]:
        routes: list[str] = []
        try:
            hrefs = page.eval_on_selector_all("a", "els => els.map(e => e.getAttribute('href'))") or []
            origin = urlsplit(self.base_url).netloc
            for href in hrefs:
                if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                url = urljoin(self.base_url + "/", href)
                p = urlsplit(url)
                if p.netloc != origin or p.scheme not in ("http", "https"):
                    continue
                if is_allowed(url) and url.rstrip("/") != self.base_url.rstrip("/"):
                    routes.append(url)
        except Exception:
            pass
        seen, uniq = set(), []
        for r in routes:
            if r not in seen:
                seen.add(r)
                uniq.append(r)
        return uniq

    # ------------------------------------------------------------------ #
    def scan_jwt_cookies(self) -> list[str]:
        for cookie in self.cookies:
            if RE_JWT.search(cookie.get("value", "")):
                token = RE_JWT.search(cookie["value"]).group(0)  # type: ignore[union-attr]
                if token not in self.jwt_tokens:
                    self.jwt_tokens.append(token)
        return self.jwt_tokens
