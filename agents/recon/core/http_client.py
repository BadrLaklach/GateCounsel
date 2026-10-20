"""Scope-aware, rate-limited HTTP client.

The single network choke-point of the httpx-side recon pipeline:
  * every request is checked against the ScopeGuard BEFORE it is sent;
  * redirects are followed manually and re-checked at every hop;
  * a token-bucket-style interval enforces the operator's rps cap;
  * response bodies are capped to avoid memory blow-ups.
"""

from __future__ import annotations

import json as _json
import logging
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from safety.scope_guard import ScopeGuard

log = logging.getLogger("gatecounsel.http")

MAX_REDIRECTS = 6
DEFAULT_BODY_CAP = 2 * 1024 * 1024  # 2 MB


@dataclass
class FetchResult:
    """Normalized result of one HTTP exchange."""

    url: str
    final_url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    error: str | None = None
    redirects: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and self.status < 500

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str | None:
        ct = self.headers.get("content-type")
        return ct.split(";")[0].strip().lower() if ct else None

    def json(self):
        try:
            return _json.loads(self.text)
        except (ValueError, TypeError):
            return None


class ScopedHttpClient:
    """httpx.Client wrapper enforcing scope + rate limits for every request."""

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        rps: float = 5.0,
        timeout: float = 10.0,
        user_agent: str = "GateCounsel-Recon/0.1 (security research; authorized lab target)",
        body_cap: int = DEFAULT_BODY_CAP,
    ) -> None:
        self.guard = guard
        self.rps = max(rps, 0.1)
        self._min_interval = 1.0 / self.rps
        self._last_request = 0.0
        self._lock = threading.Lock()
        self.body_cap = body_cap
        self.requests_made = 0
        self.errors = 0
        self.scope_blocked = 0
        self.jwt_token: str | None = None  # set by AuthDetector on successful login
        self._client = httpx.Client(
            follow_redirects=False,  # manual: re-check scope on every hop
            timeout=httpx.Timeout(timeout),
            verify=False,  # lab targets commonly use self-signed certs
            headers={"User-Agent": user_agent, "Accept": "*/*"},
        )

    # ------------------------------------------------------------------ #
    def _throttle(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        data=None,
        json=None,  # noqa: A002 - matches httpx signature
        follow_redirects: bool = True,
    ) -> FetchResult:
        """Send a request through the Scope Guard with manual redirect checks."""
        try:
            self.guard.enforce(url)
        except PermissionError as exc:
            self.scope_blocked += 1
            log.warning("Blocked by scope: %s", exc)
            return FetchResult(url=url, final_url=url, error=f"scope: {exc}")

        current = url
        hops: list[str] = []
        merged = dict(self.auth_headers())
        merged.update(headers or {})
        result_headers = merged

        for _hop in range(MAX_REDIRECTS + 1):
            self._throttle()
            self.requests_made += 1
            started = time.monotonic()
            try:
                resp = self._client.request(
                    method, current, headers=result_headers, content=content, data=data, json=json
                )
            except httpx.HTTPError as exc:
                self.errors += 1
                return FetchResult(url=url, final_url=current, error=f"{type(exc).__name__}: {exc}",
                                   redirects=hops, elapsed=time.monotonic() - started)

            elapsed = time.monotonic() - started
            if resp.is_redirect and follow_redirects:
                loc = resp.headers.get("location", "")
                if not loc:
                    return self._from_response(resp, url, current, hops, elapsed)
                nxt = urljoin(current, loc)
                try:
                    self.guard.enforce(nxt)  # re-check every redirect hop
                except PermissionError as exc:
                    self.scope_blocked += 1
                    log.warning("Redirect blocked by scope: %s", exc)
                    return FetchResult(url=url, final_url=current, error=f"scope: {exc}",
                                       redirects=hops, elapsed=elapsed)
                hops.append(nxt)
                current = nxt
                # RFC 7231: 301/302/303 switch the method to GET and drop the
                # body; 307/308 keep the original method and body. Re-POSTing
                # to the redirect target would corrupt login/CSRF flows.
                if resp.status_code in (301, 302, 303) and method.upper() not in ("GET", "HEAD"):
                    method = "GET"
                    content, data, json = None, None, None  # noqa: A002
                    result_headers = {
                        k: v for k, v in result_headers.items()
                        if k.lower() not in ("content-length", "content-type")
                    }
                continue

            return self._from_response(resp, url, current, hops, elapsed)

        return FetchResult(url=url, final_url=current, error="too many redirects", redirects=hops)

    def _from_response(self, resp: httpx.Response, url: str, final_url: str, hops, elapsed) -> FetchResult:
        body = b""
        read_error: str | None = None
        try:
            for chunk in resp.iter_bytes(65536):
                body += chunk
                if len(body) >= self.body_cap:
                    break
        except httpx.HTTPError as exc:
            read_error = f"partial body read: {type(exc).__name__}"
        return FetchResult(
            url=url,
            final_url=final_url,
            status=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            body=body,
            elapsed=elapsed,
            redirects=hops,
            error=read_error,
        )

    # Convenience verbs ------------------------------------------------- #
    @property
    def cookie_names(self) -> list[str]:
        """Names of cookies the session currently holds."""
        try:
            return list(self._client.cookies.keys())
        except Exception:
            return []

    def auth_headers(self) -> dict[str, str]:
        """Authorization header for the stored JWT, if any."""
        return {"Authorization": f"Bearer {self.jwt_token}"} if self.jwt_token else {}

    def get(self, url: str, **kw) -> FetchResult:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> FetchResult:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw) -> FetchResult:
        return self.request("HEAD", url, follow_redirects=False, **kw)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScopedHttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
