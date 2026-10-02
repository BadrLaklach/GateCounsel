"""Hackbot Recon Agent (spec §6.1) — builds the structured site map.

Pipeline phases:
  0. scope registration + target reachability check
  1. fast httpx BFS crawl (links, forms, JS-referenced API paths)
  2. API surface guessing (robots/sitemap/OpenAPI/common prefixes, GET-only)
  3. auth detection; operator-driven auto-login; protected-surface probing
  4. Playwright network-capture pass (SPA XHR/fetch + localStorage tokens)
  5. technology fingerprinting (headers + body signatures)
  6. bounded reflection probing (benign marker, GET-only)

Output: agents.models.SiteMap — the contract consumed by the Planner Agent.
Every network request (httpx or captured from the browser) is filtered
through the deterministic ScopeGuard.
"""

from __future__ import annotations

import logging
import time
from typing import Any, TypedDict
from urllib.parse import urljoin, urlsplit

from agents.auth_detector import AuthDetector, decode_jwt
from agents.browser_crawler import BrowserCrawler
from agents.crawler import HttpCrawler, normalize_key
from agents.fingerprint import fingerprint, merge_hints
from agents.gemini_planner import GeminiReconPlanner
from agents.http_client import ScopedHttpClient
from agents.katana_crawler import KatanaCrawler
from agents.models import AuthInfo, Endpoint, SiteMap, TechHint
from agents.param_probe import ParamProber
from safety.scope_guard import ScopeGuard

log = logging.getLogger("hackbot.recon")


class ReconConfig(TypedDict, total=False):
    max_pages: int
    max_depth: int
    rps: float
    timeout: float
    use_playwright: bool
    max_reflection_probes: int
    max_spa_routes: int
    pin_dns: bool
    audit_log: str | None
    use_gemini: bool
    gemini_model: str
    gemini_max_targets: int
    gemini_timeout: float
    use_katana: bool
    katana_headless: bool
    katana_duration: int


class ReconAgent:
    """Orchestrates the recon pipeline against one sanctioned target."""

    def __init__(
        self,
        target: str,
        *,
        username: str | None = None,
        password: str | None = None,
        scope_targets: list[str] | None = None,
        config: ReconConfig | None = None,
    ) -> None:
        self.target = target.rstrip("/") or "/"
        self.base_url = target.rstrip("/")
        self.username = username
        self.password = password
        cfg: ReconConfig = config or {}
        self.max_pages = int(cfg.get("max_pages", 60))
        self.max_depth = int(cfg.get("max_depth", 3))
        self.rps = float(cfg.get("rps", 5.0))
        self.timeout = float(cfg.get("timeout", 10.0))
        self.use_playwright = bool(cfg.get("use_playwright", True))
        self.max_reflection_probes = int(cfg.get("max_reflection_probes", 40))
        self.max_spa_routes = int(cfg.get("max_spa_routes", 15))
        self.pin_dns = bool(cfg.get("pin_dns", False))
        self.use_gemini = bool(cfg.get("use_gemini", False))
        self.gemini_model = str(cfg.get("gemini_model", "gemini-3.5-flash-lite"))
        self.gemini_max_targets = int(cfg.get("gemini_max_targets", 8))
        self.gemini_timeout = float(cfg.get("gemini_timeout", 20.0))
        self.use_katana = bool(cfg.get("use_katana", False))
        self.katana_headless = bool(cfg.get("katana_headless", False))
        self.katana_duration = int(cfg.get("katana_duration", 60))

        # Scope: the operator's declared target(s). The recon agent refuses
        # to add any host the operator did not sanction.
        self.guard = ScopeGuard(
            targets=scope_targets or [target],
            pin_dns=self.pin_dns,
            audit_log=cfg.get("audit_log"),
        )

    # ------------------------------------------------------------------ #
    def run(self) -> SiteMap:
        started = time.monotonic()
        notes: list[str] = []
        client = ScopedHttpClient(self.guard, rps=self.rps, timeout=self.timeout)

        # Phase 0 — reachability ------------------------------------------------
        probe = client.get(self.base_url + "/")
        if probe.error and probe.status is None:
            notes.append(f"target unreachable: {probe.error}")
            log.error("Target %s unreachable: %s", self.base_url, probe.error)

        # Phase 1 — fast httpx crawl -------------------------------------------
        crawler = HttpCrawler(client, self.base_url, max_pages=self.max_pages, max_depth=self.max_depth)
        crawler.crawl()
        endpoints: dict[tuple[str, str], Endpoint] = dict(crawler.endpoints)
        log.info("phase 1 (httpx crawl): %d pages, %d endpoints", crawler.pages_crawled, len(endpoints))

        # Phase 1b — optional Katana discovery ---------------------------------
        katana_used = False
        if self.use_katana:
            katana = KatanaCrawler(
                self.base_url, is_allowed=self.guard.is_allowed,
                max_depth=self.max_depth, max_pages=self.max_pages, rps=self.rps,
                duration_seconds=self.katana_duration, headless=self.katana_headless,
            )
            katana_result = katana.run()
            katana_used = katana_result.ran
            for key, ep in katana_result.endpoints.items():
                if key in endpoints:
                    endpoints[key].merge(ep)
                else:
                    endpoints[key] = ep
            notes.extend(katana_result.notes)
            log.info("phase 1b (katana): ran=%s, %d endpoints", katana_used, len(katana_result.endpoints))

        # Phase 2 — API surface guessing ----------------------------------------
        prober = ParamProber(client, self.base_url)
        guessed, guess_notes = prober.probe_api_surface()
        for key, ep in guessed.items():
            if key in endpoints:
                endpoints[key].merge(ep)
            else:
                endpoints[key] = ep
        notes.extend(guess_notes)
        log.info("phase 2 (api guesses): %d endpoints total", len(endpoints))

        # Phase 2b — optional AI-directed, still GET-only discovery ------------
        if self.use_gemini:
            planner = GeminiReconPlanner(
                model=self.gemini_model,
                timeout=self.gemini_timeout,
                max_targets=self.gemini_max_targets,
            )
            planned, planning_note = planner.plan(self.base_url, list(endpoints.values()))
            if planning_note:
                notes.append(planning_note)
            added = self._fetch_ai_targets(client, endpoints, planned, notes)
            if planned:
                notes.append(f"AI planning nominated {len(planned)} path(s); {added} safe GET target(s) fetched")

        # Phase 3 — auth --------------------------------------------------------
        auth = AuthDetector(client, self.base_url)
        auth.observe_headers(probe)
        auth.detect(endpoints)
        if self.username and self.password:
            authed = auth.authenticate(self.username, self.password)
            if authed:
                notes.append(f"auto-login succeeded via {auth.info.login_strategy}")
                # authenticated second pass over discovered links (bounded)
                auth_crawler = HttpCrawler(
                    client, self.base_url, max_pages=min(self.max_pages, 30), max_depth=2
                )
                auth_crawler.crawl()
                for key, ep in auth_crawler.endpoints.items():
                    if key in endpoints:
                        endpoints[key].merge(ep)
                    else:
                        ep.auth_required = True  # reachable only post-auth
                        endpoints[key] = ep
                protected = auth.probe_protected(endpoints)
                if protected:
                    notes.append(f"{len(protected)} protected endpoint(s) confirmed")
            else:
                notes.append("auto-login failed — credentials rejected or no login found")
        elif self.username or self.password:
            notes.append("incomplete credentials (need both --username and --password) — auth skipped")
        else:
            notes.append("no credentials supplied — authenticated surface not crawled")

        # Phase 4 — Playwright pass --------------------------------------------
        browser_used = False
        if self.use_playwright:
            browser = BrowserCrawler(self.base_url, max_spa_routes=self.max_spa_routes)
            auth_cookies = self._export_cookies(client)
            ran = browser.run(
                self.guard.is_allowed,
                auth_cookies=auth_cookies,
                auth_token=client.jwt_token,
            )
            browser_used = ran
            if ran:
                for key, ep in browser.captured.items():
                    if key in endpoints:
                        endpoints[key].merge(ep)
                    else:
                        endpoints[key] = ep
                for token in browser.scan_jwt_cookies():
                    if not client.jwt_token:
                        client.jwt_token = token
                        claims = decode_jwt(token)
                        if claims and not auth.info.jwt_sample_claims:
                            auth.info.jwt_sample_claims = claims
                        auth.info.token_type = "jwt"
                        auth.info.token_storage = "localStorage"
                        notes.append("JWT found in browser localStorage (unauthenticated surface)")
                for key, value in browser.local_storage.items():
                    low = key.lower()
                    if any(h in low for h in ("token", "jwt", "auth")) and not auth.info.token_storage:
                        auth.info.token_storage = "localStorage"
            notes.extend(browser.errors)
            log.info("phase 4 (browser): ran=%s, %d captured endpoints", ran, len(browser.captured))
        else:
            notes.append("Playwright pass disabled by config")

        # Phase 5 — fingerprinting (aggregate from stored fingerprints) ----------
        tech = self._aggregate_tech(crawler, notes)

        # Phase 6 — reflection probing (bounded, GET-only, benign marker) --------
        reflected_count = 0
        probes = 0
        for (_m, _k), ep in endpoints.items():
            if probes >= self.max_reflection_probes:
                break
            has_params = any(p.location == "query" for p in ep.params) or ep.forms
            # form-only endpoints may never have been fetched yet (no status) —
            # the probe itself is a harmless GET, so probe those too
            no_status = not ep.status_codes
            if ep.method == "GET" and has_params and (
                no_status or ep.status_codes[0] < 400
            ):
                probes += 1
                before = {p.name for p in ep.params if p.reflected}
                prober.probe_reflection(ep)
                if no_status and ep.status_codes:
                    pass  # probe_reflection doesn't fetch the base endpoint; leave status empty
                after = {p.name for p in ep.params if p.reflected}
                if after - before:
                    reflected_count += 1
        if reflected_count:
            notes.append(f"{reflected_count} endpoint(s) reflect parameter values (XSS/SQLi candidates)")

        stats = {
            "pages_crawled": crawler.pages_crawled,
            "unique_urls_seen": len(crawler.seen_urls) + len(crawler.hash_routes),
            "requests_made": client.requests_made,
            "scope_blocked": client.scope_blocked + self.guard.counters["blocked"],
            "errors": client.errors,
            "duration_seconds": round(time.monotonic() - started, 2),
            "playwright_used": browser_used,
            "katana_used": katana_used,
            "authenticated_pass": auth.info.authenticated,
        }

        sitemap = SiteMap(
            target=self.target,
            base_url=self.base_url,
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            endpoints=sorted(endpoints.values(), key=lambda e: (e.url, e.method)),
            auth=auth.info,
            technologies=tech,
            stats=stats,  # type: ignore[arg-type]
            notes=notes,
        )
        client.close()
        return sitemap

    def _fetch_ai_targets(self, client, endpoints, planned, notes: list[str]) -> int:
        """Validate every model suggestion before issuing a bounded GET request."""
        added = 0
        seen: set[str] = set()
        for proposal in planned:
            path = proposal.path
            parsed = urlsplit(path)
            if (not path.startswith("/") or parsed.scheme or parsed.netloc or parsed.query or
                    parsed.fragment or ".." in parsed.path.split("/")):
                notes.append("AI suggestion rejected: unsafe or non-path target")
                continue
            url = urljoin(self.base_url + "/", path)
            if url in seen:
                continue
            seen.add(url)
            # The ScopeGuard is the final authority; model output is never trusted.
            if not self.guard.is_allowed(url):
                notes.append("AI suggestion rejected: outside declared scope")
                continue
            result = client.get(url)
            if result.error or result.status is None:
                continue
            ep = Endpoint(
                url=url, method="GET", status_codes=[result.status],
                content_type=result.content_type, discovered_via="ai_plan",
                notes=f"AI-directed path: {proposal.reason}" if proposal.reason else "AI-directed path",
            )
            key = normalize_key("GET", url)
            if key in endpoints:
                endpoints[key].merge(ep)
            else:
                endpoints[key] = ep
            added += 1
        return added

    # ------------------------------------------------------------------ #
    def _export_cookies(self, client: ScopedHttpClient) -> list[dict]:
        cookies = []
        try:
            jar = client._client.cookies.jar  # noqa: SLF001 - deliberate internal use
            host = self.base_url.split("//", 1)[-1]
            for c in jar:
                cookies.append({
                    "name": c.name, "value": c.value or "",
                    "domain": c.domain or host, "path": c.path or "/",
                })
        except Exception:
            pass
        return cookies

    def _aggregate_tech(self, crawler: HttpCrawler, notes: list[str]) -> list[TechHint]:
        hints: list[TechHint] = list(crawler.tech_hints)  # per-response signature hits
        for kind, name, evidence in crawler.fingerprints:
            if kind == "cookie":
                hints.append(TechHint(name=f"cookie: {name}", category="cookie", source="cookie",
                                      evidence=evidence))
        if crawler.jwt_hits:
            claims = decode_jwt(crawler.jwt_hits[0])
            hints.append(TechHint(name="JWT tokens in responses", category="app", source="body",
                                  evidence=f"{len(crawler.jwt_hits)} token(s)" +
                                           (f"; claims: {sorted(claims)[:6]}" if claims else "")))
        notes.append(f"{len(crawler.session_cookies)} distinct cookie(s) observed")
        return merge_hints(hints)


# ---------------------------------------------------------------------- #
# LangGraph node (spec §10: orchestration via LangGraph)
# ---------------------------------------------------------------------- #
class ReconState(TypedDict, total=False):
    target: str
    username: str | None
    password: str | None
    scope_targets: list[str] | None
    recon_config: ReconConfig
    sitemap: dict[str, Any]
    recon_done: bool


def recon_node(state: ReconState) -> dict[str, Any]:
    """LangGraph-compatible node: run recon, return site map into shared state."""
    target = state["target"]
    agent = ReconAgent(
        target,
        username=state.get("username"),
        password=state.get("password"),
        scope_targets=state.get("scope_targets"),
        config=state.get("recon_config"),
    )
    sitemap = agent.run()
    return {"sitemap": sitemap.model_dump(), "recon_done": True}


if __name__ == "__main__":  # pragma: no cover - delegates to CLI
    import sys
    from run_recon import main

    sys.exit(main())
