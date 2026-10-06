"""Deterministic rule engine for the Hackbot Planner (spec §6.2 core).

Turns recon signals from a SiteMap into scored attack-plan tasks:

  scoring:   priority(0-100) = round(100 x impact(class) x likelihood)
  bands:     >=80 critical | >=60 high | >=40 medium | else low
  risk tier: safe_probe = benign GET-only verification
             needs_review = mutating method OR injection / SSRF / auth bypass

Every task carries its evidence (`signals`) so any downstream agent — or a
human reviewer — can audit WHY it was planned. No LLM involved at this layer.
"""

from __future__ import annotations

import re

from agents.planner.models.plan_models import Band, PlanTask, RiskTier, VulnClass, band_from_priority
from agents.recon.core.models import Endpoint, SiteMap

# --- signal tables ---------------------------------------------------------- #
# Parameter names that historically feed SQL queries.
SQLI_PARAM_HINTS = {
    "id", "uid", "user", "userid", "user_id", "username", "email", "product",
    "productid", "product_id", "item", "itemid", "item_id", "category", "cat",
    "page", "p", "order", "orderby", "order_by", "sort", "search", "q", "query",
    "s", "name", "filter", "keyword", "kw", "tag", "ref", "no", "num", "code",
    "view", "type", "lang", "dir",
}
# Parameter names that look like object references (IDOR candidates).
ID_PARAM_HINTS = {
    "id", "uid", "uuid", "guid", "user", "userid", "user_id", "account",
    "account_id", "accountid", "order", "order_id", "orderid", "invoice",
    "invoice_id", "doc", "doc_id", "document_id", "profile", "profile_id",
    "post", "post_id", "comment", "comment_id", "record", "record_id", "ref",
}
# Parameter names that commonly carry redirect destinations.
OPEN_REDIRECT_HINTS = {
    "redirect", "redirect_uri", "redirect_url", "redirecturi", "next", "return",
    "return_url", "returnurl", "return_to", "returnto", "goto", "continue",
    "rurl", "forward", "back", "destination_url", "url_return", "target_url",
}
# Parameter names that commonly carry server-fetched URLs (SSRF candidates).
# (deliberately disjoint from OPEN_REDIRECT_HINTS; "callback" excluded — it is
# usually a JSONP function name, not a URL)
SSRF_PARAM_HINTS = {
    "url", "uri", "dest", "destination", "target", "host", "domain", "site",
    "fetch", "proxy", "load", "src", "source", "file", "document", "feed",
    "image", "img", "link", "server", "remote", "share", "webhook", "import",
}
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SENSITIVE_CLAIMS = {"role", "admin", "is_admin", "scope", "scopes", "permissions", "priv", "group", "groups"}
PII_CLAIMS = {"email", "password", "password_hash", "hash", "ssn", "phone", "address"}

# --- class metadata --------------------------------------------------------- #
CLASS_IMPACT: dict[VulnClass, float] = {
    "sqli": 0.95,
    "xss_reflected": 0.55,
    "jwt_misconfig": 0.90,
    "auth_bypass": 0.90,
    "idor": 0.80,
    "ssrf": 0.85,
    "open_redirect": 0.50,
}
CLASS_EXPERT: dict[VulnClass, str] = {
    "sqli": "sqli_expert",
    "xss_reflected": "xss_expert",
    "jwt_misconfig": "jwt_expert",
    "auth_bypass": "auth_bypass_expert",
    "idor": "idor_expert",
    "ssrf": "ssrf_expert",
    "open_redirect": "open_redirect_expert",
}
# Injection and side-effecting classes are never auto-run as "benign" probes.
CLASS_RISK: dict[VulnClass, RiskTier] = {
    "sqli": "needs_review",
    "xss_reflected": "safe_probe",
    "jwt_misconfig": "safe_probe",
    "auth_bypass": "needs_review",
    "idor": "safe_probe",
    "ssrf": "needs_review",
    "open_redirect": "safe_probe",
}

LIKELIHOOD_FLOOR = 0.30
LIKELIHOOD_CAP = 0.95


def _numeric_example(param) -> bool:
    return any(ex.isdigit() for ex in param.examples)


def _uuid_example(param) -> bool:
    return any(UUID_RE.match(ex) for ex in param.examples)


class _TaskAccum:
    """Collects signals for one (vuln_class, method, url) triple."""

    def __init__(self, vuln_class: VulnClass, endpoint: Endpoint) -> None:
        self.vuln_class = vuln_class
        self.endpoint_url = endpoint.url
        self.method = endpoint.method
        self.target_params: list[str] = []
        self.signals: list[str] = []
        self.likelihood = LIKELIHOOD_FLOOR
        self.auth_required = bool(endpoint.auth_required)

    def add(self, param_name: str | None, signal: str, boost: float) -> None:
        if param_name and param_name not in self.target_params:
            self.target_params.append(param_name)
        if signal not in self.signals:
            self.signals.append(signal)
        self.likelihood = min(LIKELIHOOD_CAP, self.likelihood + boost)


class RuleEngine:
    """Deterministic SiteMap -> list[PlanTask] generator."""

    def generate(self, sitemap: SiteMap) -> list[PlanTask]:
        accums: dict[tuple[str, str, str], _TaskAccum] = {}
        self._tech_boosts(sitemap)
        for ep in sitemap.endpoints:
            self._endpoint_tasks(ep, accums)
        self._auth_tasks(sitemap, accums)
        return self._finalize(accums)

    # ---- per-endpoint rules ------------------------------------------------ #
    def _endpoint_tasks(self, ep: Endpoint, accums: dict) -> None:
        is_get = ep.method.upper() == "GET"
        reachable = bool(ep.status_codes) and min(ep.status_codes) < 400
        reach_boost = 0.05 if reachable else 0.0

        for param in ep.params:
            name_l = param.name.lower()
            reflected = param.reflected or param.name in ep.reflected_params
            hint = name_l in SQLI_PARAM_HINTS
            numeric = _numeric_example(param)

            # SQLi: need two independent cues so a lone "q" or "page" is not enough.
            if (hint, numeric, reflected).count(True) >= 2:
                acc = self._accum(accums, "sqli", ep)
                if hint:
                    acc.add(param.name, f"param '{param.name}' matches SQLi-prone name", 0.15)
                if numeric:
                    examples = ", ".join(param.examples[:3])
                    acc.add(param.name, f"numeric example values: {examples}", 0.20)
                if reflected:
                    acc.add(param.name, "value reflected in response (error-based probing viable)", 0.25)
                if reach_boost:
                    acc.add(None, "endpoint confirmed reachable", reach_boost)

            if reflected and is_get:
                acc = self._accum(accums, "xss_reflected", ep)
                acc.add(param.name, f"value of '{param.name}' echoed in response body", 0.30)
                if reach_boost:
                    acc.add(None, "endpoint confirmed reachable", reach_boost)

            id_like = name_l in ID_PARAM_HINTS or name_l.endswith("_id")
            id_evidence = numeric or _uuid_example(param) or param.type_hint == "number"
            if id_like and id_evidence:
                acc = self._accum(accums, "idor", ep)
                acc.add(param.name, f"'{param.name}' looks like a direct object reference", 0.20)
                if numeric:
                    acc.add(param.name, "sequential numeric values observed", 0.20)
                if _uuid_example(param):
                    acc.add(param.name, "UUID values observed (enumeration harder, try leaks)", 0.10)
                if ep.auth_required:
                    acc.add(None, "endpoint requires authentication (privileged object access)", 0.15)
                if reach_boost:
                    acc.add(None, "endpoint confirmed reachable", reach_boost)

            if name_l in OPEN_REDIRECT_HINTS:
                acc = self._accum(accums, "open_redirect", ep)
                acc.add(param.name, f"'{param.name}' carries a redirect destination", 0.30)
                if reach_boost:
                    acc.add(None, "endpoint confirmed reachable", reach_boost)
            elif name_l in SSRF_PARAM_HINTS:
                acc = self._accum(accums, "ssrf", ep)
                acc.add(param.name, f"'{param.name}' is fetched by the server (SSRF candidate)", 0.30)
                if reach_boost:
                    acc.add(None, "endpoint confirmed reachable", reach_boost)

    # ---- auth-wide rules ---------------------------------------------------- #
    def _auth_tasks(self, sitemap: SiteMap, accums: dict) -> None:
        auth = sitemap.auth

        if auth.token_type == "jwt":
            target_url = sitemap.base_url + "/"
            for candidate in auth.login_candidates:
                parts = candidate.split(" ", 1)
                if len(parts) == 2 and parts[0].upper() in (
                        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    target_url = parts[1]
                else:
                    target_url = candidate
                break
            acc = self._accum(
                accums, "jwt_misconfig",
                Endpoint(url=target_url, method="GET"),
            )
            claims = auth.jwt_sample_claims
            if claims:
                acc.add(None, "JWT sample decoded from target", 0.10)
                sensitive = sorted(SENSITIVE_CLAIMS.intersection(claims))
                if sensitive:
                    acc.add(None, f"privileged claims exposed: {', '.join(sensitive)}", 0.20)
                pii = sorted(PII_CLAIMS.intersection(claims))
                if pii:
                    acc.add(None, f"PII claims exposed: {', '.join(pii)}", 0.15)
                if "exp" not in claims:
                    acc.add(None, "no 'exp' claim — tokens may never expire", 0.25)
            else:
                acc.add(None, "JWT issued by target (claims not decoded)", 0.10)
            if auth.token_storage == "localStorage":
                acc.add(None, "token stored in localStorage (stealable via XSS)", 0.15)

        probed = set(auth.protected_endpoints)
        required = {ep.url for ep in sitemap.endpoints if ep.auth_required}
        for url in sorted(probed | required):
            acc = self._accum(
                accums, "auth_bypass",
                Endpoint(url=url, method="GET", auth_required=True),
            )
            if url in probed:
                acc.add(None, "endpoint returned 401/403 anonymously (auth boundary)", 0.20)
            else:
                acc.add(None, "endpoint flagged auth_required by recon", 0.15)
            if auth.authenticated:
                acc.add(None, "operator session available for authenticated comparison", 0.15)

    def _tech_boosts(self, sitemap: SiteMap) -> None:
        return None

    def _accum(self, accums: dict, vuln_class: VulnClass, ep: Endpoint) -> _TaskAccum:
        key = (vuln_class, ep.method, ep.url)
        if key not in accums:
            accums[key] = _TaskAccum(vuln_class, ep)
        return accums[key]

    def _finalize(self, accums: dict) -> list[PlanTask]:
        tasks: list[PlanTask] = []
        for (vuln_class, method, _url), acc in accums.items():
            likelihood = max(LIKELIHOOD_FLOOR, min(LIKELIHOOD_CAP, acc.likelihood))
            priority = round(100 * CLASS_IMPACT[vuln_class] * likelihood)
            priority = max(1, min(100, priority))
            risk: RiskTier = CLASS_RISK[vuln_class]
            if method.upper() != "GET":
                risk = "needs_review"
            band: Band = band_from_priority(priority)
            tasks.append(PlanTask(
                id="T-000",
                vuln_class=vuln_class,
                expert_route=CLASS_EXPERT[vuln_class],
                endpoint_url=acc.endpoint_url,
                method=method,
                target_params=acc.target_params,
                signals=acc.signals,
                rationale=self._rationale(vuln_class, acc),
                priority=priority,
                band=band,
                risk_tier=risk,
            ))
        tasks.sort(key=lambda t: (-t.priority, t.vuln_class, t.endpoint_url))
        for i, task in enumerate(tasks, start=1):
            task.id = f"T-{i:03d}"
        return tasks

    @staticmethod
    def _rationale(vuln_class: VulnClass, acc: _TaskAccum) -> str:
        params = ", ".join(acc.target_params) if acc.target_params else "endpoint"
        leaders = {
            "sqli": f"Probe {acc.method} {params} for SQL injection",
            "xss_reflected": f"Test reflected XSS in {params}",
            "jwt_misconfig": "Verify JWT configuration hardening",
            "auth_bypass": f"Verify access control on {acc.endpoint_url}",
            "idor": f"Enumerate object references in {params}",
            "ssrf": f"Test server-side fetch via {params}",
            "open_redirect": f"Test unvalidated redirect via {params}",
        }
        return leaders.get(vuln_class, f"Assess {vuln_class} on {params}")
