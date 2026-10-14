"""Non-destructive parameter probing + API surface discovery.

Reflection detection answers one question for the Planner: "if I put a
marker value in this parameter, does the app echo it back?" — the primary
signal for routing XSS/SQLi candidates. The marker is an innocuous random
string plus a few context characters; no exploit payloads are used at
recon stage.

API guessing is GET-only and includes OpenAPI/Swagger spec parsing, which
converts a lucky guess into a complete API inventory.
"""

from __future__ import annotations

import logging
import random
import re
import string
from urllib.parse import urljoin, urlsplit, parse_qsl, urlencode

from agents.recon.core.http_client import ScopedHttpClient
from agents.recon.crawlers.crawler import normalize_key
from agents.recon.core.models import Endpoint, Param

log = logging.getLogger("gatecounsel.probe")

MARKER_CHARS = string.ascii_lowercase + string.digits
MARKER_SUFFIX = '<>"\'()'  # context chars: quote/angle/paren reflection context probe
REFLECTION_CONTEXT = re.compile(
    r"""hbx(?P<core>[a-z0-9]{10})(?P<after>.{0,12})""", re.S
)

_TYPE_MAP = {"integer": "number", "number": "number", "boolean": "boolean",
             "string": "string", "array": "json", "object": "json"}


def _normalize_type(raw: str | None) -> str:
    return _TYPE_MAP.get((raw or "").lower(), "unknown")


def make_marker() -> str:
    core = "".join(random.choice(MARKER_CHARS) for _ in range(10))
    return f"hbx{core}"


class ParamProber:
    """Detects reflected parameters and guesses the undocumented API surface."""

    def __init__(self, client: ScopedHttpClient, base_url: str):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.marker = make_marker()

    # ------------------------------------------------------------------ #
    # Reflection detection
    # ------------------------------------------------------------------ #
    def probe_reflection(self, endpoint: Endpoint, *, max_params: int = 12) -> dict[str, str]:
        """Send each query param alone with the marker; return {param: context}.

        Returns a mapping param-name -> reflection description:
          'raw'          -> marker incl. special chars echoed unescaped
          'encoded'      -> alphanumeric core echoed (special chars escaped/dropped)
        """
        results: dict[str, str] = {}
        parts = urlsplit(endpoint.url)
        base = f"{parts.scheme}://{parts.netloc}{parts.path}"
        candidates = [p for p in endpoint.params if p.location == "query"]
        if not candidates and endpoint.method == "GET" and endpoint.forms:
            candidates = [Param(name=f, location="query") for f in endpoint.forms[0].fields]
        if not candidates:
            return results

        for param in candidates[:max_params]:
            test_url = f"{base}?{urlencode({param.name: self.marker + MARKER_SUFFIX})}"
            result = self.client.get(test_url)
            if result.error or result.status is None:
                continue
            body = result.text
            m = REFLECTION_CONTEXT.search(body)
            if m:
                param.reflected = True
                if param.name not in endpoint.reflected_params:
                    endpoint.reflected_params.append(param.name)
                results[param.name] = "raw" if m.group("core") in body and "<>" in body else "encoded"
                endpoint.notes = f"{endpoint.notes or ''}; reflection={results[param.name]}".strip("; ")
            elif self.marker in body:
                param.reflected = True
                if param.name not in endpoint.reflected_params:
                    endpoint.reflected_params.append(param.name)
                results[param.name] = "encoded"
        return results

    # ------------------------------------------------------------------ #
    # API surface guessing (GET-only, includes spec parsing)
    # ------------------------------------------------------------------ #
    GUESS_PATHS = [
        "/robots.txt", "/sitemap.xml",
        "/openapi.json", "/swagger.json", "/api-docs", "/swagger/v1/swagger.json",
        "/api", "/api/", "/api/v1", "/api/v2", "/rest", "/graphql",
        "/api/users", "/api/items", "/api/products", "/api/config", "/api/status",
        "/.well-known/security.txt", "/version", "/health",
    ]

    def probe_api_surface(self) -> tuple[dict[tuple[str, str], Endpoint], list[str]]:
        """GET the common discovery paths. Returns (endpoints, notes)."""
        found: dict[tuple[str, str], Endpoint] = {}
        notes: list[str] = []

        for path in self.GUESS_PATHS:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            result = self.client.get(url)
            if result.error or result.status is None:
                continue
            ep = Endpoint(
                url=url, method="GET", status_codes=[result.status],
                content_type=result.content_type, discovered_via="guess",
            )
            key = normalize_key("GET", url)
            if key in found:
                # keep the richer entry (e.g. spec-parsed with params) and fold in status
                found[key].merge(ep)
                if result.status < 300:
                    notes.append(f"{path} -> {result.status} ({result.content_type or '?'})")
                continue
            found[key] = ep
            if result.status < 300:
                notes.append(f"{path} -> {result.status} ({result.content_type or '?'})")
            if result.status == 405:  # exists, wrong verb (e.g. GraphQL wants POST)
                ep.notes = "exists; answered 405 Method Not Allowed for GET"
                notes.append(f"{path} exists (405 for GET)")

            ctype = result.content_type or ""
            if result.status < 300 and ("json" in ctype or path.endswith((".json",))):
                spec_eps = self._parse_openapi(url, result.text)
                if spec_eps:
                    notes.append(f"OpenAPI/Swagger spec parsed at {path}: {len(spec_eps)} paths")
                    for sep in spec_eps:
                        skey = normalize_key(sep.method, sep.url)
                        if skey in found:
                            found[skey].merge(sep)
                        else:
                            found[skey] = sep
            elif result.status < 300 and path == "/robots.txt":
                robots_eps = self._parse_robots(result.text)
                for rep in robots_eps:
                    rkey = normalize_key("GET", rep)
                    if rkey not in found:
                        found[rkey] = Endpoint(url=rep, method="GET", discovered_via="robots")
                if robots_eps:
                    notes.append(f"robots.txt disclosed {len(robots_eps)} path(s)")
            elif result.status < 300 and path == "/sitemap.xml":
                sm_eps = self._parse_sitemap(result.text)
                for rep in sm_eps:
                    skey2 = normalize_key("GET", rep)
                    if skey2 not in found:
                        found[skey2] = Endpoint(url=rep, method="GET", discovered_via="sitemap_xml")
                if sm_eps:
                    notes.append(f"sitemap.xml disclosed {len(sm_eps)} URL(s)")

        return found, notes

    # ------------------------------------------------------------------ #
    def _parse_openapi(self, spec_url: str, text: str) -> list[Endpoint]:
        import json as _json
        try:
            spec = _json.loads(text)
        except ValueError:
            return []
        if not isinstance(spec, dict) or "paths" not in spec:
            return []
        base = spec.get("servers", [{}])
        root = (base[0].get("url") if base and isinstance(base[0], dict) else "") or ""
        root = urljoin(spec_url, root) if root else self.base_url

        out: list[Endpoint] = []
        for path, methods in spec["paths"].items():
            if not isinstance(methods, dict):
                continue
            for verb, op in methods.items():
                if verb.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                url = urljoin(root + "/", str(path).lstrip("/"))
                params: list[Param] = []
                raw_params = op.get("parameters") if isinstance(op, dict) else None
                for p in raw_params or []:
                    try:
                        loc = p.get("in", "query")
                        if loc in ("query", "path", "header", "cookie"):
                            params.append(Param(name=p.get("name", "?"), location=loc,
                                                type_hint=_normalize_type(p.get("schema", {}).get("type"))))  # type: ignore[arg-type]
                    except AttributeError:
                        continue
                if isinstance(op, dict) and isinstance(op.get("requestBody"), dict):
                    content = op["requestBody"].get("content", {})
                    schema = content.get("application/json", {}).get("schema", {})
                    for prop in (schema.get("properties") or {}):
                        params.append(Param(name=prop, location="body", type_hint="string"))
                ep = Endpoint(url=url, method=verb.upper(), params=params,
                              discovered_via="api_spec")
                summary = op.get("summary") or op.get("description") if isinstance(op, dict) else None
                if summary:
                    ep.response_snippet = str(summary)[:200]
                out.append(ep)
        return out

    def _parse_robots(self, text: str) -> list[str]:
        urls: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                value = line.split(":", 1)[1].strip()
                if not value or value == "/":
                    continue
                if value.startswith("http"):
                    urls.append(value)
                else:
                    urls.append(urljoin(self.base_url + "/", value.lstrip("/")))
        return [u for u in urls if not u.lower().endswith((".xml",))][:20]

    def _parse_sitemap(self, text: str) -> list[str]:
        return re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", text, re.I)[:50]
