"""Pydantic models for GateCounsel's structured site map (spec §6.1 output contract).

The site map is the interface between the Recon Agent and the Planner Agent:
every endpoint is annotated with parameters, auth requirements and technology
hints so the Planner can route (endpoint, vulnerability_class) pairs to the
matching expert agent.
"""

from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

ParamLocation = Literal["query", "body", "header", "cookie", "path"]
DiscoveredVia = Literal[
    "seed", "link", "form", "js", "guess", "api_spec", "robots",
    "sitemap_xml", "network", "redirect", "auth_probe", "ai_plan", "katana",
]


class Param(BaseModel):
    """A single parameter attached to an endpoint."""

    name: str
    location: ParamLocation = "query"
    type_hint: Literal["string", "number", "boolean", "json", "unknown"] = "unknown"
    examples: list[str] = Field(default_factory=list)
    reflected: bool = False  # value echoed back in the response (XSS/SQLi hint)
    notes: Optional[str] = None


class FormInfo(BaseModel):
    """An HTML form discovered on a page."""

    action: str
    method: str = "GET"
    fields: list[str] = Field(default_factory=list)
    field_types: dict[str, str] = Field(default_factory=dict)
    hidden_values: dict[str, str] = Field(default_factory=dict)  # CSRF tokens etc. (snapshot)
    page_url: str | None = None  # page the form was found on — re-fetched for fresh CSRF tokens
    has_password_field: bool = False
    likely_login: bool = False


class Endpoint(BaseModel):
    """One discovered API/page endpoint with recon annotations."""

    url: str
    method: str = "GET"
    params: list[Param] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    content_type: Optional[str] = None
    auth_required: Optional[bool] = None  # None = unknown
    reflected_params: list[str] = Field(default_factory=list)
    forms: list[FormInfo] = Field(default_factory=list)
    discovered_via: DiscoveredVia = "link"
    response_snippet: Optional[str] = None  # short body snippet (error text, JSON keys...)
    notes: Optional[str] = None

    def merge(self, other: "Endpoint") -> None:
        """Merge duplicate observations of the same endpoint."""
        for code in other.status_codes:
            if code not in self.status_codes:
                self.status_codes.append(code)
        for p in other.params:
            self._upsert_param(p)
        for form in other.forms:
            if form.model_dump() not in [f.model_dump() for f in self.forms]:
                self.forms.append(form)
        for rp in other.reflected_params:
            if rp not in self.reflected_params:
                self.reflected_params.append(rp)
        if other.auth_required and not self.auth_required:
            self.auth_required = True
        if other.response_snippet and not self.response_snippet:
            self.response_snippet = other.response_snippet
        if other.notes:
            self.notes = f"{self.notes or ''}; {other.notes}".strip("; ")

    def _upsert_param(self, p: Param) -> None:
        for existing in self.params:
            if existing.name == p.name and existing.location == p.location:
                for ex in p.examples:
                    if ex not in existing.examples and len(existing.examples) < 5:
                        existing.examples.append(ex)
                if p.reflected:
                    existing.reflected = True
                if p.type_hint != "unknown" and existing.type_hint == "unknown":
                    existing.type_hint = p.type_hint
                return
        self.params.append(p)


class AuthInfo(BaseModel):
    """Authentication surface of the target (spec: 'detect auth flows')."""

    login_candidates: list[str] = Field(default_factory=list)
    login_forms: list[FormInfo] = Field(default_factory=list)
    token_type: Optional[Literal["jwt", "session_cookie", "basic", "none"]] = None
    token_storage: Optional[str] = None  # response_body | set_cookie | localStorage | authorization_header
    authenticated: bool = False
    login_strategy: Optional[str] = None  # how auto-login succeeded, if it did
    session_cookie_names: list[str] = Field(default_factory=list)
    jwt_sample_claims: Optional[dict[str, Any]] = None
    protected_endpoints: list[str] = Field(default_factory=list)


class TechHint(BaseModel):
    """One detected technology (framework / server / library / app)."""

    name: str
    category: str  # framework | server | language | cms | library | cookie | app | security-header
    source: str  # header | body | cookie
    evidence: str


class CrawlStats(BaseModel):
    pages_crawled: int = 0
    unique_urls_seen: int = 0
    requests_made: int = 0
    scope_blocked: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    playwright_used: bool = False
    katana_used: bool = False
    authenticated_pass: bool = False


class SiteMap(BaseModel):
    """Full recon output for one target. Consumed by the Planner Agent."""

    target: str
    base_url: str
    generated_at: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    auth: AuthInfo = Field(default_factory=AuthInfo)
    technologies: list[TechHint] = Field(default_factory=list)
    stats: CrawlStats = Field(default_factory=CrawlStats)
    notes: list[str] = Field(default_factory=list)

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)
