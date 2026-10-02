"""Technology fingerprinting — headers + body patterns (no heavy deps).

Kept deliberately small and auditable: every signature is an explicit rule
with a human-readable evidence string, so the Planner Agent (and the report)
can always show *why* a technology was inferred.
"""

from __future__ import annotations

import re

from agents.recon.core.models import TechHint

# (name, category, source, compiled regex, where the regex applies)
_BODY_SIGNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("OWASP Juice Shop", "app", re.compile(r"OWASP[\s-]?Juice[\s-]?Shop", re.I)),
    ("DVWA", "app", re.compile(r"Damn Vulnerable Web Application|DVWA", re.I)),
    ("WebGoat", "app", re.compile(r"WebGoat", re.I)),
    ("Angular", "framework", re.compile(r'ng-version="([^"]+)"')),
    ("AngularJS", "framework", re.compile(r"\bng-app\b|\bng-controller\b|angular(?:\.min)?\.js", re.I)),
    ("React", "framework", re.compile(r"__NEXT_DATA__|data-reactroot|react(?:-dom)?\.production\.min\.js", re.I)),
    ("Next.js", "framework", re.compile(r"__NEXT_DATA__|/_next/static", re.I)),
    ("Vue.js", "framework", re.compile(r"data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.min)?\.js", re.I)),
    ("Nuxt", "framework", re.compile(r"/_nuxt/", re.I)),
    ("Svelte", "framework", re.compile(r"svelte-[0-9a-z]{6}", re.I)),
    ("jQuery", "library", re.compile(r"jquery[.\-]?\d*\.(?:min\.)?js", re.I)),
    ("Bootstrap", "library", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I)),
    ("Swagger UI", "docs", re.compile(r"swagger-ui|swagger-initializer", re.I)),
    ("GraphiQL", "docs", re.compile(r"graphiql", re.I)),
    ("WordPress", "cms", re.compile(r"wp-content|wp-includes", re.I)),
    ("Drupal", "cms", re.compile(r"drupal|sites/default/files", re.I)),
    ("Joomla", "cms", re.compile(r"/media/jui/|Joomla!", re.I)),
    ("ASP.NET WebForms", "framework", re.compile(r"__VIEWSTATE|__doPostBack")),
    ("ASP.NET", "framework", re.compile(r"asp-net|aspnet_client", re.I)),
    ("PHP", "language", re.compile(r"\.php(?:[?'\"]|$)")),
    ("Java/JSP", "language", re.compile(r"\.jsp(?:[?'\"]|$)|JSESSIONID", re.I)),
    ("Django", "framework", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("Laravel", "framework", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
    ("GraphQL", "api", re.compile(r"graphql", re.I)),
    ("Font Awesome", "library", re.compile(r"font-?awesome", re.I)),
]

_HEADER_SIGNS: dict[str, dict[str, tuple[str, str]]] = {
    # header -> (value-substring -> (tech name, category))
    "server": {
        "nginx": ("nginx", "server"),
        "apache": ("Apache", "server"),
        "microsoft-iis": ("Microsoft IIS", "server"),
        "litespeed": ("LiteSpeed", "server"),
        "caddy": ("Caddy", "server"),
        "gunicorn": ("gunicorn (Python WSGI)", "server"),
        "werkzeug": ("Werkzeug (Flask dev)", "server"),
        "uvicorn": ("uvicorn (ASGI)", "server"),
        "kestrel": ("Kestrel (ASP.NET)", "server"),
    },
    "x-powered-by": {
        "express": ("Express (Node.js)", "framework"),
        "php": ("PHP", "language"),
        "asp.net": ("ASP.NET", "framework"),
        "next.js": ("Next.js", "framework"),
        "servlet": ("Java Servlets", "language"),
    },
    "set-cookie": {
        "phpsessid": ("PHP", "language"),
        "jsessionid": ("Java", "language"),
        "connect.sid": ("Express session", "framework"),
        "laravel_session": ("Laravel", "framework"),
        "csrftoken": ("Django", "framework"),
        "asp.net_sessionid": ("ASP.NET", "framework"),
    },
}


def fingerprint(headers: dict[str, str], body: str) -> list[TechHint]:
    """Return tech hints found in one response's headers and/or body."""
    hints: list[TechHint] = []

    for header, rules in _HEADER_SIGNS.items():
        value = headers.get(header, "")
        low = value.lower()
        for needle, (name, category) in rules.items():
            if needle in low:
                hints.append(TechHint(name=name, category=category, source="header",
                                      evidence=f"{header}: {value[:80]}"))

    probe = body[:120_000]  # cap regex work on huge pages
    for name, category, pattern in _BODY_SIGNS:
        m = pattern.search(probe)
        if m:
            evidence = m.group(0)[:60]
            if m.groups() and m.group(1):
                evidence = f"{m.group(0)[:40]} (v={m.group(1)[:20]})"
            hints.append(TechHint(name=name, category=category, source="body", evidence=evidence))

    csp = headers.get("content-security-policy")
    if csp:
        hints.append(TechHint(name="Content-Security-Policy", category="security-header",
                              source="header", evidence=csp[:80]))
    return hints


def merge_hints(hints: list[TechHint]) -> list[TechHint]:
    """Dedupe by (name, category), keeping the first (most informative) evidence."""
    seen: dict[tuple[str, str], TechHint] = {}
    for h in hints:
        key = (h.name, h.category)
        if key not in seen:
            seen[key] = h
    return list(seen.values())
