"""Authentication-flow detection and operator-driven auto-login.

Recon phase responsibilities (spec §6.1):
  * detect authentication flows (login pages, JSON login APIs, session
    tokens, JWT usage) and which endpoints require authentication;
  * if the operator supplies credentials (--username/--password), perform a
    *generic* login attempt (form-encoded or JSON) and crawl the protected
    surface as well.

Auto-login only happens when the operator explicitly passes credentials —
it is never attempted otherwise. No credential brute-forcing happens here;
that belongs to the Auth/JWT expert agent, not to recon.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from urllib.parse import urljoin, urlsplit

from agents.crawler import RE_JWT
from agents.http_client import FetchResult, ScopedHttpClient
from agents.models import AuthInfo, Endpoint, FormInfo

log = logging.getLogger("hackbot.auth")

LOGIN_URL_HINTS = re.compile(r"(login|signin|sign-in|auth|session|authenticate)", re.I)
USERNAME_FIELDS = ["email", "username", "user", "login", "mail"]
PASSWORD_FIELDS = ["password", "pass", "pwd"]
SUCCESS_TOKEN_KEYS = ["token", "authentication", "jwt", "access_token", "id_token", "auth"]
FAIL_HINTS = re.compile(r"(invalid|incorrect|wrong|failed|unauthorized|bad credentials)", re.I)


def decode_jwt(token: str) -> dict | None:
    """Decode a JWT's payload WITHOUT verifying the signature (recon intel only)."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        return claims if isinstance(claims, dict) else None
    except Exception:
        return None


class AuthDetector:
    """Detects login surfaces; performs one operator-authorized login."""

    def __init__(self, client: ScopedHttpClient, base_url: str):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.info = AuthInfo()

    # ------------------------------------------------------------------ #
    # Detection — called after the first crawl pass with its findings
    # ------------------------------------------------------------------ #
    def detect(self, endpoints: dict[tuple[str, str], Endpoint]) -> AuthInfo:
        for (method, _key), ep in endpoints.items():
            path = urlsplit(ep.url).path.lower()
            if LOGIN_URL_HINTS.search(path) or any(f.likely_login for f in ep.forms):
                candidate = f"{method} {ep.url}"
                if candidate not in self.info.login_candidates:
                    self.info.login_candidates.append(candidate)
            for form in ep.forms:
                if form.likely_login and form not in self.info.login_forms:
                    self.info.login_forms.append(form)
            for cookie_name in ("session", "sessionid", "connect.sid", "jsessionid", "phpsessid"):
                if cookie_name in str(ep.response_snippet or "").lower():
                    self._add_cookie_name(cookie_name)
        return self.info

    def observe_headers(self, result: FetchResult) -> None:
        """Feed response headers/cookies from any fetch into auth intel."""
        set_cookie = result.headers.get("set-cookie", "")
        if set_cookie:
            name = set_cookie.split("=", 1)[0].strip()
            self._add_cookie_name(name)
        auth_header = result.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer") or RE_JWT.search(auth_header):
            self.info.token_type = "jwt"
            self.info.token_storage = "authorization_header"

    def _add_cookie_name(self, name: str) -> None:
        if name and name.lower() not in [c.lower() for c in self.info.session_cookie_names]:
            self.info.session_cookie_names.append(name)
        if name.lower() in ("session", "sessionid", "connect.sid", "jsessionid"):
            if self.info.token_type not in ("jwt",):
                self.info.token_type = "session_cookie"

    # ------------------------------------------------------------------ #
    # Auto-login (operator-supplied credentials only)
    # ------------------------------------------------------------------ #
    def authenticate(self, username: str, password: str) -> bool:
        """Try generic login strategies; store token/session on success.

        Strategy order: discovered login FORMS first (we know their exact
        fields, including CSRF hidden inputs, which are re-fetched fresh
        right before submitting), then JSON POST variants, then common
        login paths. Form and JSON attempts on the same URL are deduped
        per-kind so both get a chance (e.g. DVWA: form works, JSON won't).
        """
        attempts: list[tuple[str, str, FormInfo | None]] = []

        # 1) discovered login forms (most precise)
        for form in self.info.login_forms:
            if form.method.upper() == "POST":
                attempts.append(("form", form.action, form))

        # 2) JSON POST to detected login endpoints/pages
        for candidate in self.info.login_candidates:
            method, url = candidate.split(" ", 1)
            if method != "POST":
                attempts.append(("json", url, None))

        # 3) common login paths even if not discovered
        for path in ("/rest/user/login", "/api/login", "/api/auth/login", "/auth/login",
                     "/login", "/signin", "/api/session", "/api-token-auth/"):
            attempts.append(("json", urljoin(self.base_url + "/", path.lstrip("/")), None))

        seen: set[tuple[str, str]] = set()
        for kind, url, form in attempts:
            key = (kind, url)
            if key in seen:
                continue
            seen.add(key)
            pre_cookies = set(self.client.cookie_names)

            if kind == "json":
                for field_map in self._json_field_variants(username, password):
                    result = self.client.post(url, json=field_map)
                    self.observe_headers(result)
                    if self._evaluate(result, url, pre_cookies=pre_cookies,
                                      strategy=f"json POST {url} fields={list(field_map)}"):
                        return True
            else:  # form
                field_map = self._form_field_map(form, username, password)
                result = self.client.post(url, data=field_map)
                self.observe_headers(result)
                if self._evaluate(result, url, pre_cookies=pre_cookies, form_kind=True,
                                  strategy=f"form POST {url} fields={sorted(field_map)}"):
                    return True
        return False

    def _json_field_variants(self, username: str, password: str) -> list[dict]:
        out = []
        for uf in USERNAME_FIELDS:
            out.append({uf: username, "password": password})
        # Juice Shop shape: {email, password}
        out.append({"email": username, "password": password})
        return out

    def _fresh_form_values(self, form: FormInfo) -> dict[str, str]:
        """Re-fetch the form's page to pick up CURRENT hidden-field values
        (CSRF tokens are frequently per-session or per-request)."""
        url = (form.page_url or form.action).split("#", 1)[0]
        result = self.client.get(url)
        if result.error or result.status is None:
            return dict(form.hidden_values)
        out: dict[str, str] = {}
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(result.text, "html.parser")
            for tag in soup.find_all("form"):
                for inp in tag.find_all("input"):
                    name = inp.get("name")
                    if not name:
                        continue
                    if (inp.get("type") or "text").lower() == "hidden":
                        out[name] = inp.get("value") or ""
        except Exception:
            return dict(form.hidden_values)
        return out or dict(form.hidden_values)

    def _form_field_map(self, form: FormInfo | None, username: str, password: str) -> dict:
        if form is None:
            return {"username": username, "password": password}
        values: dict[str, str] = {}
        for name, ftype in form.field_types.items():
            if ftype == "password":
                values[name] = password
            elif ftype == "hidden":
                values[name] = ""  # filled with fresh values below
            elif any(h in name.lower() for h in ("user", "email", "login", "mail")):
                values[name] = username
        for name in form.fields:
            values.setdefault(name, username if name.lower() in USERNAME_FIELDS else
                              (password if name.lower() in PASSWORD_FIELDS else ""))
        for name, value in self._fresh_form_values(form).items():  # overlay fresh CSRF tokens
            values[name] = value
        return values

    def _evaluate(self, result: FetchResult, url: str, *, strategy: str,
                  pre_cookies: set[str] | None = None, form_kind: bool = False) -> bool:
        """Success heuristics, in order of strength:
          1. a token (JWT) in the response body;
          2. form logins that redirect AWAY from a login-looking URL
             (the DVWA pattern: success -> index, failure -> back to login);
          3. a recognized session cookie (detected name) now present in the jar.
        """
        if result.error or result.status is None:
            return False
        body = result.text[:16384]

        token = self._extract_token(result)
        if token:
            claims = decode_jwt(token)
            if claims is not None:
                self.info.token_type = "jwt"
                self.info.token_storage = "response_body"
                self.info.jwt_sample_claims = claims
                self.client.jwt_token = token
                log.info("JWT obtained via %s (claims: %s)", strategy, sorted(claims)[:6])
            else:
                if self.info.token_type is None:
                    self.info.token_type = "session_cookie"
                    self.info.token_storage = "set_cookie"
            self.info.authenticated = True
            self.info.login_strategy = strategy
            return True

        ok_status = 200 <= result.status < 300
        looks_failed = bool(FAIL_HINTS.search(body))
        jar_names = self.client.cookie_names
        got_session = any(c.lower() in self.info.session_cookie_names for c in jar_names)
        final_path = urlsplit(result.final_url).path
        away_from_login = not LOGIN_URL_HINTS.search(final_path)

        success = False
        if ok_status and not looks_failed:
            if form_kind and away_from_login:
                success = True
            elif got_session:
                success = True
            elif not form_kind and away_from_login and any(
                    re.search(r"(session|sid|auth|token|login)", c, re.I)
                    for c in set(jar_names) - (pre_cookies or set())):
                success = True  # JSON endpoint set a session-ish cookie + left the login URL

        if success:
            self.info.authenticated = True
            self.info.login_strategy = strategy
            if self.info.token_type is None:
                self.info.token_type = "session_cookie"
                self.info.token_storage = "set_cookie"
        return success

    @staticmethod
    def _extract_token(result: FetchResult) -> str | None:
        data = result.json()
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in SUCCESS_TOKEN_KEYS:
                    if isinstance(value, str) and RE_JWT.match(value):
                        return value
                    if isinstance(value, dict):
                        for k2, v2 in value.items():
                            if isinstance(v2, str) and (RE_JWT.match(v2) or k2.lower() in SUCCESS_TOKEN_KEYS):
                                if RE_JWT.match(v2):
                                    return v2
            raw = json.dumps(data)
            m = RE_JWT.search(raw)
            if m:
                return m.group(0)
        m = RE_JWT.search(result.text[:16384])
        if m:
            return m.group(0)
        return None

    # ------------------------------------------------------------------ #
    # Protected-surface probing: which endpoints flip 401/403 -> 2xx?
    # ------------------------------------------------------------------ #
    def probe_protected(self, endpoints: dict[tuple[str, str], Endpoint],
                        *, max_probes: int = 25) -> list[str]:
        """Re-test endpoints that ever answered 401/403; flip auth_required on success.

        Note: after the authenticated crawl pass, some endpoints carry merged
        status histories (e.g. [401, 200]) — the 401/403 marker alone decides
        probing, not a strict all-codes match.
        """
        protected: list[str] = []
        checked = 0
        for (_m, _k), ep in sorted(endpoints.items()):
            if checked >= max_probes:
                break
            if any(code in (401, 403) for code in ep.status_codes):
                checked += 1
                result = self.client.get(ep.url)
                if result.status and 200 <= result.status < 300:
                    ep.auth_required = True
                    if result.status not in ep.status_codes:
                        ep.status_codes.append(result.status)
                    if ep.url not in protected:
                        protected.append(ep.url)
                    ep.notes = f"{ep.notes or ''}; auth flips 401/403->200".strip("; ")
        if protected:
            self.info.protected_endpoints = protected
        return protected
