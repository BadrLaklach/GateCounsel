"""A tiny deliberately-vulnerable mock app used ONLY to unit-test the
Hackbot recon pipeline without Docker. Pure stdlib, ephemeral port.

Features it emulates (mirroring common lab-app patterns):
  * HTML pages with links + a GET search form that REFLECTS its parameter
  * a login page (form) and a JSON login API issuing a JWT
  * session cookie issuance on successful login
  * a protected /admin endpoint (401 anonymous, 200 with Bearer/cookie)
  * an OpenAPI spec and robots.txt disclosing a hidden page
  * inline JS referencing /api/users (so JS-extraction has something to find)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = """<!doctype html>
<html><head><title>MockShop</title>
<script src="/static/app.js"></script></head>
<body>
  <h1>MockShop — the mock vulnerable app</h1>
  <a href="/about">About</a>
  <a href="/login">Login</a>
  <a href="/csrf/login">Secure admin login</a>
  <a href="/admin">Admin</a>
  <form action="/search" method="GET">
    <input type="text" name="q" placeholder="search products">
    <button type="submit">Go</button>
  </form>
  <div id="out"></div>
  <script>
    fetch('/api/users').then(r => r.json()).then(d => {{
      document.getElementById('out').textContent = d.length + ' users';
    }});
  </script>
</body></html>"""

ABOUT = PAGE.replace("MockShop — the mock vulnerable app", "About MockShop")
LOGIN_PAGE = """<!doctype html>
<html><head><title>Login — MockShop</title></head><body>
  <form action="/login" method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
  </form>
</body></html>"""

CSRF_LOGIN_PAGE = """<!doctype html>
<html><head><title>Secure login — MockShop</title></head><body>
  <form action="/csrf/login" method="POST">
    <input type="hidden" name="user_token" value="{token}">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
  </form>
</body></html>"""

ADMIN_PAGE = "<html><body><h1>Admin panel</h1><p>secret metrics: 42</p></body></html>"
HIDDEN = "<html><body><h1>Hidden treasure page</h1></body></html>"

USERS = [{"id": 1, "email": "admin@mock.sh", "role": "admin"},
         {"id": 2, "email": "user@mock.sh", "role": "user"}]

SECRET = b"hackbot-mock-secret"
JSON_USERS = {"admin@mock.sh": "admin123"}   # /auth/login JSON API -> JWT
VALID_USERS = {"admin": "admin123"}          # /csrf/login form -> session cookie
FORM_USERS = {"user": "password123"}         # plain HTML form login (no CSRF)
CSRF_SESSIONS: dict[str, str] = {}  # sid -> current user_token


def make_jwt(payload: dict) -> str:
    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body["exp"] = int(time.time()) + 3600
    signing = f"{b64(header)}.{b64(body)}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(SECRET, signing, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(body)}.{sig}"


class MockAppHandler(BaseHTTPRequestHandler):
    server_version = "Werkzeug/2.3.0"  # realistic-ish fingerprint

    def log_message(self, *args):  # silence test noise
        pass

    # helpers ------------------------------------------------------------ #
    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return len(auth) > 20
        cookie = self.headers.get("Cookie", "")
        return "session=" in cookie

    # routes -------------------------------------------------------------- #
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        qs = parse_qs(urlsplit(self.path).query)

        if path == "/":
            return self._send(200, PAGE.encode())
        if path == "/about":
            return self._send(200, ABOUT.encode())
        if path == "/login":
            return self._send(200, LOGIN_PAGE.encode())
        if path == "/csrf/login":  # DVWA-style: session-bound CSRF token in a hidden field
            sid = self._cookie("sid")
            headers = {}
            if not sid:
                sid = base64.b64encode(os.urandom(9)).decode().rstrip("=")
                headers["Set-Cookie"] = f"sid={sid}; Path=/"
            token = hmac.new(SECRET + sid.encode(), b"csrf", hashlib.sha256).hexdigest()[:10]
            CSRF_SESSIONS[sid] = token
            return self._send(200, CSRF_LOGIN_PAGE.format(token=token).encode(), headers=headers)
        if path == "/search":
            q = (qs.get("q") or [""])[0]
            body = PAGE.replace("MockShop — the mock vulnerable app",
                                f"Search results for: {q}")
            return self._send(200, body.encode())
        if path == "/admin":
            if self._authorized():
                return self._send(200, ADMIN_PAGE.encode())
            return self._send(401, b"<html><body>401 Unauthorized</body></html>")
        if path == "/hidden-treasure":
            return self._send(200, HIDDEN.encode())
        if path == "/api/users":
            return self._send(200, json.dumps(USERS).encode(), "application/json")
        if path == "/api/items":
            return self._send(200, json.dumps([{"id": 1, "name": "item"}]).encode(), "application/json")
        if path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "MockShop API", "version": "1.0"},
                "servers": [{"url": "/"}],
                "paths": {
                    "/api/items": {
                        "get": {"summary": "List items",
                                "parameters": [{"name": "page", "in": "query", "schema": {"type": "integer"}}]},
                        "post": {"summary": "Create item",
                                 "requestBody": {"content": {"application/json": {
                                     "schema": {"properties": {"name": {"type": "string"}}}}}}},
                    }
                },
            }
            return self._send(200, json.dumps(spec).encode(), "application/json")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /hidden-treasure\n", "text/plain")
        if path == "/static/app.js":
            js = ("axios.get('/api/users');\n"
                  "const cfg = '/api/config';\n"
                  "document.querySelector('#out');\n")
            return self._send(200, js.encode(), "application/javascript")
        return self._send(404, b"<html><body>404 Not Found</body></html>")

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")

        if path == "/auth/login":
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                data = {}
            user = data.get("email") or data.get("username")
            if user in JSON_USERS and data.get("password") == JSON_USERS[user]:
                token = make_jwt({"sub": user, "role": "admin"})
                body = json.dumps({"authentication": {"token": token, "umail": user}})
                return self._send(200, body.encode(), "application/json")
            return self._send(401, json.dumps({"error": "Invalid email or password."}).encode(),
                              "application/json")

        if path == "/login":
            data = parse_qs(raw.decode())
            user = (data.get("username") or [""])[0]
            password = (data.get("password") or [""])[0]
            if FORM_USERS.get(user) == password:
                return self._send(302, b"", headers={
                    "Location": "/", "Set-Cookie": "session=abc123sessiontoken; Path=/"})
            return self._send(302, b"", headers={
                "Location": "/login", "Set-Cookie": "session=; Path=/"})

        if path == "/csrf/login":  # CSRF token MUST be valid AND creds must match
            sid = self._cookie("sid")
            data = parse_qs(raw.decode())
            token = (data.get("user_token") or [""])[0]
            user = (data.get("username") or [""])[0]
            password = (data.get("password") or [""])[0]
            expected = CSRF_SESSIONS.get(sid, "")
            if (sid and expected and hmac.compare_digest(token, expected)
                    and VALID_USERS.get(user) == password):
                return self._send(302, b"", headers={
                    "Location": "/", "Set-Cookie": "session=csrfsession456; Path=/"})
            return self._send(302, b"", headers={"Location": "/csrf/login"})

        return self._send(404, b"404")

    def _cookie(self, name: str) -> str:
        """Read one named cookie from the request's Cookie header."""
        from http.cookies import SimpleCookie
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        morsel = jar.get(name)
        return morsel.value if morsel else ""


def start_mock_app() -> tuple[ThreadingHTTPServer, str]:
    """Start on an ephemeral port; returns (server, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockAppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
