"""End-to-end tests for the Hackbot recon pipeline.

Run from the repo root:   python -m unittest discover -s tests -v
(or:  python tests/test_recon.py)

The suite starts a local mock vulnerable app (stdlib, no Docker) and asserts
the recon agent's discovery, auth, fingerprinting, scope and reflection
behaviors against it. A separate optional browser test runs only when the
Playwright chromium binary is available.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.recon.core.models import SiteMap  # noqa: E402
from agents.recon.planners.gemini_planner import GeminiReconPlanner, _dotenv_key  # noqa: E402
from agents.recon.crawlers.katana_crawler import KatanaCrawler  # noqa: E402
from agents.recon.recon_agent import ReconAgent  # noqa: E402
from safety.scope_guard import ScopeGuard, ScopeViolationError  # noqa: E402
from tests.mock_app import start_mock_app  # noqa: E402


class ScopeGuardTests(unittest.TestCase):
    def test_allowlist_enforced(self):
        guard = ScopeGuard(["http://localhost:3000"])
        self.assertTrue(guard.is_allowed("http://localhost:3000/rest/products"))
        self.assertFalse(guard.is_allowed("http://evil.internal/"))
        self.assertFalse(guard.is_allowed("http://localhost:9999/"))

    def test_port_scoping(self):
        guard = ScopeGuard(["http://localhost:3000"])
        decision = guard.check("http://localhost:9999/")
        self.assertFalse(decision.allowed)
        self.assertIn("port", decision.reason)

    def test_any_port_when_unspecified(self):
        guard = ScopeGuard(["localhost"])
        self.assertTrue(guard.is_allowed("http://localhost:3000/"))
        self.assertTrue(guard.is_allowed("http://localhost:8080/"))

    def test_scheme_block(self):
        guard = ScopeGuard(["http://localhost:3000"])
        self.assertFalse(guard.is_allowed("file:///etc/passwd"))
        self.assertFalse(guard.is_allowed("gopher://localhost:3000/"))

    def test_violation_raises_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            guard = ScopeGuard(["http://localhost:3000"], audit_log=log_path)
            with self.assertRaises(ScopeViolationError):
                guard.enforce("http://evil.internal/steal")
            self.assertTrue(log_path.exists())
            record = json.loads(log_path.read_text().strip())
            self.assertFalse(record["allowed"])
            self.assertEqual(record["url"], "http://evil.internal/steal")

    def test_subdomains_off_by_default(self):
        guard = ScopeGuard(["http://lab.local:3000"])
        self.assertFalse(guard.is_allowed("http://api.lab.local:3000/"))
        guard2 = ScopeGuard(["http://lab.local:3000"], allow_subdomains=True)
        self.assertTrue(guard2.is_allowed("http://api.lab.local:3000/"))


class GeminiPlannerTests(unittest.TestCase):
    def test_dotenv_reader_extracts_only_gemini_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            dotenv = Path(tmp) / ".env"
            dotenv.write_text("OTHER=value\nGEMINI_API_KEY='test-key'\n", encoding="utf-8")
            self.assertEqual(_dotenv_key("GEMINI_API_KEY", dotenv), "test-key")

    def test_planner_payload_is_structural_and_redacted(self):
        from agents.recon.core.models import Endpoint, FormInfo, Param
        endpoint = Endpoint(
            url="http://lab.local/login", method="POST",
            params=[Param(name="password", examples=["secret-value"])],
            forms=[FormInfo(action="http://lab.local/login", hidden_values={"csrf": "secret-token"})],
            response_snippet="private response body",
        )
        payload = GeminiReconPlanner(api_key="test")._payload("http://lab.local", [endpoint], [])
        rendered = json.dumps(payload)
        self.assertIn("password", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("secret-token", rendered)
        self.assertNotIn("private response body", rendered)

    def test_model_response_parser_keeps_only_bounded_candidates(self):
        planner = GeminiReconPlanner(api_key="test", max_targets=1)
        plans = planner._parse('{"candidates":[{"path":"/admin","reason":"admin route"},{"path":"/ignored","reason":"cap"}]}')
        self.assertEqual(plans, [type(plans[0])("/admin", "admin route")])


class KatanaCrawlerTests(unittest.TestCase):
    def test_command_uses_exact_origin_scope_and_safe_defaults(self):
        crawler = KatanaCrawler("https://app.example.test:8443", is_allowed=lambda _url: True,
                                max_depth=2, rps=4, duration_seconds=30)
        command = crawler.command()
        self.assertIn("-jsonl", command)
        self.assertIn("-jc", command)
        self.assertIn("-fs", command)
        self.assertIn("fqdn", command)
        self.assertIn("^https://app\\.example\\.test:8443(?:/|$)", command)
        self.assertNotIn("-headless", command)

    def test_parses_jsonl_and_rejects_invalid_urls(self):
        crawler = KatanaCrawler("http://lab.local", is_allowed=lambda _url: True)
        endpoint = crawler._parse_line('{"request":{"endpoint":"http://lab.local/api/users","method":"GET"},"response":{"status_code":200,"headers":{"content-type":"application/json; charset=utf-8"}}}')
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.url, "http://lab.local/api/users")
        self.assertEqual(endpoint.status_codes, [200])
        self.assertEqual(endpoint.content_type, "application/json")
        self.assertIsNone(crawler._parse_line('{"url":"file:///etc/passwd"}'))


class ReconPipelineTests(unittest.TestCase):
    """Full pipeline against the mock app (no Playwright for determinism)."""

    server = None
    base_url = None

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = start_mock_app()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _run(self, username: str | None = None, password: str | None = None, **cfg) -> SiteMap:
        agent = ReconAgent(
            self.base_url,
            username=username,
            password=password,
            config={"use_playwright": False, "rps": 20, "max_pages": 30, "max_depth": 2, **cfg},
        )
        return agent.run()

    def test_full_recon_map(self):
        sitemap = self._run()
        urls = {e.url for e in sitemap.endpoints}

        # HTML pages found via link crawl
        self.assertIn(self.base_url + "/", urls)
        self.assertIn(self.base_url + "/about", urls)
        self.assertIn(self.base_url + "/login", urls)
        self.assertIn(self.base_url + "/admin", urls)

        # search form: method + param + reflection
        search = next(e for e in sitemap.endpoints if e.url.endswith("/search"))
        self.assertEqual(search.method, "GET")
        self.assertIn("q", [p.name for p in search.params])
        self.assertIn("q", search.reflected_params)

        # JS-referenced API endpoint
        self.assertTrue(any(u.endswith("/api/users") for u in urls),
                        f"/api/users not discovered; urls={urls}")

        # openapi spec parsed -> /api/items with params
        items = next((e for e in sitemap.endpoints if e.url.endswith("/api/items")), None)
        self.assertIsNotNone(items, "OpenAPI-parsed /api/items missing")
        self.assertIn("page", [p.name for p in items.params])

        # robots.txt disclosure
        self.assertTrue(any("hidden-treasure" in u for u in urls), "robots.txt path missing")

        # fingerprinting
        names = {t.name for t in sitemap.technologies}
        self.assertIn("Express (Node.js)", names)  # X-Powered-By header

        # stats sanity
        self.assertGreater(sitemap.stats.requests_made, 5)
        self.assertEqual(sitemap.stats.scope_blocked, 0)

    def test_auto_login_and_protected_surface(self):
        sitemap = self._run(username="admin@mock.sh", password="admin123")
        self.assertTrue(sitemap.auth.authenticated)
        self.assertEqual(sitemap.auth.token_type, "jwt")
        self.assertIsNotNone(sitemap.auth.jwt_sample_claims)
        self.assertEqual(sitemap.auth.jwt_sample_claims.get("sub"), "admin@mock.sh")
        self.assertTrue(any(u.endswith("/admin") for u in sitemap.auth.protected_endpoints),
                        f"protected={sitemap.auth.protected_endpoints}")
        admin = next(e for e in sitemap.endpoints if e.url.endswith("/admin"))
        self.assertTrue(admin.auth_required)

    def test_login_detection_without_credentials(self):
        sitemap = self._run()
        self.assertFalse(sitemap.auth.authenticated)
        self.assertTrue(sitemap.auth.login_candidates, "no login candidates detected")
        self.assertTrue(any(f.has_password_field for f in sitemap.auth.login_forms))

    def test_csrf_protected_form_login(self):
        """DVWA-style flow: login form carries a session-bound hidden CSRF
        token; auto-login must fetch a FRESH token and submit it."""
        sitemap = self._run(username="admin", password="admin123")
        self.assertTrue(sitemap.auth.authenticated,
                        f"csrf login failed; notes={sitemap.notes}")
        self.assertIn("form POST", sitemap.auth.login_strategy or "")
        self.assertIn("csrf/login", sitemap.auth.login_strategy or "")
        self.assertEqual(sitemap.auth.token_type, "session_cookie")

    def test_site_map_is_valid_json_contract(self):
        sitemap = self._run()
        dump = sitemap.model_dump()
        again = SiteMap.model_validate(dump)
        self.assertEqual(again.target, sitemap.target)
        blob = json.loads(sitemap.model_dump_json())
        self.assertIn("endpoints", blob)
        self.assertIn("auth", blob)


class ScopeInteractionTests(unittest.TestCase):
    """The recon agent must never send a request outside the allow-list."""

    def test_agent_blocks_out_of_scope_redirect(self):
        # target that redirects to an out-of-scope host must be refused at the hop
        guard = ScopeGuard(["http://127.0.0.1:1"])
        self.assertFalse(guard.is_allowed("http://somewhere-else.example/"))

    def test_scope_counters_increase_on_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard = ScopeGuard(["http://127.0.0.1:1"], audit_log=Path(tmp) / "a.jsonl")
            before = guard.counters["blocked"]
            guard.check("http://not-in-scope.example/")
            self.assertEqual(guard.counters["blocked"], before + 1)


class LangGraphNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = start_mock_app()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_recon_node_returns_state_update(self):
        from agents.recon.recon_agent import recon_node
        update = recon_node({"target": self.base_url,
                             "recon_config": {"use_playwright": False, "rps": 20}})
        self.assertTrue(update["recon_done"])
        self.assertIn("sitemap", update)
        self.assertTrue(update["sitemap"]["endpoints"])

    def test_langgraph_graph_builds_and_runs(self):
        try:
            from orchestration.graph import LANGGRAPH_AVAILABLE, run_recon
        except ImportError:
            self.skipTest("langgraph not installed")
        if not LANGGRAPH_AVAILABLE:
            self.skipTest("langgraph not installed")
        result = run_recon(self.base_url, recon_config={"use_playwright": False, "rps": 20})
        self.assertTrue(result.get("recon_done"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
