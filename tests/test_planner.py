"""Tests for the Hackbot Planner Agent (spec §6.2).

Run from the repo root:  python -m unittest tests.test_planner -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.planner import AttackPlanner, planner_node  # noqa: E402
from agents.planner.client.llm_client import extract_json_object, llm_config_from_env  # noqa: E402
from agents.planner.engine.rule_engine import RuleEngine  # noqa: E402
from agents.planner.models.plan_models import AttackPlan, band_from_priority  # noqa: E402
from agents.planner.planner import LLM_PRIORITY_DELTA  # noqa: E402
from agents.recon.core.models import AuthInfo, Endpoint, Param, SiteMap, TechHint  # noqa: E402
from tests.mock_app import start_mock_app  # noqa: E402

BASE = "http://lab.local:3000"


def _ep(url: str, method: str = "GET", **kw) -> Endpoint:
    return Endpoint(url=url, method=method, **kw)


def synthetic_sitemap() -> SiteMap:
    """A site map that exercises every planner rule."""
    return SiteMap(
        target=BASE,
        base_url=BASE,
        generated_at="2025-01-01T00:00:00+0000",
        endpoints=[
            _ep(f"{BASE}/search", params=[Param(name="q", reflected=True)],
                reflected_params=["q"], status_codes=[200]),
            _ep(f"{BASE}/users", params=[Param(name="id", type_hint="number",
                                               examples=["1", "2"])], status_codes=[200]),
            _ep(f"{BASE}/redirect", params=[Param(name="next", examples=["/dashboard"])],
                status_codes=[200]),
            _ep(f"{BASE}/fetch", params=[Param(name="url", examples=["http://internal/"])],
                status_codes=[200]),
            _ep(f"{BASE}/admin", status_codes=[401], auth_required=True),
            _ep(f"{BASE}/api/login", method="POST",
                params=[Param(name="username", examples=["admin"]), Param(name="password")]),
            _ep(f"{BASE}/items", method="POST",
                params=[Param(name="id", examples=["1"])], status_codes=[200]),
        ],
        auth=AuthInfo(token_type="jwt",
                      jwt_sample_claims={"sub": "a@b.c", "role": "admin", "exp": 1735689600},
                      token_storage="localStorage",
                      protected_endpoints=[f"{BASE}/admin"]),
        technologies=[TechHint(name="PHP", category="language", source="header", evidence="x")],
    )


def _find(tasks, vuln_class, url_sub=None):
    return [t for t in tasks if t.vuln_class == vuln_class
            and (url_sub is None or url_sub in t.endpoint_url)]


class _FakeLLM:
    """Stand-in for LLMClient in re-rank tests."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.last_user = None

    def complete(self, system: str, user: str, **kw) -> str:
        self.last_user = user
        return self.reply

    def close(self) -> None:
        pass


class RuleEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = RuleEngine().generate(synthetic_sitemap())

    def test_sqli_task_for_search_param(self):
        sqli = _find(self.tasks, "sqli", "/search")
        self.assertTrue(sqli, "no sqli task for /search")
        self.assertIn("q", sqli[0].target_params)
        self.assertTrue(any("reflected" in s for s in sqli[0].signals))
        self.assertEqual(sqli[0].risk_tier, "needs_review")

    def test_sqli_requires_two_signals(self):
        sitemap = SiteMap(
            target=BASE, base_url=BASE, generated_at="2025-01-01T00:00:00+0000",
            endpoints=[_ep(f"{BASE}/page", params=[Param(name="q")])],
        )
        tasks = RuleEngine().generate(sitemap)
        self.assertFalse(_find(tasks, "sqli", "/page"))

    def test_xss_task_for_reflected_param(self):
        xss = _find(self.tasks, "xss_reflected", "/search")
        self.assertTrue(xss, "no xss task for reflected q")
        self.assertEqual(xss[0].method, "GET")
        self.assertEqual(xss[0].risk_tier, "safe_probe")
        self.assertEqual(xss[0].expert_route, "xss_expert")

    def test_idor_task_numeric_id(self):
        idor = _find(self.tasks, "idor", "/users")
        self.assertTrue(idor, "no idor task for /users?id=")
        self.assertIn("id", idor[0].target_params)
        self.assertTrue(any("numeric" in s for s in idor[0].signals))

    def test_idor_skips_name_without_value_evidence(self):
        sitemap = SiteMap(
            target=BASE, base_url=BASE, generated_at="2025-01-01T00:00:00+0000",
            endpoints=[_ep(f"{BASE}/ref", params=[Param(name="ref")])],
        )
        tasks = RuleEngine().generate(sitemap)
        self.assertFalse(_find(tasks, "idor", "/ref"))

    def test_open_redirect_task(self):
        red = _find(self.tasks, "open_redirect", "/redirect")
        self.assertTrue(red, "no open_redirect task for next=")
        self.assertEqual(red[0].risk_tier, "safe_probe")

    def test_ssrf_task_needs_review(self):
        ssrf = _find(self.tasks, "ssrf", "/fetch")
        self.assertTrue(ssrf, "no ssrf task for url=")
        self.assertEqual(ssrf[0].risk_tier, "needs_review")
        self.assertEqual(ssrf[0].expert_route, "ssrf_expert")

    def test_jwt_misconfig_task(self):
        jwt_tasks = _find(self.tasks, "jwt_misconfig")
        self.assertTrue(jwt_tasks, "no jwt_misconfig task")
        signals = " | ".join(jwt_tasks[0].signals)
        self.assertIn("role", signals)
        self.assertIn("localStorage", signals)
        self.assertEqual(jwt_tasks[0].expert_route, "jwt_expert")

    def test_jwt_missing_expiry_signal(self):
        sitemap = synthetic_sitemap()
        sitemap.auth.jwt_sample_claims = {"sub": "a@b.c", "role": "admin"}
        tasks = RuleEngine().generate(sitemap)
        jwt_tasks = _find(tasks, "jwt_misconfig")
        self.assertTrue(any("no 'exp'" in s for s in jwt_tasks[0].signals))

    def test_auth_bypass_task(self):
        bypass = _find(self.tasks, "auth_bypass", "/admin")
        self.assertTrue(bypass, "no auth_bypass task for /admin")
        self.assertEqual(bypass[0].risk_tier, "needs_review")
        self.assertEqual(bypass[0].expert_route, "auth_bypass_expert")
        self.assertTrue(any("401/403" in s for s in bypass[0].signals))

    def test_post_endpoint_sqli_is_needs_review(self):
        sqli = _find(self.tasks, "sqli", "/items")
        self.assertTrue(sqli, "no sqli task on POST /items")
        self.assertEqual(sqli[0].method, "POST")
        self.assertEqual(sqli[0].risk_tier, "needs_review")

    def test_login_username_alone_is_not_sqli(self):
        self.assertFalse(_find(self.tasks, "sqli", "/api/login"))

    def test_sorted_desc_with_sequential_ids_and_bands(self):
        priorities = [t.priority for t in self.tasks]
        self.assertEqual(priorities, sorted(priorities, reverse=True))
        self.assertEqual([t.id for t in self.tasks],
                         [f"T-{i:03d}" for i in range(1, len(self.tasks) + 1)])
        for t in self.tasks:
            self.assertEqual(t.band, band_from_priority(t.priority))
            self.assertTrue(1 <= t.priority <= 100)

    def test_dedup_merges_same_class_and_endpoint(self):
        sitemap = synthetic_sitemap()
        sitemap.endpoints[1].params.append(Param(name="user_id", examples=["7"]))
        tasks = RuleEngine().generate(sitemap)
        idor = _find(tasks, "idor", "/users")
        self.assertEqual(len(idor), 1)
        self.assertIn("id", idor[0].target_params)
        self.assertIn("user_id", idor[0].target_params)


class LlmClientTests(unittest.TestCase):
    def test_extract_json_object_from_fence(self):
        raw = '```json\n{"tasks": [{"id": "T-001", "keep": true}]}\n```'
        data = extract_json_object(raw)
        self.assertEqual(data["tasks"][0]["id"], "T-001")

    def test_extract_json_object_ignores_prose_and_nested_braces(self):
        raw = 'Sure. {"tasks": [{"id": "T-001", "rationale": "uses {id}"}]} trailing'
        data = extract_json_object(raw)
        self.assertEqual(data["tasks"][0]["rationale"], "uses {id}")

    def test_extract_json_object_rejects_arrays(self):
        self.assertIsNone(extract_json_object("[1, 2]"))

    def test_llm_config_reads_dotenv_when_env_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            dotenv = Path(tmp) / ".env"
            dotenv.write_text("GEMINI_API_KEY=from-file\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
                "agents.planner.client.llm_client._repo_dotenv_paths",
                return_value=[dotenv],
            ):
                cfg = llm_config_from_env()
        self.assertEqual(cfg["api_key"], "from-file")

    def test_llm_config_none_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "agents.planner.client.llm_client._repo_dotenv_paths",
            return_value=[],
        ):
            self.assertIsNone(llm_config_from_env())


class AttackPlannerTests(unittest.TestCase):
    def test_plan_contract_and_summary(self):
        plan = AttackPlanner({"use_llm": False}).plan(synthetic_sitemap())
        self.assertIsInstance(plan, AttackPlan)
        self.assertEqual(plan.summary.total_tasks, len(plan.tasks))
        self.assertEqual(sum(plan.summary.by_class.values()), len(plan.tasks))
        self.assertEqual(sum(plan.summary.by_band.values()), len(plan.tasks))
        self.assertEqual(plan.summary.safe_probes + plan.summary.needs_review,
                         len(plan.tasks))
        self.assertFalse(plan.llm_used)
        again = AttackPlan.model_validate(json.loads(plan.model_dump_json()))
        self.assertEqual(again.summary.total_tasks, plan.summary.total_tasks)

    def test_max_tasks_cap(self):
        plan = AttackPlanner({"use_llm": False, "max_tasks": 2}).plan(synthetic_sitemap())
        self.assertEqual(len(plan.tasks), 2)

    def test_min_priority_filter(self):
        plan = AttackPlanner({"use_llm": False, "min_priority": 95}).plan(synthetic_sitemap())
        self.assertTrue(all(t.priority >= 95 for t in plan.tasks))

    def test_llm_fallback_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "agents.planner.client.llm_client._repo_dotenv_paths",
            return_value=[],
        ):
            planner = AttackPlanner({"use_llm": True})
        self.assertIsNone(planner.llm_client)
        plan = planner.plan(synthetic_sitemap())
        self.assertFalse(plan.llm_used)
        self.assertTrue(any("no API key" in n for n in plan.notes))

    def test_llm_rerank_applied_and_clamped(self):
        rules = RuleEngine().generate(synthetic_sitemap())
        original = rules[0].priority
        planner = AttackPlanner({"use_llm": False})
        planner.llm_client = _FakeLLM(json.dumps(
            {"tasks": [{"id": "T-001", "keep": True, "priority": 99,
                        "rationale": "top pick per analyst"}]}))
        planner.llm_model = "fake-model"
        plan = planner.plan(synthetic_sitemap())
        self.assertTrue(plan.llm_used)
        bumped = next(t for t in plan.tasks if t.rationale == "top pick per analyst")
        self.assertEqual(bumped.priority, min(100, original + LLM_PRIORITY_DELTA))
        self.assertEqual(bumped.band, band_from_priority(bumped.priority))

    def test_llm_drop_task(self):
        planner = AttackPlanner({"use_llm": False})
        planner.llm_client = _FakeLLM(json.dumps(
            {"tasks": [{"id": "T-001", "keep": False}]}))
        planner.llm_model = "fake-model"
        expected = len(RuleEngine().generate(synthetic_sitemap())) - 1
        plan = planner.plan(synthetic_sitemap())
        self.assertEqual(plan.summary.total_tasks, expected)

    def test_llm_invalid_json_falls_back(self):
        planner = AttackPlanner({"use_llm": False})
        planner.llm_client = _FakeLLM("sorry, I cannot help with that")
        planner.llm_model = "fake-model"
        plan = planner.plan(synthetic_sitemap())
        self.assertFalse(plan.llm_used)
        self.assertTrue(any("LLM pass failed" in n for n in plan.notes))
        self.assertEqual(plan.summary.total_tasks,
                         len(RuleEngine().generate(synthetic_sitemap())))

    def test_llm_cannot_invent_tasks(self):
        planner = AttackPlanner({"use_llm": False})
        planner.llm_client = _FakeLLM(json.dumps(
            {"tasks": [{"id": "T-999", "keep": True, "priority": 100},
                       {"id": "T-001", "keep": True, "priority": 50}]}))
        planner.llm_model = "fake-model"
        rules = RuleEngine().generate(synthetic_sitemap())
        plan = planner.plan(synthetic_sitemap())
        self.assertEqual(plan.summary.total_tasks, len(rules))
        self.assertNotIn("T-999", [t.id for t in plan.tasks])


class PlannerIntegrationTests(unittest.TestCase):
    """Full recon -> planner flow against the live mock app."""

    server = None
    base_url = None

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = start_mock_app()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _sitemap(self, username=None, password=None) -> SiteMap:
        from agents.recon.recon_agent import ReconAgent
        return ReconAgent(
            self.base_url, username=username, password=password,
            config={"use_playwright": False, "rps": 20, "max_pages": 30, "max_depth": 2},
        ).run()

    def test_recon_then_planner_pipeline(self):
        sitemap = self._sitemap(username="admin@mock.sh", password="admin123")
        plan = AttackPlanner({"use_llm": False}).plan(sitemap)
        self.assertGreater(plan.summary.total_tasks, 3)
        self.assertTrue(_find(plan.tasks, "xss_reflected", "/search"))
        self.assertTrue(_find(plan.tasks, "jwt_misconfig"))
        bypass = _find(plan.tasks, "auth_bypass", "/admin")
        self.assertTrue(bypass)
        self.assertTrue(all(t.signals for t in plan.tasks))
        self.assertTrue(all(t.rationale for t in plan.tasks))

    def test_planner_node_direct(self):
        dump = self._sitemap().model_dump()
        update = planner_node({"sitemap": dump, "planner_config": {"use_llm": False}})
        self.assertTrue(update["planner_done"])
        self.assertGreater(update["plan"]["summary"]["total_tasks"], 0)

    def test_langgraph_recon_planner_graph(self):
        try:
            from orchestration.graph import LANGGRAPH_AVAILABLE, run_recon_and_plan
        except ImportError:
            self.skipTest("langgraph not installed")
        if not LANGGRAPH_AVAILABLE:
            self.skipTest("langgraph not installed")
        result = run_recon_and_plan(
            self.base_url,
            recon_config={"use_playwright": False, "rps": 20},
            planner_config={"use_llm": False},
        )
        self.assertTrue(result.get("recon_done"))
        self.assertTrue(result.get("planner_done"))
        self.assertTrue(result["plan"]["tasks"])


class PlannerCliTests(unittest.TestCase):
    def test_cli_writes_plan(self):
        from run_planner import main
        with tempfile.TemporaryDirectory() as tmp:
            sitemap_path = Path(tmp) / "sitemap.json"
            sitemap_path.write_text(synthetic_sitemap().model_dump_json())
            out_path = Path(tmp) / "plan.json"
            rc = main([str(sitemap_path), "--out", str(out_path), "--no-llm", "-q"])
            self.assertEqual(rc, 0)
            data = json.loads(out_path.read_text())
            self.assertIn("tasks", data)
            self.assertIn("summary", data)
            self.assertFalse(data["llm_used"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
