"""Hackbot Planner Agent (spec §6.2) — turns the recon site map into a
prioritized, safety-tiered attack plan.

Pipeline:
  1. Deterministic rule engine generates candidate tasks from recon signals
     and scores them (impact x likelihood, 0-100).
  2. Optional LLM pass re-ranks, drops false positives and enriches
     rationales. The planner NEVER lets the LLM invent tasks: model output
     is validated against candidate IDs, and priority edits are clamped to
     the rule score. A hallucinated or malformed reply falls back to rules-only.

Output: agents.planner.models.AttackPlan — consumed by expert/exploit agents.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Mapping, TypedDict

from agents.planner.client.llm_client import LLMClient, extract_json_object, llm_config_from_env
from agents.planner.engine.rule_engine import RuleEngine
from agents.planner.models.plan_models import AttackPlan, PlanSummary, PlanTask
from agents.recon.core.models import SiteMap

log = logging.getLogger("hackbot.planner")

PLANNER_VERSION = "0.1.0"
MAX_LLM_CANDIDATES = 30
LLM_PRIORITY_DELTA = 20


class PlannerConfig(TypedDict, total=False):
    max_tasks: int
    min_priority: int
    use_llm: bool
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    llm_timeout: float


class AttackPlanner:
    """Deterministic-first planner with an optional LLM re-ranking layer."""

    def __init__(self, config: PlannerConfig | None = None) -> None:
        cfg: PlannerConfig = config or {}
        self.max_tasks = int(cfg.get("max_tasks", 40))
        self.min_priority = int(cfg.get("min_priority", 0))

        self.llm_client: LLMClient | None = None
        self.llm_model: str | None = None
        self._llm_requested = cfg.get("use_llm")
        self._llm_unavailable_note: str | None = None
        llm_cfg = llm_config_from_env(
            base_url=cfg.get("llm_base_url"),
            api_key=cfg.get("llm_api_key"),
            model=cfg.get("llm_model"),
        )
        if llm_cfg and self._llm_requested is not False:
            timeout = float(cfg.get("llm_timeout", 25.0))
            self.llm_client = LLMClient(llm_cfg, timeout=timeout)
            self.llm_model = llm_cfg["model"]
        elif self._llm_requested is True:
            self._llm_unavailable_note = (
                "LLM pass requested but no API key found "
                "(LLM_API_KEY / GEMINI_API_KEY / OPENAI_API_KEY) — rules-only plan"
            )

    def close(self) -> None:
        if self.llm_client is not None:
            self.llm_client.close()

    def plan(self, sitemap: SiteMap) -> AttackPlan:
        notes: list[str] = []

        candidates = RuleEngine().generate(sitemap)
        notes.append(f"{len(candidates)} candidate task(s) from deterministic rules")

        candidates = [t for t in candidates if t.priority >= self.min_priority]
        candidates = candidates[: self.max_tasks]

        llm_used = False
        if self.llm_client is not None:
            try:
                candidates = self._llm_rerank(sitemap, candidates, notes)
                llm_used = True
            except Exception as exc:  # LLM must never break planning
                note = f"LLM pass failed ({type(exc).__name__}: {exc}) — deterministic plan kept"
                notes.append(note)
                log.warning(note)
        elif self._llm_unavailable_note:
            notes.append(self._llm_unavailable_note)

        return AttackPlan(
            target=sitemap.target,
            base_url=sitemap.base_url,
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            planner_version=PLANNER_VERSION,
            summary=self._summarize(candidates),
            tasks=candidates,
            llm_used=llm_used,
            llm_model=self.llm_model if llm_used else None,
            notes=notes,
        )

    def _llm_rerank(self, sitemap: SiteMap, tasks: list[PlanTask],
                    notes: list[str]) -> list[PlanTask]:
        """Ask the LLM to re-rank/drop candidates. It cannot add tasks."""
        digest = [
            {
                "id": t.id,
                "vuln_class": t.vuln_class,
                "endpoint": t.endpoint_url,
                "method": t.method,
                "params": t.target_params,
                "signals": t.signals,
                "priority": t.priority,
                "risk_tier": t.risk_tier,
            }
            for t in tasks[:MAX_LLM_CANDIDATES]
        ]
        claims = sitemap.auth.jwt_sample_claims
        auth_digest = {
            "token_type": sitemap.auth.token_type,
            "authenticated": sitemap.auth.authenticated,
            "jwt_claim_names": sorted(claims) if claims else None,
            "protected_endpoints": len(sitemap.auth.protected_endpoints),
        }
        system = (
            "You are the planning layer of an AUTHORIZED penetration-testing "
            "framework. Recon produced the candidate attack tasks below. "
            "Re-rank them by real-world exploitability, drop obvious false "
            "positives, and sharpen each kept task's rationale in one sentence. "
            "You must NOT invent new tasks or change IDs. "
            'Respond with ONLY this JSON shape: '
            '{"tasks": [{"id": "T-001", "keep": true, "priority": 0-100, '
            '"rationale": "..."}]}'
        )
        user = json.dumps({
            "target": sitemap.target,
            "auth": auth_digest,
            "candidates": digest,
        }, ensure_ascii=False)

        if self.llm_client is None:
            raise RuntimeError("LLM client is not configured")
        raw = self.llm_client.complete(system, user)
        data = extract_json_object(raw)
        if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
            raise ValueError("LLM reply is not the expected JSON object")

        by_id = {t.id: t for t in tasks}
        adjusted = 0
        for item in data["tasks"]:
            if not isinstance(item, dict):
                continue
            task = by_id.get(str(item.get("id", "")))
            if task is None:
                continue
            if item.get("keep") is False:
                task.priority = 0
                adjusted += 1
                continue
            priority = item.get("priority")
            if isinstance(priority, (int, float)) and 0 <= priority <= 100:
                rule_priority = task.priority
                lo = max(1, rule_priority - LLM_PRIORITY_DELTA)
                hi = min(100, rule_priority + LLM_PRIORITY_DELTA)
                task.priority = max(lo, min(hi, int(priority)))
                task.reband()
                adjusted += 1
            rationale = item.get("rationale")
            if isinstance(rationale, str) and rationale.strip():
                task.rationale = rationale.strip()[:400]
        notes.append(f"LLM ({self.llm_model}) adjusted {adjusted} task(s)")

        kept = [t for t in tasks if t.priority > 0]
        kept.sort(key=lambda t: (-t.priority, t.vuln_class, t.endpoint_url))
        for i, task in enumerate(kept, start=1):
            task.id = f"T-{i:03d}"
        return kept

    @staticmethod
    def _summarize(tasks: list[PlanTask]) -> PlanSummary:
        by_class: dict[str, int] = {}
        by_band: dict[str, int] = {}
        needs_review = 0
        for t in tasks:
            by_class[t.vuln_class] = by_class.get(t.vuln_class, 0) + 1
            by_band[t.band] = by_band.get(t.band, 0) + 1
            if t.risk_tier == "needs_review":
                needs_review += 1
        return PlanSummary(
            total_tasks=len(tasks),
            by_class=by_class,
            by_band=by_band,
            safe_probes=len(tasks) - needs_review,
            needs_review=needs_review,
        )


def planner_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """LangGraph-compatible node: consume state['sitemap'], emit state['plan']."""
    sitemap = SiteMap.model_validate(state["sitemap"])
    planner = AttackPlanner(config=state.get("planner_config"))
    try:
        plan = planner.plan(sitemap)
    finally:
        planner.close()
    return {"plan": plan.model_dump(), "planner_done": True}
