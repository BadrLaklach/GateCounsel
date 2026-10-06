"""Pydantic models for Hackbot's attack plan (planner output contract, spec §6.2).

The plan is the interface between the Planner Agent and the expert/exploit
agents: every task is an (endpoint, vulnerability_class) hypothesis produced
from recon signals, scored 0-100 (impact x likelihood), banded, and tagged
with a risk tier so the exploit stage can auto-run only benign GET probes.

Deterministic rules produce the tasks; an optional LLM pass (OpenAI-compatible
API, e.g. Gemini) may re-rank, drop false positives and enrich rationales.
The plan stays valid even if the LLM layer is absent or fails.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field

VulnClass = Literal[
    "sqli",            # SQL / command injection candidates
    "xss_reflected",   # reflected XSS candidates
    "jwt_misconfig",   # JWT structure / claims weaknesses
    "auth_bypass",     # access-control verification on protected endpoints
    "idor",            # insecure direct object references
    "ssrf",            # server-side request fetch parameters
    "open_redirect",   # unvalidated redirect parameters
]
RiskTier = Literal["safe_probe", "needs_review"]
Band = Literal["critical", "high", "medium", "low"]


def band_from_priority(priority: int) -> Band:
    """Map a 0-100 priority onto a CVSS-inspired band."""
    if priority >= 80:
        return "critical"
    if priority >= 60:
        return "high"
    if priority >= 40:
        return "medium"
    return "low"


class PlanTask(BaseModel):
    """One attack hypothesis routed to an expert agent."""

    id: str = "T-000"
    vuln_class: VulnClass
    expert_route: str  # which expert agent should execute it (e.g. sqli_expert)
    endpoint_url: str
    method: str = "GET"
    target_params: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)  # recon evidence behind the task
    rationale: str = ""
    priority: int = 0  # 0-100, impact x likelihood
    band: Band = "low"
    risk_tier: RiskTier = "safe_probe"

    def reband(self) -> None:
        self.band = band_from_priority(self.priority)


class PlanSummary(BaseModel):
    """Aggregated counts for quick dashboarding / report writing."""

    total_tasks: int = 0
    by_class: dict[str, int] = Field(default_factory=dict)
    by_band: dict[str, int] = Field(default_factory=dict)
    safe_probes: int = 0
    needs_review: int = 0


class AttackPlan(BaseModel):
    """Full planner output for one target. Consumed by expert/exploit agents."""

    target: str
    base_url: str
    generated_at: str
    planner_version: str = "0.1.0"
    summary: PlanSummary = Field(default_factory=PlanSummary)
    tasks: list[PlanTask] = Field(default_factory=list)
    llm_used: bool = False
    llm_model: Optional[str] = None
    notes: list[str] = Field(default_factory=list)

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)
