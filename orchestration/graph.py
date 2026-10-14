"""GateCounsel orchestration graph (spec §10) — LangGraph pipeline definition.

Currently wires recon → planner; expert/exploit/report stages attach later.
Keep the node contract dict-shaped so each stage stays independently testable.
"""

from __future__ import annotations

import logging
from typing import Any

from agents.planner import PlannerConfig, planner_node
from agents.recon.recon_agent import ReconState, recon_node

log = logging.getLogger("gatecounsel.graph")

try:
    from langgraph.graph import END, START, StateGraph

    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False


class GateCounselState(ReconState, total=False):
    """Shared pipeline state: recon keys (inherited) + planner keys."""

    plan: dict[str, Any]
    planner_done: bool
    planner_config: PlannerConfig


def build_recon_graph():
    """Graph: START -> recon -> END."""
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed; pip install langgraph")
    graph = StateGraph(ReconState)
    graph.add_node("recon", recon_node)
    graph.add_edge(START, "recon")
    graph.add_edge("recon", END)
    return graph.compile()


def build_recon_planner_graph():
    """Graph: START -> recon -> planner -> END."""
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed; pip install langgraph")
    graph = StateGraph(GateCounselState)
    graph.add_node("recon", recon_node)
    graph.add_node("planner", planner_node)
    graph.add_edge(START, "recon")
    graph.add_edge("recon", "planner")
    graph.add_edge("planner", END)
    return graph.compile()


def build_full_graph_stub():
    """Skeleton showing where the remaining GateCounsel stages attach.

    planner_node  -> consumes state['sitemap'], emits testing tasks
    expert_nodes  -> per-vulnerability-class attack plans (RAG/LoRA)
    exploit_node  -> executes plans through the Scope Guard
    report_node   -> CVSS-scored findings
    """
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed; pip install langgraph")
    graph = StateGraph(GateCounselState)
    graph.add_node("recon", recon_node)
    graph.add_node("planner", planner_node)
    graph.add_edge(START, "recon")
    graph.add_edge("recon", "planner")
    graph.add_edge("planner", END)
    return graph.compile()


def run_recon(target: str, **kwargs: Any) -> dict[str, Any]:
    """Convenience runner used by the CLI when langgraph is available."""
    app = build_recon_graph()
    final: dict[str, Any] = {}
    for chunk in app.stream({"target": target, **kwargs}, stream_mode="updates"):
        for node_name, update in chunk.items():
            log.debug("node %s finished", node_name)
            final.update(update)
    return final


def run_recon_and_plan(target: str, **kwargs: Any) -> dict[str, Any]:
    """Run recon -> planner; returns combined state with sitemap and plan."""
    app = build_recon_planner_graph()
    final: dict[str, Any] = {}
    for chunk in app.stream({"target": target, **kwargs}, stream_mode="updates"):
        for node_name, update in chunk.items():
            log.debug("node %s finished", node_name)
            final.update(update)
    return final
