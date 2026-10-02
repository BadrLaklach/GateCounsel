"""Hackbot orchestration graph (spec §10) — LangGraph pipeline definition.

Currently wires the recon stage end-to-end; the planner/expert/exploit/
reporting stages slot in as additional nodes on the same shared state.
Keep the node contract dict-shaped so each stage stays independently
testable (as demonstrated in tests/test_recon.py).
"""

from __future__ import annotations

import logging
from typing import Any

from agents.recon.recon_agent import ReconState, recon_node

log = logging.getLogger("hackbot.graph")

try:
    from langgraph.graph import END, START, StateGraph

    LANGGRAPH_AVAILABLE = True
except ImportError:  # graceful degradation — node functions still work
    LANGGRAPH_AVAILABLE = False


def build_recon_graph():
    """Graph: START -> recon -> END (planner hooks in right after recon)."""
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed; pip install langgraph")
    graph = StateGraph(ReconState)
    graph.add_node("recon", recon_node)
    graph.add_edge(START, "recon")
    graph.add_edge("recon", END)
    return graph.compile()


def build_full_graph_stub():
    """Skeleton showing where the remaining HACKBOT stages attach.

    planner_node  -> consumes state['sitemap'], emits testing tasks
    expert_nodes  -> per-vulnerability-class attack plans (RAG/LoRA)
    exploit_node  -> executes plans through the Scope Guard
    report_node   -> CVSS-scored findings
    """
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed; pip install langgraph")
    graph = StateGraph(ReconState)
    graph.add_node("recon", recon_node)
    # graph.add_node("planner", planner_node)      # TODO: milestone weeks 6-8
    # graph.add_node("experts", experts_node)      # TODO: milestone weeks 6-8
    # graph.add_node("exploit", exploit_node)      # TODO: milestone weeks 9-10
    # graph.add_node("report", report_node)        # TODO: milestone week 13
    graph.add_edge(START, "recon")
    graph.add_edge("recon", END)
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
