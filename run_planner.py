#!/usr/bin/env python3
"""Hackbot Planner CLI — turn a recon site map into a prioritized attack plan.

Usage:
    python run_planner.py sitemap.json --out plan.json
    python run_planner.py sitemap.json --no-llm --max-tasks 20 --min-priority 40
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from agents.planner import AttackPlanner, PlannerConfig
from agents.recon.core.models import SiteMap


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hackbot-planner",
        description="Plan attack tasks from a Hackbot recon site map.",
    )
    p.add_argument("sitemap", help="Path to a sitemap.json produced by run_recon.py")
    p.add_argument("--out", default="plan.json", help="Output plan JSON path (default: plan.json)")
    p.add_argument("--max-tasks", type=int, default=40, help="Cap on number of planned tasks (default: 40)")
    p.add_argument("--min-priority", type=int, default=0, help="Drop tasks scoring below this (0-100)")
    p.add_argument("--no-llm", action="store_true", help="Skip the LLM re-ranking pass (rules only)")
    p.add_argument("--llm-model", default=None, help="Override LLM model (default: gemini-3.5-flash-lite)")
    p.add_argument("--llm-base-url", default=None, help="Override OpenAI-compatible base URL")
    p.add_argument("--llm-timeout", type=float, default=25.0, help="LLM request timeout seconds")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Only warnings/errors")
    return p


def _print_table(plan) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for t in plan.tasks:
            print(f"[{t.id}] {t.priority:>3} {t.band:<8} {t.vuln_class:<14} "
                  f"{t.risk_tier:<12} {t.method} {t.endpoint_url} ({', '.join(t.target_params)})")
        return
    console = Console()
    table = Table(title=f"Attack Plan — {plan.target} ({plan.summary.total_tasks} tasks)")
    table.add_column("ID", style="dim")
    table.add_column("PRI", justify="right")
    table.add_column("Band")
    table.add_column("Class")
    table.add_column("Tier")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Params", overflow="fold")
    band_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for t in plan.tasks:
        table.add_row(
            t.id,
            str(t.priority),
            f"[{band_style[t.band]}]{t.band}[/]",
            t.vuln_class,
            "review" if t.risk_tier == "needs_review" else "safe",
            f"{t.method} {t.endpoint_url}",
            ", ".join(t.target_params),
        )
    console.print(table)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else (logging.WARNING if args.quiet
                                                                 else logging.INFO),
                        format="%(levelname)s %(name)s: %(message)s")

    path = Path(args.sitemap)
    if not path.exists():
        print(f"error: sitemap not found: {path}", file=sys.stderr)
        return 2
    sitemap = SiteMap.model_validate(json.loads(path.read_text(encoding="utf-8")))

    config: PlannerConfig = {
        "max_tasks": args.max_tasks,
        "min_priority": args.min_priority,
        "llm_timeout": args.llm_timeout,
    }
    if args.no_llm:
        config["use_llm"] = False
    if args.llm_model:
        config["llm_model"] = args.llm_model
    if args.llm_base_url:
        config["llm_base_url"] = args.llm_base_url

    planner = AttackPlanner(config)
    try:
        plan = planner.plan(sitemap)
    finally:
        planner.close()

    out_path = Path(args.out)
    out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    _print_table(plan)

    mode = f"LLM: {plan.llm_model}" if plan.llm_used else "rules-only"
    print(f"\n{plan.summary.total_tasks} tasks "
          f"(critical: {plan.summary.by_band.get('critical', 0)}, "
          f"high: {plan.summary.by_band.get('high', 0)}, "
          f"needs review: {plan.summary.needs_review}) — {mode}")
    print(f"plan written to {out_path}")
    for note in plan.notes:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
