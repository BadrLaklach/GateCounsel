#!/usr/bin/env python3
"""GateCounsel Recon Agent CLI.

Usage:
    python run_recon.py http://localhost:3000
    python run_recon.py http://localhost:3000 --username admin@juice-sh.op --password admin123
    python run_recon.py http://localhost:3000 --no-playwright --out sitemap.json --rps 2

Only run this against targets you are explicitly authorized to test
(see GateCounsel spec §9 — sanctioned lab applications only).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from agents.recon.recon_agent import ReconAgent

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
except ImportError:  # pragma: no cover
    RICH = False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gatecounsel-recon",
        description="GateCounsel Recon Agent — maps the attack surface of a sanctioned lab target.",
    )
    p.add_argument("target", help="Base URL of the target, e.g. http://localhost:3000")
    p.add_argument("--username", help="Operator-supplied login for the authenticated pass")
    p.add_argument("--password", help="Operator-supplied password for the authenticated pass")
    p.add_argument("--scope", action="append", default=[],
                   help="Extra sanctioned hosts/URLs (repeatable); the target is always in scope")
    p.add_argument("--out", default="sitemap.json", help="Output JSON path (default: sitemap.json)")
    p.add_argument("--max-pages", type=int, default=60, help="HTML page crawl cap (default: 60)")
    p.add_argument("--max-depth", type=int, default=3, help="BFS depth cap (default: 3)")
    p.add_argument("--rps", type=float, default=5.0, help="Max requests/second (default: 5)")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds")
    p.add_argument("--no-playwright", action="store_true", help="Skip the headless-browser pass")
    p.add_argument("--katana", action="store_true", help="Use Katana as an additional bounded discovery backend")
    p.add_argument("--katana-headless", action="store_true", help="Enable Katana browser mode (requires --katana)")
    p.add_argument("--katana-duration", type=int, default=60, help="Katana crawl duration cap in seconds (default: 60)")
    p.add_argument("--ai", action="store_true", help="Use Gemini to nominate extra safe GET paths (needs GEMINI_API_KEY)")
    p.add_argument("--gemini-model", default="gemini-3.5-flash-lite", help="Gemini model for --ai (default: gemini-3.5-flash-lite)")
    p.add_argument("--gemini-max-targets", type=int, default=8, help="Maximum AI-nominated paths to fetch (default: 8)")
    p.add_argument("--pin-dns", action="store_true", help="Pin target DNS IPs for the whole run")
    p.add_argument("--audit-log", default=None, help="JSONL path for the scope audit trail")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Only warnings/errors")
    return p


def print_summary(sitemap) -> None:
    if not RICH:
        print(f"[{sitemap.target}] endpoints={len(sitemap.endpoints)} "
              f"auth={sitemap.auth.authenticated} tech={len(sitemap.technologies)}")
        return
    console = Console()
    stats = sitemap.stats
    console.print(f"\n[bold cyan]GateCounsel Recon — {sitemap.target}[/]")
    console.print(
        f"  endpoints: [bold]{len(sitemap.endpoints)}[/]   pages: {stats.pages_crawled}   "
        f"requests: {stats.requests_made}   scope-blocked: {stats.scope_blocked}   "
        f"errors: {stats.errors}   time: {stats.duration_seconds}s"
    )
    console.print(
        f"  auth: {'[green]authenticated[/]' if sitemap.auth.authenticated else '[yellow]anonymous[/]'}"
        f"   token: {sitemap.auth.token_type or 'none detected'}"
        f"   protected endpoints: {len(sitemap.auth.protected_endpoints)}"
    )

    tech = Table(title="Technologies", show_header=True, header_style="bold")
    tech.add_column("Name"); tech.add_column("Category"); tech.add_column("Evidence", overflow="fold")
    for t in sitemap.technologies[:12]:
        tech.add_row(t.name, t.category, t.evidence)
    console.print(tech)

    table = Table(title=f"Top endpoints ({min(len(sitemap.endpoints), 20)} of {len(sitemap.endpoints)})")
    table.add_column("Method", style="bold cyan")
    table.add_column("URL", overflow="fold")
    table.add_column("Params", justify="right")
    table.add_column("Reflected", style="yellow", justify="right")
    table.add_column("Auth", justify="center")
    table.add_column("Status", justify="right")
    for ep in sitemap.endpoints[:20]:
        table.add_row(
            ep.method, ep.url, str(len(ep.params)), str(len(ep.reflected_params)),
            "yes" if ep.auth_required else ("?" if ep.auth_required is None else "no"),
            ",".join(map(str, ep.status_codes[:4])),
        )
    console.print(table)

    if sitemap.notes:
        console.print("[bold]Notes[/]")
        for n in sitemap.notes:
            console.print(f"  • {n}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
    )
    import urllib3
    urllib3.disable_warnings()
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    agent = ReconAgent(
        args.target,
        username=args.username,
        password=args.password,
        scope_targets=[args.target] + args.scope,
        config={
            "max_pages": args.max_pages,
            "max_depth": args.max_depth,
            "rps": args.rps,
            "timeout": args.timeout,
            "use_playwright": not args.no_playwright,
            "use_katana": args.katana,
            "katana_headless": args.katana_headless,
            "katana_duration": args.katana_duration,
            "use_gemini": args.ai,
            "gemini_model": args.gemini_model,
            "gemini_max_targets": args.gemini_max_targets,
            "pin_dns": args.pin_dns,
            "audit_log": args.audit_log,
        },
    )
    sitemap = agent.run()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(sitemap.model_dump_json(indent=2), encoding="utf-8")
    print_summary(sitemap)
    scope_block_rate = (
        sitemap.stats.scope_blocked / max(1, sitemap.stats.requests_made + sitemap.stats.scope_blocked)
    )
    if scope_block_rate > 0.5:
        print("WARNING: majority of attempted URLs were out of scope — check target URL.", file=sys.stderr)
    print(f"\nSite map written to {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
