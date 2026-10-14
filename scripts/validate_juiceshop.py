#!/usr/bin/env python3
"""Validate the recon agent against a running OWASP Juice Shop instance.

Prerequisite:
    docker compose -f lab/docker-compose.yml up -d
    (Juice Shop on http://localhost:3000)

Usage:
    python scripts/validate_juiceshop.py
    python scripts/validate_juiceshop.py --username admin@juice-sh.op --password admin123
    python scripts/validate_juiceshop.py --target http://localhost:3000 --no-playwright

Prints a checklist of what the recon agent was expected to discover on a
default Juice Shop build and exits non-zero if core expectations fail.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.recon.recon_agent import ReconAgent  # noqa: E402
from agents.recon.core.models import SiteMap  # noqa: E402

EXPECTED_URL_FRAGMENTS = [
    "/rest/products/search",   # XHR API captured by the browser pass
    "/rest/user/whoami",       # session-check API
    "/login",                  # login page
    "/search",                 # SPA search route
]
EXPECTED_TECH = ["Angular", "Express"]  # hints; body/header dependent
EXPECTED_LOGIN = True


def wait_for_target(url: str, timeout: float = 90.0) -> bool:
    import httpx
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=5.0, verify=False)
            if r.status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        print(f"  waiting for {url} ...")
        time.sleep(3)
    return False


def check(sitemap: SiteMap, username: str | None) -> tuple[int, int]:
    urls = [e.url for e in sitemap.endpoints]
    passed, failed = 0, 0

    def report(name: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not ok else ""))
        passed, failed = passed + (1 if ok else 0), failed + (0 if ok else 1)

    for frag in EXPECTED_URL_FRAGMENTS:
        report(f"endpoint *{frag}*", any(frag in u for u in urls))

    names = {t.name for t in sitemap.technologies}
    for tech in EXPECTED_TECH:
        report(f"technology hint '{tech}'", any(tech in n for n in names),
               f"found: {sorted(names)[:12]}")

    if not username:
        report("login surface detected", bool(sitemap.auth.login_candidates))
    else:
        report("authenticated pass", sitemap.auth.authenticated, str(sitemap.auth.login_strategy))

    report("endpoints discovered (>15)", len(sitemap.endpoints) > 15,
           f"only {len(sitemap.endpoints)}")
    report("scope blocked nothing legit", sitemap.stats.scope_blocked == 0)
    return passed, failed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--out", default="juiceshop_sitemap.json")
    parser.add_argument("--no-playwright", action="store_true")
    parser.add_argument("--skip-wait", action="store_true")
    args = parser.parse_args()

    print(f"== GateCounsel recon validation — {args.target} ==")
    if not args.skip_wait:
        print("waiting for the target to come up...")
        if not wait_for_target(args.target):
            print("target never became reachable — is the lab running?")
            return 2

    agent = ReconAgent(
        args.target,
        username=args.username,
        password=args.password,
        config={"use_playwright": not args.no_playwright, "rps": 4,
                "max_pages": 80, "max_depth": 3, "max_spa_routes": 20},
    )
    sitemap = agent.run()

    out = Path(args.out)
    out.write_text(sitemap.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nsite map saved to {out.resolve()} ({len(sitemap.endpoints)} endpoints)\n")

    passed, failed = check(sitemap, args.username)
    print(f"\n== {passed} passed, {failed} failed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
