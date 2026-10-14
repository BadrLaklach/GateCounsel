"""Optional ProjectDiscovery Katana crawler adapter.

Katana runs as a separate process, so it is constrained with its own exact
origin crawl scope and bounded rate/depth/duration.  Its JSONL findings are
also checked against GateCounsel's ScopeGuard before they enter the site map.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from agents.recon.crawlers.crawler import normalize_key
from agents.recon.core.models import Endpoint

log = logging.getLogger("gatecounsel.katana")


@dataclass
class KatanaResult:
    endpoints: dict[tuple[str, str], Endpoint] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    ran: bool = False


class KatanaCrawler:
    """Run Katana with strict bounds and translate JSONL into endpoints.

    Standard mode is the default. Headless mode must be deliberately enabled,
    because JavaScript executing in a page can itself create network traffic.
    """

    def __init__(
        self,
        base_url: str,
        *,
        is_allowed: Callable[[str], bool],
        max_depth: int = 3,
        max_pages: int = 60,
        rps: float = 5.0,
        duration_seconds: int = 60,
        headless: bool = False,
        executable: str = "katana",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.is_allowed = is_allowed
        self.max_depth = max(0, max_depth)
        self.max_records = max(1, max_pages * 4)
        self.rps = max(1, int(rps))
        self.duration_seconds = max(5, duration_seconds)
        self.headless = headless
        self.executable = executable

    def command(self) -> list[str]:
        """Build the command without a shell; safe to inspect in tests/logs."""
        parts = urlsplit(self.base_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        # Katana receives an exact origin regex as a second independent scope.
        scope_regex = "^" + re.escape(origin) + r"(?:/|$)"
        cmd = [
            self.executable, "-u", self.base_url, "-silent", "-jsonl",
            "-d", str(self.max_depth), "-jc", "-rl", str(self.rps),
            "-ct", f"{self.duration_seconds}s", "-fs", "fqdn", "-cs", scope_regex,
        ]
        if self.headless:
            cmd.extend(["-headless", "-xhr"])
        return cmd

    def run(self) -> KatanaResult:
        result = KatanaResult()
        if not shutil.which(self.executable):
            result.notes.append("Katana skipped: executable not found on PATH")
            return result
        if not self.is_allowed(self.base_url):
            result.notes.append("Katana skipped: target is outside declared scope")
            return result

        try:
            completed = subprocess.run(
                self.command(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.duration_seconds + 15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.notes.append("Katana stopped: crawl duration limit reached")
            return result
        except OSError as exc:
            result.notes.append(f"Katana skipped: {type(exc).__name__}")
            return result

        result.ran = True
        for line in completed.stdout.splitlines()[:self.max_records]:
            endpoint = self._parse_line(line)
            if endpoint is None or not self.is_allowed(endpoint.url):
                continue
            key = normalize_key(endpoint.method, endpoint.url)
            if key in result.endpoints:
                result.endpoints[key].merge(endpoint)
            else:
                result.endpoints[key] = endpoint
        if completed.returncode not in (0, None):
            detail = completed.stderr.strip().splitlines()[-1:] or [f"exit code {completed.returncode}"]
            result.notes.append(f"Katana exited with code {completed.returncode}: {detail[0][:180]}")
        result.notes.append(f"Katana discovered {len(result.endpoints)} in-scope endpoint(s)")
        return result

    def _parse_line(self, line: str) -> Endpoint | None:
        try:
            record = json.loads(line)
        except ValueError:
            return None
        if not isinstance(record, dict):
            return None
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        url = request.get("endpoint") or request.get("url") or record.get("endpoint") or record.get("url")
        method = str(request.get("method") or record.get("method") or "GET").upper()
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return None
        status = response.get("status_code") or response.get("status") or record.get("status_code")
        statuses = [status] if isinstance(status, int) else []
        headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
        content_type = headers.get("content-type") or headers.get("Content-Type")
        return Endpoint(
            url=url, method=method, status_codes=statuses,
            content_type=str(content_type).split(";", 1)[0].lower() if content_type else None,
            discovered_via="katana", notes="discovered by Katana",
        )
