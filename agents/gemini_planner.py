"""Bounded Gemini planning for the reconnaissance stage.

Gemini can nominate a small set of additional, safe GET paths from a redacted
endpoint inventory. It has no direct network access: the recon agent validates
every suggestion through the deterministic Scope Guard before fetching it.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from agents.models import Endpoint

log = logging.getLogger("hackbot.gemini")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
MAX_MODEL_CANDIDATES = 20


def _dotenv_key(name: str, path: Path | None = None) -> str | None:
    """Read one named value from a local .env file without replacing env vars."""
    dotenv_path = path or Path.cwd() / ".env"
    try:
        lines = dotenv_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if separator and key.strip() == name:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            return value or None
    return None


@dataclass(frozen=True)
class PlannedTarget:
    """A model-suggested path, retained with its explanation for auditability."""

    path: str
    reason: str


class GeminiReconPlanner:
    """Ask Gemini for a small, evidence-based list of safe recon targets."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_GEMINI_MODEL,
        api_key: str | None = None,
        timeout: float = 20.0,
        max_targets: int = 8,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or _dotenv_key("GEMINI_API_KEY")
        self.timeout = max(1.0, timeout)
        self.max_targets = max(1, min(max_targets, MAX_MODEL_CANDIDATES))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def plan(self, target: str, endpoints: list[Endpoint], technologies: list[str] | None = None) -> tuple[list[PlannedTarget], str | None]:
        """Return model suggestions or a non-fatal status message."""
        if not self.configured:
            return [], "AI planning skipped: GEMINI_API_KEY is not set"

        payload = self._payload(target, endpoints, technologies or [])
        try:
            url = GEMINI_API_URL.format(model=quote(self.model, safe="-_ .".replace(" ", "")))
            with httpx.Client(timeout=self.timeout, verify=True) as client:
                response = client.post(
                    url,
                    headers={"x-goog-api-key": self.api_key},
                    json={
                        "system_instruction": {"parts": [{"text": self._system_prompt()}]},
                        "contents": [{"role": "user", "parts": [{
                            "text": json.dumps(payload, separators=(",", ":")),
                        }]}],
                        "generationConfig": {
                            "temperature": 0.2,
                            "maxOutputTokens": 900,
                            "responseMimeType": "application/json",
                        },
                    },
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("Gemini planning unavailable: %s", exc)
            return [], f"AI planning skipped: {type(exc).__name__}"

        try:
            parts = data["candidates"][0]["content"]["parts"]
            content = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
            return self._parse(content), None
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            log.warning("Invalid Gemini planning response: %s", exc)
            return [], "AI planning skipped: invalid model response"

    def _payload(self, target: str, endpoints: list[Endpoint], technologies: list[str]) -> dict[str, Any]:
        """Produce a deliberately redacted, structural-only model input."""
        inventory = []
        for endpoint in endpoints[:250]:
            inventory.append({
                "url": endpoint.url,
                "method": endpoint.method,
                "status_codes": endpoint.status_codes[:4],
                "content_type": endpoint.content_type,
                "auth_required": endpoint.auth_required,
                "params": [{"name": p.name, "location": p.location, "type": p.type_hint}
                           for p in endpoint.params[:20]],
                "discovered_via": endpoint.discovered_via,
            })
        return {
            "target": target,
            "technologies": technologies[:20],
            "endpoints": inventory,
            "request": "Suggest up to %d additional likely application paths to inspect." % self.max_targets,
        }

    def _system_prompt(self) -> str:
        return (
            "You are a web-application reconnaissance planner for an explicitly authorized target. "
            "Use only the supplied structural inventory. Return JSON only, with this exact shape: "
            '{"candidates":[{"path":"/path","reason":"brief evidence-based reason"}]}. '
            "Suggest at most %d candidates. Each path must be a relative path beginning with '/', "
            "contain no query string, fragment, scheme, host, credentials, traversal, or payload. "
            "Do not suggest state-changing actions, authentication attempts, or exploitation."
        ) % self.max_targets

    def _parse(self, content: Any) -> list[PlannedTarget]:
        if not isinstance(content, str):
            raise ValueError("model content is not text")
        text = content.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text[:-3]
        raw = json.loads(text)
        candidates = raw.get("candidates", []) if isinstance(raw, dict) else []
        out: list[PlannedTarget] = []
        for item in candidates[:self.max_targets]:
            if not isinstance(item, dict):
                continue
            path, reason = item.get("path"), item.get("reason", "")
            if isinstance(path, str) and isinstance(reason, str):
                out.append(PlannedTarget(path=path.strip(), reason=reason.strip()[:240]))
        return out
