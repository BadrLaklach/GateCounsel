"""OpenAI-compatible chat client for the GateCounsel planner LLM layer.

Talks HTTP to any `/chat/completions` endpoint (Gemini's OpenAI-compat
surface, OpenAI, local vLLM/Ollama). Uses httpx — the same stack as recon —
so the planner does not depend on the `openai` package.

Auth is resolved from explicit config, process env, then a local `.env` file
(same pattern as recon's Gemini planner). Missing keys mean "no LLM", not an
error: the planner stays rules-only.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import httpx

log = logging.getLogger("gatecounsel.llm")

GEMINI_OPENAI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_MODEL = "gemini-3.5-flash-lite"
DEFAULT_TIMEOUT = 25.0

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)
_ENV_KEY_NAMES = ("LLM_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY")


def _dotenv_value(name: str, path: Path) -> str | None:
    """Read one named value from a .env file without mutating os.environ."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep or key.strip() != name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        return value or None
    return None


def _repo_dotenv_paths() -> list[Path]:
    here = Path(__file__).resolve()
    # agents/planner/client/llm_client.py -> repo root is parents[3]
    return [Path.cwd() / ".env", here.parents[3] / ".env"]


def _resolve_secret(name: str) -> str | None:
    env = os.environ.get(name)
    if env:
        return env
    seen: set[Path] = set()
    for path in _repo_dotenv_paths():
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        value = _dotenv_value(name, path)
        if value:
            return value
    return None


def llm_config_from_env(
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> dict[str, str] | None:
    """Resolve LLM settings from args, env, then .env. None = no LLM."""
    key = api_key
    if not key:
        for name in _ENV_KEY_NAMES:
            key = _resolve_secret(name)
            if key:
                break
    if not key:
        return None
    return {
        "base_url": (base_url or os.environ.get("LLM_BASE_URL") or GEMINI_OPENAI_BASE),
        "api_key": key,
        "model": model or os.environ.get("LLM_MODEL") or DEFAULT_MODEL,
    }


def strip_code_fences(text: str) -> str:
    """Remove a single ```json ... ``` wrapper some models add around JSON."""
    m = _FENCE_RE.match(text.strip())
    return m.group(1) if m else text.strip()


def _object_span(text: str, start: int) -> str | None:
    """Return the substring of the first complete `{...}` object at start."""
    if start < 0 or start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort: parse a JSON object from a model reply (fences / prose)."""
    if not text or not text.strip():
        return None
    cleaned = strip_code_fences(text)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    snippet = _object_span(cleaned, start)
    if not snippet:
        return None
    try:
        parsed = json.loads(snippet)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
        joined = "".join(parts).strip()
        if joined:
            return joined
    raise ValueError("LLM response content is empty or not text")


class LLMClient:
    """Thin synchronous chat-completions wrapper."""

    def __init__(self, config: dict[str, str], timeout: float = DEFAULT_TIMEOUT) -> None:
        self.base_url = config["base_url"].rstrip("/") + "/"
        self.api_key = config["api_key"]
        self.model = config["model"]
        self.timeout = max(1.0, float(timeout))
        self._client: Optional[httpx.Client] = None

    def complete(self, system: str, user: str, temperature: float = 0.2,
                 max_tokens: int = 2000) -> str:
        """One-shot chat completion; returns assistant text content."""
        if self._client is None:
            self._client = httpx.Client(timeout=httpx.Timeout(self.timeout))
        url = self.base_url + "chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        resp = self._client.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValueError(
                f"LLM HTTP {exc.response.status_code} from {self.model}"
            ) from None
        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise ValueError("LLM response is not JSON") from exc
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(f"unexpected LLM response shape: {exc}") from exc
        if not isinstance(message, dict):
            raise ValueError("unexpected LLM response shape: message")
        return _message_text(message)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "LLMClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
