"""Scope Guard — Hackbot's single, non-bypassable safety checkpoint.

Design principle (per HACKBOT spec §9):
    This is plain, deterministic code — NOT an LLM call — so its behavior
    is guaranteed and independently testable, not just "probably safe".

Every network-facing component (Recon Agent, Exploit Agent, browser
crawler) must route every single request through a ScopeGuard instance.
Anything that does not match the operator-declared allow-list is refused
*before* it touches the network, and the refusal is written to an audit
trail for post-run review.

Usage:
    guard = ScopeGuard(["http://localhost:3000"])
    guard.enforce("http://localhost:3000/rest/products")   # ok
    guard.enforce("http://evil.internal/")                  # raises ScopeViolationError

Thread-safe. Fails closed. No exceptions for "trusted" callers.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

__all__ = ["ScopeGuard", "ScopeDecision", "ScopeViolationError"]


class ScopeViolationError(PermissionError):
    """Raised when an action targets a host outside the sanctioned allow-list."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"SCOPE VIOLATION blocked '{url}': {reason}")


@dataclass(frozen=True)
class ScopeDecision:
    """Result of checking a URL against the allow-list."""

    allowed: bool
    reason: str
    url: str


def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


class ScopeGuard:
    """Deterministic allow-list of sanctioned targets.

    Parameters
    ----------
    targets:
        Sanctioned target URLs or ``host[:port]`` strings, declared by the
        human operator *before* the run starts. If a target is given with an
        explicit port, only that port is allowed on that host; without a
        port, any port on that host is allowed.
    allow_subdomains:
        If True, subdomains of a registered hostname are also allowed
        (default False — strictest behavior).
    pin_dns:
        If True, each registered hostname is resolved once at registration
        and every subsequent check re-resolves the host and compares the
        IPs — a lightweight defence against DNS rebinding mid-run.
        Fail-closed: a host that stops resolving is blocked.
    audit_log:
        Path to a JSONL file. Every check (allowed AND blocked) is appended,
        giving the full audit trail required by the project spec.
    """

    def __init__(
        self,
        targets: list[str] | tuple[str, ...] | None = None,
        *,
        allow_subdomains: bool = False,
        pin_dns: bool = False,
        audit_log: str | Path | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._allowed: dict[str, set[int | None]] = {}  # host -> allowed ports (None = any)
        self.allow_subdomains = allow_subdomains
        self.pin_dns = pin_dns
        self._pinned_ips: dict[str, set[str]] = {}
        self.audit_log = Path(audit_log) if audit_log else None
        self.counters = {"allowed": 0, "blocked": 0}

        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)

        for t in targets or []:
            self.register(t)

    # ------------------------------------------------------------------ #
    # Registration
    # ------------------------------------------------------------------ #
    def register(self, target: str) -> None:
        """Add a sanctioned target. Accepts URL or host[:port] form."""
        raw = (target or "").strip()
        if not raw:
            raise ValueError("Empty scope target")
        if "://" not in raw:
            raw = "http://" + raw  # host[:port] shorthand

        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Scope target must be http/https, got scheme '{scheme}'")
        if not parts.hostname:
            raise ValueError(f"Cannot parse host from scope target '{target}'")

        host = _normalize_host(parts.hostname)
        port: int | None = parts.port  # None => any port on this host

        with self._lock:
            ports = self._allowed.setdefault(host, set())
            ports.add(port)
            if self.pin_dns:
                self._pinned_ips[host] = self._resolve(host)

    def register_many(self, targets) -> None:
        for t in targets:
            self.register(t)

    @staticmethod
    def _resolve(host: str) -> set[str]:
        try:
            infos = socket.getaddrinfo(host, None)
            return {info[4][0] for info in infos}
        except OSError:
            return set()

    # ------------------------------------------------------------------ #
    # Checking
    # ------------------------------------------------------------------ #
    def check(self, url: str) -> ScopeDecision:
        """Check a URL. Pure function of state + URL — no I/O except pin_dns."""
        decision = self._decide(url)
        with self._lock:
            key = "allowed" if decision.allowed else "blocked"
            self.counters[key] += 1
        self._audit(decision)
        return decision

    def enforce(self, url: str) -> ScopeDecision:
        """Check a URL and raise :class:`ScopeViolationError` when blocked."""
        decision = self.check(url)
        if not decision.allowed:
            raise ScopeViolationError(url, decision.reason)
        return decision

    def is_allowed(self, url: str) -> bool:
        return self.check(url).allowed

    def _decide(self, url: str) -> ScopeDecision:
        try:
            parts = urlsplit(str(url))
        except ValueError:
            return ScopeDecision(False, f"unparseable URL: {url!r}", str(url))

        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            return ScopeDecision(False, f"scheme '{scheme or 'none'}' not allowed (http/https only)", str(url))

        host = _normalize_host(parts.hostname or "")
        if not host:
            return ScopeDecision(False, "missing host", str(url))

        if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".localhost"):
            pass  # valid lab hosts, still require registration below
        try:
            port: int | None = parts.port
        except ValueError:
            return ScopeDecision(False, f"invalid port in URL: {url!r}", str(url))

        with self._lock:
            # 1) exact host match
            ports = self._allowed.get(host)
            matched_host = host if ports is not None else None

            # 2) subdomain match (opt-in)
            if matched_host is None and self.allow_subdomains:
                for reg_host, reg_ports in self._allowed.items():
                    if host.endswith("." + reg_host):
                        matched_host, ports = reg_host, reg_ports
                        break

            if matched_host is None:
                return ScopeDecision(False, f"host '{host}' not in allow-list", str(url))

            if ports and None not in ports and port not in ports:
                allowed_repr = ", ".join(str(p) for p in sorted(p for p in ports if p is not None))
                return ScopeDecision(False, f"port {port} not allowed on '{matched_host}' (allowed: {allowed_repr})", str(url))

            if self.pin_dns:
                current = self._resolve(host)
                pinned = self._pinned_ips.get(matched_host, set())
                if not current or not (current & pinned):
                    return ScopeDecision(
                        False,
                        f"DNS pinning mismatch for '{host}' (pinned={sorted(pinned)}, now={sorted(current)})",
                        str(url),
                    )

        return ScopeDecision(True, "in scope", str(url))

    # ------------------------------------------------------------------ #
    # Audit trail
    # ------------------------------------------------------------------ #
    def _audit(self, decision: ScopeDecision) -> None:
        if not self.audit_log:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "url": decision.url,
            "allowed": decision.allowed,
            "reason": decision.reason,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            with self.audit_log.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    # ------------------------------------------------------------------ #
    # Introspection helpers (used by the reporting agent / tests)
    # ------------------------------------------------------------------ #
    def summary(self) -> dict:
        with self._lock:
            return {
                "targets": {h: sorted(p for p in ps if p is not None) if ps and None not in ps else "any"
                            for h, ps in self._allowed.items()},
                "allow_subdomains": self.allow_subdomains,
                "pin_dns": self.pin_dns,
                "counters": dict(self.counters),
            }

    def __repr__(self) -> str:  # pragma: no cover
        with self._lock:
            hosts = ", ".join(sorted(self._allowed)) or "<empty>"
        return f"ScopeGuard([{hosts}], subdomains={self.allow_subdomains}, pin_dns={self.pin_dns})"


def guard_from_targets(targets, audit_log: str | Path | None = None) -> ScopeGuard:
    """Convenience factory used by the recon/exploit agents."""
    return ScopeGuard(targets=targets, audit_log=audit_log)
