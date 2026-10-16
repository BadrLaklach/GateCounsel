"""Synthetic open-redirect ExpertVerdict cases based on the curated HackTricks note.

Source ID: HT-OPEN-REDIRECT-CORE. Redirects are inspected, never followed.
"""

VULN_CLASS = "open_redirect"

EXAMPLES = [
    {
        "task_id": "HT-OR-001",
        "endpoint_url": "http://demo-target/login",
        "method": "GET",
        "target_param": "return_to",
        "injection_point": "query",
        "recon_evidence": (
            "The local fixture returns a 302 after reading return_to. Its response currently uses "
            "the supplied value as Location; the executor is configured not to follow redirects."
        ),
        "planner_rationale": "Check whether the response emits the one pre-registered internal lab destination.",
        "retrieved_context": (
            "HT-OPEN-REDIRECT-CORE: inspect how the destination is validated and emitted in the "
            "first Location header. Validation and use should operate on the same parsed value."
        ),
        "approved_test_values": ["http://ssrf-sentinel/capture/HT-OR-001"],
        "payload": "http://ssrf-sentinel/capture/HT-OR-001",
        "expected_success_signal": (
            "The first response is a redirect and its Location value exactly matches the "
            "pre-registered http://ssrf-sentinel/capture/HT-OR-001 value. Do not issue a request to that Location."
        ),
        "confidence": 0.87,
        "reasoning": (
            "The fixture is documented to place return_to in Location, and the supplied destination "
            "is a fixed internal lab value. Inspecting the header without following it safely tests "
            "whether the destination control is enforced."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-OPEN-REDIRECT-CORE"],
    },
    {
        "task_id": "HT-OR-002",
        "endpoint_url": "http://demo-target/logout",
        "method": "GET",
        "target_param": "next",
        "injection_point": "query",
        "recon_evidence": (
            "The logout handler accepts a next parameter and returns a 302. Its documented "
            "application allowlist contains only the relative /dashboard route; the verifier "
            "captures the first response without navigation."
        ),
        "planner_rationale": "Check whether the handler rejects one unregistered origin from the fixture's exact same-origin allowlist.",
        "retrieved_context": (
            "HT-OPEN-REDIRECT-CORE: a strict allowlist should be checked against the canonical "
            "destination that is actually emitted. The first Location header is the relevant evidence."
        ),
        "approved_test_values": ["http://ssrf-sentinel/capture/HT-OR-002"],
        "payload": "http://ssrf-sentinel/capture/HT-OR-002",
        "expected_success_signal": (
            "A positive result is the first response emitting the exact unregistered "
            "http://ssrf-sentinel/capture/HT-OR-002 value in Location. A relative /dashboard "
            "redirect or an authorization-safe rejection is a negative result. Never follow Location."
        ),
        "confidence": 0.77,
        "reasoning": (
            "The response is compared with the fixture's exact same-origin allowlist. The one "
            "unregistered destination is still inside the isolated lab, and no normalization trick "
            "or redirect following is needed."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-OPEN-REDIRECT-CORE"],
    },
    {
        "task_id": "HT-OR-003",
        "endpoint_url": "http://demo-target/login",
        "method": "GET",
        "target_param": "return_to",
        "injection_point": "query",
        "recon_evidence": (
            "The fixture documents /dashboard as an approved same-origin destination and rejects "
            "unregistered origins. Redirect following is disabled."
        ),
        "planner_rationale": "Use the registered relative route as a benign control; same-origin navigation does not establish an open redirect.",
        "retrieved_context": (
            "HT-OPEN-REDIRECT-CORE: check the first Location value and compare it with the "
            "allowlist. A safe fixed relative destination is a negative control, not a vulnerability."
        ),
        "approved_test_values": ["/dashboard"],
        "payload": "/dashboard",
        "expected_success_signal": (
            "The first Location remains the exact approved same-origin /dashboard path. This is a "
            "negative control and must not be reported as an open redirect."
        ),
        "confidence": 0.97,
        "reasoning": (
            "The approved relative route checks the normal redirect path. It does not cross the "
            "origin boundary, so a matching Location supports the control rather than confirming a finding."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-OPEN-REDIRECT-CORE"],
    },
]
