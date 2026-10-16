"""Synthetic reflected-XSS ExpertVerdict cases based on the curated HackTricks notes.

Source IDs: HT-XSS-CORE, HT-XSS-DOM. All endpoints and canaries are local-lab only.
"""

VULN_CLASS = "xss_reflected"

EXAMPLES = [
    {
        "task_id": "HT-XSS-001",
        "endpoint_url": "http://demo-target/search",
        "method": "GET",
        "target_param": "q",
        "injection_point": "query",
        "recon_evidence": (
            "The synthetic search term is inserted unescaped into an HTML text context in the "
            "initial server response. The fixture allows inline script execution and has no "
            "external network route."
        ),
        "planner_rationale": "A reflected value reaches raw HTML; a context-matched browser canary can test whether it executes.",
        "retrieved_context": (
            "HT-XSS-CORE: reflection alone is only a candidate; identify the output context and "
            "confirm execution in the browser. HT-XSS-DOM: trace controlled data to the final "
            "rendering or execution sink."
        ),
        "approved_test_values": [
            "<script>document.documentElement.dataset.gcTest='HT-XSS-001'</script>"
        ],
        "payload": "<script>document.documentElement.dataset.gcTest='HT-XSS-001'</script>",
        "expected_success_signal": (
            "The headless browser observes document.documentElement.dataset.gcTest equal to "
            "HT-XSS-001. The canary performs no reads and makes no requests."
        ),
        "confidence": 0.86,
        "reasoning": (
            "The recon evidence places the value in raw HTML before browser parsing, so a single "
            "allowlisted canary can distinguish execution from text reflection. Only the local "
            "DOM marker is relevant evidence."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-XSS-CORE", "HT-XSS-DOM"],
    },
    {
        "task_id": "HT-XSS-002",
        "endpoint_url": "http://demo-target/profile/search",
        "method": "GET",
        "target_param": "term",
        "injection_point": "query",
        "recon_evidence": (
            "The value is reflected inside a quoted value attribute on a fixture input. The "
            "fixture's browser test focuses that input once after navigation."
        ),
        "planner_rationale": "The attribute context must be assessed separately from raw HTML text.",
        "retrieved_context": (
            "HT-XSS-CORE: determine which HTML context receives the value before selecting a test. "
            "HT-XSS-DOM: use the final browser behavior, not a string match, as the signal."
        ),
        "approved_test_values": [
            "\" autofocus onfocus=\"document.documentElement.dataset.gcTest='HT-XSS-002'"
        ],
        "payload": "\" autofocus onfocus=\"document.documentElement.dataset.gcTest='HT-XSS-002'",
        "expected_success_signal": (
            "After the fixture focuses the input, the browser observes the HT-XSS-002 DOM marker. "
            "The marker handler must not access page data or make a network request."
        ),
        "confidence": 0.78,
        "reasoning": (
            "The evidence identifies a quoted attribute and the fixture supplies the focus event. "
            "This one approved canary tests that specific context without probing other users or origins."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-XSS-CORE", "HT-XSS-DOM"],
    },
    {
        "task_id": "HT-XSS-003",
        "endpoint_url": "http://demo-target/search-safe",
        "method": "GET",
        "target_param": "q",
        "injection_point": "query",
        "recon_evidence": (
            "A benign search marker is reflected, and the response HTML shows angle brackets "
            "encoded as text. The browser displays the marker literally."
        ),
        "planner_rationale": "Reflection is present, but current evidence suggests contextual encoding; test only the local canary and require execution evidence.",
        "retrieved_context": (
            "HT-XSS-CORE: reflected input is not proof of XSS; context and browser interpretation "
            "matter. Encoded output should remain text."
        ),
        "approved_test_values": [
            "<script>document.documentElement.dataset.gcTest='HT-XSS-003'</script>"
        ],
        "payload": "<script>document.documentElement.dataset.gcTest='HT-XSS-003'</script>",
        "expected_success_signal": (
            "Only execution of the canary and observation of the HT-XSS-003 DOM marker would be "
            "positive. If the browser displays escaped text and the marker is absent, do not confirm XSS."
        ),
        "confidence": 0.10,
        "reasoning": (
            "The current observation supports safe text encoding, so reflection alone should not "
            "be treated as a finding. The single local canary provides a bounded check; the verifier "
            "must leave the case unconfirmed if it remains text."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-XSS-CORE"],
    },
]
