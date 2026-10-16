"""Synthetic SSRF ExpertVerdict cases based on curated HackTricks notes.

Source IDs: HT-SSRF-CORE, HT-SSRF-URL-PARSING. Sentinel-only; no public destinations.
"""

VULN_CLASS = "ssrf"

EXAMPLES = [
    {
        "task_id": "HT-SSRF-001",
        "endpoint_url": "http://demo-target/preview",
        "method": "GET",
        "target_param": "url",
        "injection_point": "query",
        "recon_evidence": (
            "The local preview feature performs a server-side HTTP fetch. Its fixture policy "
            "allows only the exact Compose service ssrf-sentinel and the /capture/<case-id> route."
        ),
        "planner_rationale": "Verify server-originated fetch behavior with one unique event at the approved lab receiver.",
        "retrieved_context": (
            "HT-SSRF-CORE: a server-side interaction at a controlled receiver distinguishes SSRF "
            "from a URL merely reflected to the client. HT-SSRF-URL-PARSING: validate the canonical "
            "destination and re-check redirects."
        ),
        "approved_test_values": ["http://ssrf-sentinel/capture/HT-SSRF-001"],
        "payload": "http://ssrf-sentinel/capture/HT-SSRF-001",
        "expected_success_signal": (
            "The sentinel's local event log records exactly one request for case HT-SSRF-001 from "
            "the demo target. The test does not require or return sentinel response contents."
        ),
        "confidence": 0.88,
        "reasoning": (
            "Recon confirms that the server fetches this parameter and the destination is the one "
            "explicitly allowed lab receiver. A unique sentinel event is direct evidence of the "
            "server-side request without accessing another service."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-SSRF-CORE", "HT-SSRF-URL-PARSING"],
    },
    {
        "task_id": "HT-SSRF-002",
        "endpoint_url": "http://demo-target/image-info",
        "method": "GET",
        "target_param": "source_url",
        "injection_point": "query",
        "recon_evidence": (
            "The response does not show fetched content, but the fixture's documented image-info "
            "handler fetches one URL server-side. Redirects are disabled for this route."
        ),
        "planner_rationale": "A response-body check is unavailable; use a unique, controlled sentinel receipt as the evidence channel.",
        "retrieved_context": (
            "HT-SSRF-CORE: capture a controlled server-originated interaction when the response is "
            "blind. HT-SSRF-URL-PARSING: keep destination parsing canonical and reject redirects."
        ),
        "approved_test_values": ["http://ssrf-sentinel/capture/HT-SSRF-002"],
        "payload": "http://ssrf-sentinel/capture/HT-SSRF-002",
        "expected_success_signal": (
            "The sentinel event log records case HT-SSRF-002 with the demo-target source identity. "
            "No event means this test did not confirm SSRF; response timing alone is insufficient."
        ),
        "confidence": 0.84,
        "reasoning": (
            "The known server-side fetch and a unique sentinel receipt provide a bounded signal "
            "even when content is not reflected. The approved URL is canonical and uses the only "
            "permitted destination."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-SSRF-CORE", "HT-SSRF-URL-PARSING"],
    },
    {
        "task_id": "HT-SSRF-003",
        "endpoint_url": "http://demo-target/link-check",
        "method": "GET",
        "target_param": "candidate_url",
        "injection_point": "query",
        "recon_evidence": (
            "Recon found that candidate_url is displayed in a page, but server-side fetching has "
            "not yet been established. The test target includes a safe fetch operation restricted to ssrf-sentinel."
        ),
        "planner_rationale": "Reflection is not SSRF proof; use one documented safe server-fetch operation and require a receiver-side event.",
        "retrieved_context": (
            "HT-SSRF-CORE: SSRF requires a request made by the server, not just a URL echoed to a "
            "browser. Use a controlled receiver to establish the origin of the request."
        ),
        "approved_test_values": ["http://ssrf-sentinel/capture/HT-SSRF-003"],
        "payload": "http://ssrf-sentinel/capture/HT-SSRF-003",
        "expected_success_signal": (
            "Positive only if the sentinel records case HT-SSRF-003 as a request from the target "
            "server. Client-side rendering of the URL without a sentinel event is not confirmation."
        ),
        "confidence": 0.68,
        "reasoning": (
            "The current evidence is only reflection, so the verdict must not claim SSRF. This "
            "single approved sentinel URL can resolve the uncertainty if the local fetch operation "
            "actually sends a server-side request."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-SSRF-CORE"],
    },
]
