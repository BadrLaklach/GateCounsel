"""Synthetic IDOR/BOLA ExpertVerdict cases based on the curated HackTricks note.

Source ID: HT-IDOR-CORE. Cases use one read-only request and seeded records only.
"""

VULN_CLASS = "idor"

EXAMPLES = [
    {
        "task_id": "HT-IDOR-001",
        "endpoint_url": "http://demo-target/api/orders",
        "method": "GET",
        "target_param": "order_id",
        "injection_point": "query",
        "recon_evidence": (
            "The fixture provides authenticated principal lab-user-a, which owns LAB-ORDER-A. "
            "LAB-ORDER-B is a known synthetic record owned by lab-user-b and contains only a "
            "non-sensitive marker. No other IDs are in scope."
        ),
        "planner_rationale": "The request selects an object by caller-supplied ID; compare one known foreign fixture under the same principal.",
        "retrieved_context": (
            "HT-IDOR-CORE: keep the same authenticated principal and change only one known object "
            "identifier. Confirm only if server-side object authorization fails for that specific fixture."
        ),
        "approved_test_values": ["LAB-ORDER-B"],
        "payload": "LAB-ORDER-B",
        "expected_success_signal": (
            "Under lab-user-a, the response returns the seeded LAB-ORDER-B marker owned by "
            "lab-user-b. A denial such as 403/404 or an empty authorization-safe response is not confirmation."
        ),
        "confidence": 0.84,
        "reasoning": (
            "The other fixture's ID is explicitly seeded and the caller identity stays fixed, so "
            "the single comparison isolates object-level authorization. The operation is read-only "
            "and cannot enumerate unrelated orders."
        ),
        "alternate_payloads": [],
        "requires_auth_context": True,
        "retrieved_sources": ["HT-IDOR-CORE"],
    },
    {
        "task_id": "HT-IDOR-002",
        "endpoint_url": "http://demo-target/api/profile",
        "method": "GET",
        "target_param": "user_id",
        "injection_point": "query",
        "recon_evidence": (
            "The test session belongs to lab-user-a. The target fixture documents lab-user-b as a "
            "different seeded identity; the profile response contains only synthetic display labels."
        ),
        "planner_rationale": "A user identifier may be selecting another principal's profile without an object-level ownership check.",
        "retrieved_context": (
            "HT-IDOR-CORE: identifiers can occur in query parameters, and authorization must be "
            "checked server-side for the requested object. Use a single known test identity pair."
        ),
        "approved_test_values": ["lab-user-b"],
        "payload": "lab-user-b",
        "expected_success_signal": (
            "The authenticated lab-user-a session receives the synthetic profile marker for "
            "lab-user-b without an authorization grant. Do not treat status code alone as proof; "
            "compare the fixture owner and response marker."
        ),
        "confidence": 0.81,
        "reasoning": (
            "Only the seeded user ID changes while the session remains lab-user-a. The response "
            "must be compared with the fixture ownership map; no real identity data is present."
        ),
        "alternate_payloads": [],
        "requires_auth_context": True,
        "retrieved_sources": ["HT-IDOR-CORE"],
    },
    {
        "task_id": "HT-IDOR-003",
        "endpoint_url": "http://demo-target/api/projects",
        "method": "GET",
        "target_param": "project_id",
        "injection_point": "query",
        "recon_evidence": (
            "The low-privilege lab-user-a session is a viewer on LAB-PROJECT-A. LAB-PROJECT-B is "
            "seeded as owned by lab-user-b, and the fixture's ground-truth file says lab-user-a "
            "has no membership there."
        ),
        "planner_rationale": "A known project object reference can test whether the server enforces membership for this principal.",
        "retrieved_context": (
            "HT-IDOR-CORE: test object-level authorization with a low-privilege session and one "
            "known object owned by another test identity; do not enumerate an identifier space."
        ),
        "approved_test_values": ["LAB-PROJECT-B"],
        "payload": "LAB-PROJECT-B",
        "expected_success_signal": (
            "The response contains the designated non-sensitive LAB-PROJECT-B marker for "
            "lab-user-a despite the fixture's no-membership ground truth. If access is denied, "
            "the check is negative."
        ),
        "confidence": 0.82,
        "reasoning": (
            "The known ground-truth membership state makes this a direct one-object authorization "
            "comparison. It is read-only and does not reveal any other project records."
        ),
        "alternate_payloads": [],
        "requires_auth_context": True,
        "retrieved_sources": ["HT-IDOR-CORE"],
    },
]
