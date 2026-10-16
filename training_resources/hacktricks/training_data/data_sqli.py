"""Synthetic, read-only SQLi ExpertVerdict cases based on the curated HackTricks note.

Source ID: HT-SQLI-CORE. Each check is constrained to one known fixture row.
"""

VULN_CLASS = "sqli"

EXAMPLES = [
    {
        "task_id": "HT-SQLI-001",
        "endpoint_url": "http://demo-target/api/items",
        "method": "GET",
        "target_param": "id",
        "injection_point": "query",
        "recon_evidence": (
            "In the local fixture, id=41 returns exactly the seeded item LAB-ITEM-41. The query "
            "context is known to be a numeric SQL expression, and the endpoint is read-only."
        ),
        "planner_rationale": "Check whether the numeric input is evaluated as SQL while keeping the result bounded to the known item ID.",
        "retrieved_context": (
            "HT-SQLI-CORE: use a logical operation with a known baseline to see whether input "
            "changes query semantics. A response error alone is only a clue, not a finding."
        ),
        "approved_test_values": ["41 AND 1=1"],
        "payload": "41 AND 1=1",
        "expected_success_signal": (
            "The response returns only the same seeded LAB-ITEM-41 record as id=41. The verifier "
            "must establish that this expression is evaluated in the fixture's SQL context; no "
            "other row may be returned."
        ),
        "confidence": 0.79,
        "reasoning": (
            "A true predicate attached to the known primary key should preserve only that row if "
            "the input is interpreted as SQL. A parameterized implementation treats the complete "
            "value as data and should not match the seeded integer."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-SQLI-CORE"],
    },
    {
        "task_id": "HT-SQLI-002",
        "endpoint_url": "http://demo-target/api/products/search",
        "method": "GET",
        "target_param": "name",
        "injection_point": "query",
        "recon_evidence": (
            "The local fixture's query compares a known single-quoted name value. Baseline "
            "name=blue-widget returns one seeded product; the route is read-only and returns at most that fixture row."
        ),
        "planner_rationale": "Use one context-aware true predicate and compare it with the known literal baseline.",
        "retrieved_context": (
            "HT-SQLI-CORE: identify the input's query context, then use a logical condition and "
            "stable result comparison. Keep the returned data limited to the known fixture."
        ),
        "approved_test_values": ["blue-widget' AND '1'='1"],
        "payload": "blue-widget' AND '1'='1",
        "expected_success_signal": (
            "The response returns only the same seeded blue-widget product as the baseline. "
            "Confirmation requires fixture-specific evidence that the condition affected SQL "
            "semantics, not just an HTTP success or error string."
        ),
        "confidence": 0.76,
        "reasoning": (
            "The evidence identifies a quoted string context and a one-row fixture. The true "
            "predicate keeps that exact row while a parameterized query would treat the full "
            "string as data; the response remains bounded."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-SQLI-CORE"],
    },
    {
        "task_id": "HT-SQLI-003",
        "endpoint_url": "http://demo-target/api/records",
        "method": "GET",
        "target_param": "record_id",
        "injection_point": "query",
        "recon_evidence": (
            "The fixture documents record 7 as the only expected result for id=7 and confirms the "
            "parameter reaches a numeric expression. The response body is a synthetic marker, not record contents."
        ),
        "planner_rationale": "A simple arithmetic expression can test whether the numeric parameter is evaluated, without changing the selected record.",
        "retrieved_context": (
            "HT-SQLI-CORE: mathematical/logical differences can indicate query evaluation when a "
            "known input and result are available. The verifier must use the fixture ground truth."
        ),
        "approved_test_values": ["7+0"],
        "payload": "7+0",
        "expected_success_signal": (
            "The endpoint returns only the synthetic marker for seeded record 7, matching id=7. "
            "A response that treats 7+0 as a literal identifier is not positive evidence."
        ),
        "confidence": 0.74,
        "reasoning": (
            "The arithmetic expression should resolve to the same known identifier only if the "
            "numeric input is interpreted in the query context. The test is a single read-only "
            "request and exposes no additional rows."
        ),
        "alternate_payloads": [],
        "requires_auth_context": False,
        "retrieved_sources": ["HT-SQLI-CORE"],
    },
]
