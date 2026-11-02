"""Retrieval tests for the per-class knowledge retriever (rag/retriever.py).

These double as the first retrieval-quality fixtures of the eval harness:
each case is a realistic evidence-phrased query (what an expert builds from
task.signals + rationale) asserting that the right chunk ranks at the top.
No network, fully deterministic — the same query must always rank the same.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag.retriever import KnowledgeRetriever, context_query  # noqa: E402

ALL_CLASSES = [
    "auth_bypass", "idor", "jwt_misconfig", "open_redirect", "sqli", "ssrf",
    "xss_reflected",
]


class RetrieverConstructionTests(unittest.TestCase):
    def test_unknown_class_is_rejected(self):
        with self.assertRaises(ValueError):
            KnowledgeRetriever("deserialization")

    def test_every_class_loads(self):
        for vuln_class in ALL_CLASSES:
            retriever = KnowledgeRetriever(vuln_class)
            self.assertTrue(retriever.chunk_ids, f"{vuln_class}: no chunks loaded")


class RetrievalIsolationTests(unittest.TestCase):
    def test_results_come_only_from_the_requested_class(self):
        for vuln_class in ALL_CLASSES:
            retriever = KnowledgeRetriever(vuln_class)
            hits = retriever.retrieve("url parameter value response server request")
            self.assertTrue(hits, f"{vuln_class}: expected hits for a generic query")
            for chunk in hits:
                self.assertEqual(chunk.class_name, vuln_class,
                                 f"{vuln_class}: foreign chunk {chunk.chunk_id}")

    def test_disjoint_query_returns_nothing(self):
        retriever = KnowledgeRetriever("sqli")
        self.assertEqual(retriever.retrieve("quarterly financial report audit spreadsheet"), [])

    def test_retrieval_is_deterministic(self):
        retriever = KnowledgeRetriever("xss_reflected")
        first = retriever.retrieve("reflected value inside an html tag attribute")
        second = retriever.retrieve("reflected value inside an html tag attribute")
        self.assertEqual([c.chunk_id for c in first], [c.chunk_id for c in second])


class RetrievalQualityTests(unittest.TestCase):
    """Evidence-phrased queries must rank the matching technique first."""

    def test_xss_attribute_context_ranks_attribute_chunk(self):
        hits = KnowledgeRetriever("xss_reflected").retrieve(
            "value reflected inside an html tag attribute value= quotes")
        self.assertEqual(hits[0].chunk_id, "xss-02-attribute-context-event-handlers")

    def test_sqli_error_strings_rank_error_based_chunk(self):
        hits = KnowledgeRetriever("sqli").retrieve(
            "database error message in response after quote sql syntax error")
        self.assertEqual(hits[0].chunk_id, "sqli-02-error-based")

    def test_ssrf_receiver_query_ranks_confirmation_chunk(self):
        hits = KnowledgeRetriever("ssrf").retrieve(
            "server fetches url parameter webhook controlled receiver request observed")
        self.assertIn("ssrf-01-confirming-with-a-controlled-receiver",
                      [c.chunk_id for c in hits[:2]])

    def test_idor_identifier_swap_ranks_tampering_chunk(self):
        hits = KnowledgeRetriever("idor").retrieve(
            "changing numeric user id returns another user object without ownership check")
        self.assertEqual(hits[0].chunk_id, "idor-01-object-identifier-tampering")

    def test_open_redirect_location_query_ranks_destination_chunk(self):
        hits = KnowledgeRetriever("open_redirect").retrieve(
            "location header redirect parameter next url points to external host")
        self.assertTrue(hits[0].chunk_id.startswith("open-redirect-0"),
                        f"unexpected top chunk {hits[0].chunk_id}")

    def test_jwt_alg_none_query_ranks_alg_none_chunk(self):
        hits = KnowledgeRetriever("jwt_misconfig").retrieve(
            "token header alg none signature not verified accepted")
        self.assertEqual(hits[0].chunk_id, "jwt-01-alg-none")

    def test_auth_admin_without_login_ranks_forced_browsing(self):
        hits = KnowledgeRetriever("auth_bypass").retrieve(
            "hidden admin page requested directly with no session serves the route")
        self.assertEqual(hits[0].chunk_id, "auth-01-forced-browsing")

    def test_context_query_joins_signals_and_rationale(self):
        self.assertEqual(
            context_query(["param reflected=true", "angle brackets survive"], "classic tag injection"),
            "param reflected=true angle brackets survive classic tag injection",
        )
        self.assertEqual(context_query([], None), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
