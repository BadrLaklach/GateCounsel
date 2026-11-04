"""Retrieval tests for the per-class knowledge retriever (rag/retriever.py).

These double as the first retrieval-quality fixtures of the eval harness:
each case is a realistic evidence-phrased query (what an expert builds from
task.signals + rationale) asserting that the right chunk ranks at the top.
No network, fully deterministic — the same query must always rank the same.
"""

from __future__ import annotations

import hashlib
import math
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag.ingest import ingest_class, validate_class_chunks  # noqa: E402
from rag.retriever import (  # noqa: E402
    ChromaKnowledgeRetriever,
    HybridKnowledgeRetriever,
    KNOWLEDGE_ROOT,
    KnowledgeRetriever,
    context_query,
    get_retriever,
    parse_chunk,
    resolve_embedding_identity,
)

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


class ParaphraseRobustnessTests(unittest.TestCase):
    """Vocabulary-mismatched queries must still find the right chunk.

    These came from an adversarial probe of the first retriever build: plain
    BM25 ranked wrong chunks for everyday phrasings ("echoes" vs "reflected",
    "changing the number" vs "sequential integer", "backend visits a link" vs
    "server fetches a URL"). The fixes — stopword removal, plural folding in
    the tokenizer, synonym terms in chunk anchor tags — are pinned here so
    neither engine nor corpus wording can regress them silently.
    """

    def assert_top(self, vuln_class: str, query: str, expected_prefix: str) -> None:
        hits = KnowledgeRetriever(vuln_class).retrieve(query)
        self.assertTrue(hits, f"no hits for {query!r}")
        self.assertTrue(hits[0].chunk_id.startswith(expected_prefix),
                        f"{query!r}: expected {expected_prefix}*, got {hits[0].chunk_id}")

    def test_xss_echo_in_input_field_finds_attribute_chunk(self):
        self.assert_top("xss_reflected",
                        "page echoes my text between double quotes in an input field",
                        "xss-02")

    def test_xss_mirrored_as_markup_finds_body_chunk(self):
        self.assert_top("xss_reflected",
                        "value gets mirrored into the page and runs as markup",
                        "xss-01")

    def test_sqli_apostrophe_error_finds_error_chunk(self):
        self.assert_top("sqli",
                        "apostrophe makes the app throw a database message",
                        "sqli-02")

    def test_sqli_true_false_divergence_finds_boolean_chunk(self):
        self.assert_top("sqli",
                        "different content when the condition is true versus false",
                        "sqli-03")

    def test_ssrf_backend_visits_link_finds_receiver_chunk(self):
        self.assert_top("ssrf", "backend visits a link i give it", "ssrf-01")

    def test_idor_changing_number_finds_tampering_chunk(self):
        self.assert_top("idor",
                        "user one sees user two data by changing the number",
                        "idor-01")

    def test_jwt_unsigned_accepted_finds_alg_none_chunk(self):
        self.assert_top("jwt_misconfig", "token without signature still works", "jwt-01")

    def test_redirect_sends_visitors_finds_destination_chunk(self):
        self.assert_top("open_redirect",
                        "site sends visitors to another domain via the next link",
                        "open-redirect-01")

    def test_auth_admin_without_login_finds_forced_browsing(self):
        self.assert_top("auth_bypass", "admin page opens with no login", "auth-01")


# ---------------------------------------------------------------------- #
# Vector backend (ChromaDB) — plumbing tests with a deterministic fake
# embedder: no model download, no network. Semantic quality of the real
# model is covered by the env-gated VectorEndToEndTests below.
# ---------------------------------------------------------------------- #
class _FakeEmbedding:
    """Hashed bag-of-token vectors: deterministic, offline, NOT semantic.

    ``calls`` counts invocations so tests can prove rejected queries never
    reach the embedding function.
    """

    def __init__(self, dim: int = 64) -> None:
        self.dim = dim
        self.calls = 0

    def __call__(self, texts):
        self.calls += 1
        return [self._vector(text) for text in texts]

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            slot = int(hashlib.md5(token.encode()).hexdigest()[:8], 16) % self.dim
            vec[slot] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


def _write_chunk(directory: Path, chunk_id: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{chunk_id}.md").write_text(
        f"---\nid: {chunk_id}\nclass: {directory.name}\nkind: technique\n"
        f"title: test chunk {chunk_id}\napplies_when: plumbing test fixture\n"
        f"source: generated by tests/test_rag.py\ntags: [test]\n---\n\n{body}\n",
        encoding="utf-8",
    )


class _MiniCorpus:
    """Temp knowledge root with two tiny classes, cleaned up safely on Windows."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self._tmp.name)
        _write_chunk(root / "sqli", "sqli-01-alpha", "alpha " + "sql error " * 30)
        _write_chunk(root / "sqli", "sqli-02-beta", "beta " + "union select " * 30)
        _write_chunk(root / "ssrf", "ssrf-01-gamma", "gamma " + "server fetch " * 30)
        return root

    def __exit__(self, *exc) -> None:
        self._tmp.cleanup()


class VectorIngestionTests(unittest.TestCase):
    def test_ingest_is_idempotent(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                first = ingest_class("sqli", knowledge_root=root, persist_dir=store,
                                     embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                self.assertEqual(first["chunks"], 2)
                self.assertEqual(first["added_or_updated"], 2)
                second = ingest_class("sqli", knowledge_root=root, persist_dir=store,
                                       embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                self.assertEqual(second["added_or_updated"], 0)
                self.assertEqual(second["unchanged"], 2)
                self.assertEqual(second["removed"], 0)

    def test_edit_and_delete_are_detected(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                ingest_class("sqli", knowledge_root=root, persist_dir=store,
                             embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                (root / "sqli" / "sqli-01-alpha.md").write_text(
                    (root / "sqli" / "sqli-01-alpha.md").read_text(encoding="utf-8")
                    + "\nedited body content\n", encoding="utf-8")
                (root / "sqli" / "sqli-02-beta.md").unlink()
                stats = ingest_class("sqli", knowledge_root=root, persist_dir=store,
                                     embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                self.assertEqual(stats["chunks"], 1)
                self.assertEqual(stats["added_or_updated"], 1)
                self.assertEqual(stats["removed"], 1)
                retriever = ChromaKnowledgeRetriever(
                    "sqli", persist_dir=store, embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                self.assertEqual(retriever.chunk_ids, ["sqli-01-alpha"])


class VectorRetrieverTests(unittest.TestCase):
    def test_retrieval_scoped_to_the_ingested_class(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                ingest_class("sqli", knowledge_root=root, persist_dir=store,
                             embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                ingest_class("ssrf", knowledge_root=root, persist_dir=store,
                             embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                retriever = ChromaKnowledgeRetriever(
                    "sqli", persist_dir=store, embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                hits = retriever.retrieve("sql error alpha", k=2)
                self.assertTrue(hits)
                self.assertLessEqual(len(hits), 2)
                for chunk in hits:
                    self.assertEqual(chunk.class_name, "sqli")
                    self.assertTrue(chunk.chunk_id.startswith("sqli-"))
                    self.assertTrue(chunk.title)

    def test_missing_collection_raises_with_ingest_guidance(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
            with self.assertRaisesRegex(ValueError, "rag.ingest"):
                ChromaKnowledgeRetriever("sqli", persist_dir=store,
                                         embedding_function=_FakeEmbedding(), embedding_identity="test-fake")

    def test_factory_prefers_hybrid_and_falls_back_to_lexical(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                fallback = get_retriever("sqli", persist_dir=store)
                self.assertIsInstance(fallback, KnowledgeRetriever)
                ingest_class("sqli", knowledge_root=root, persist_dir=store,
                             embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
                hybrid = get_retriever("sqli", persist_dir=store,
                                       embedding_function=_FakeEmbedding(),
                                       embedding_identity="test-fake",
                                       knowledge_root=root)
                self.assertIsInstance(hybrid, HybridKnowledgeRetriever)
                hits = hybrid.retrieve("sql error alpha", k=2)
                for chunk in hits:
                    self.assertEqual(chunk.class_name, "sqli")
                    self.assertTrue(chunk.chunk_id.startswith("sqli-"))


class QueryRejectionTests(unittest.TestCase):
    """Batch 1: every engine refuses empty/whitespace queries and k <= 0,
    and rejected queries never invoke the embedding function."""

    def test_lexical_engine_rejects_bad_queries(self):
        retriever = KnowledgeRetriever("sqli")
        for bad_query in ("", "   ", "\t\n"):
            self.assertEqual(retriever.retrieve(bad_query), [])
        self.assertEqual(retriever.retrieve("error message", 0), [])
        self.assertEqual(retriever.retrieve("error message", -3), [])

    def test_vector_engine_rejects_without_embedding(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                embed = _FakeEmbedding()
                ingest_class("sqli", knowledge_root=root, persist_dir=store,
                             embedding_function=embed, embedding_identity="test-fake")
                retriever = ChromaKnowledgeRetriever("sqli", persist_dir=store,
                                                     embedding_function=embed, embedding_identity="test-fake")
                baseline = embed.calls  # ingest itself embeds; rejected queries must not add
                for bad_query in ("", "   "):
                    self.assertEqual(retriever.retrieve(bad_query), [])
                self.assertEqual(retriever.retrieve("sql error", 0), [])
                self.assertEqual(retriever.retrieve("sql error", -1), [])
                self.assertEqual(embed.calls, baseline)

    def test_hybrid_engine_rejects_without_embedding(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                embed = _FakeEmbedding()
                ingest_class("sqli", knowledge_root=root, persist_dir=store,
                             embedding_function=embed, embedding_identity="test-fake")
                hybrid = HybridKnowledgeRetriever("sqli", persist_dir=store,
                                                  embedding_function=embed,
                                                  embedding_identity="test-fake",
                                                  knowledge_root=root)
                baseline = embed.calls  # ingest itself embeds; rejected queries must not add
                for bad_query in ("", "   "):
                    self.assertEqual(hybrid.retrieve(bad_query), [])
                self.assertEqual(hybrid.retrieve("sql error", 0), [])
                self.assertEqual(hybrid.retrieve("sql error", -2), [])
                self.assertEqual(embed.calls, baseline)


class CustomRootIsolationTests(unittest.TestCase):
    """Batch 1: knowledge_root must reach the hybrid's lexical engine, so a
    custom corpus yields exactly its own (disjoint) chunk IDs — never the
    repository corpus's IDs."""

    def test_hybrid_lexical_side_is_scoped_to_custom_root(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "knowledge"
            _write_chunk(root / "sqli", "customsql-alpha", "alpha " + "sql error " * 30)
            _write_chunk(root / "sqli", "customsql-beta", "beta " + "union select " * 30)
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
                embed = _FakeEmbedding()
                ingest_class("sqli", knowledge_root=root, persist_dir=store,
                             embedding_function=embed, embedding_identity="test-fake")
                hybrid = get_retriever("sqli", persist_dir=store,
                                       embedding_function=embed,
                                       embedding_identity="test-fake",
                                       knowledge_root=root)
                self.assertIsInstance(hybrid, HybridKnowledgeRetriever)
                self.assertEqual(hybrid.lexical.chunk_ids,
                                 ["customsql-alpha", "customsql-beta"])
                allowed = {"customsql-alpha", "customsql-beta"}
                hits = (hybrid.retrieve("sql error alpha")
                        + hybrid.retrieve("union select beta"))
                self.assertTrue(hits)
                for chunk in hits:
                    self.assertIn(chunk.chunk_id, allowed)

    def test_get_retriever_lexical_fallback_honors_custom_root(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "knowledge"
            _write_chunk(root / "ssrf", "customssrf-one", "one " + "server fetch " * 30)
            retriever = get_retriever("ssrf", persist_dir=Path(tmp) / "no_index",
                                      knowledge_root=root)
            self.assertIsInstance(retriever, KnowledgeRetriever)
            self.assertEqual(retriever.chunk_ids, ["customssrf-one"])


class MissingCollectionTests(unittest.TestCase):
    """Batch 1: NotFoundError maps to ingest guidance; operational errors
    propagate untouched. Verified against installed chromadb 1.5.0, which
    raises chromadb.errors.NotFoundError for missing collections."""

    def test_missing_collection_keeps_ingest_guidance(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
            with self.assertRaisesRegex(ValueError, r"rag\.ingest sqli"):
                ChromaKnowledgeRetriever("sqli", persist_dir=store,
                                         embedding_function=_FakeEmbedding(), embedding_identity="test-fake")

    def test_operational_errors_propagate_not_swallowed(self):
        from unittest import mock

        import chromadb

        with mock.patch.object(chromadb, "PersistentClient") as factory:
            factory.return_value.get_collection.side_effect = RuntimeError("disk exploded")
            with self.assertRaisesRegex(RuntimeError, "disk exploded"):
                ChromaKnowledgeRetriever("sqli", embedding_function=_FakeEmbedding(), embedding_identity="test-fake")


def _raw_chunk(chunk_id: str, class_name: str, *, kind: str = "technique",
               body: str = "fixture body text for validation tests") -> str:
    return (f"---\nid: {chunk_id}\nclass: {class_name}\nkind: {kind}\n"
            f"title: fixture {chunk_id}\napplies_when: ingestion validation fixture\n"
            f"source: tests/test_rag.py\ntags: [test]\n---\n\n{body}\n")


class IngestionValidationTests(unittest.TestCase):
    """Batch 2.1: the whole source class is validated before any index
    mutation; errors name file paths; an existing index survives refusal."""

    def _fresh_corpus(self, base: Path) -> Path:
        root = base / "knowledge"
        (root / "sqli").mkdir(parents=True)
        (root / "sqli" / "valsql-one.md").write_text(
            _raw_chunk("valsql-one", "sqli"), encoding="utf-8")
        (root / "sqli" / "valsql-two.md").write_text(
            _raw_chunk("valsql-two", "sqli"), encoding="utf-8")
        return root

    def _ingest(self, root: Path, store: str) -> dict:
        return ingest_class("sqli", knowledge_root=root, persist_dir=store,
                            embedding_function=_FakeEmbedding(),
                            embedding_identity="test-fake")

    def test_invalid_sources_raise_with_paths_and_leave_index_intact(self):
        cases = {
            "missing-source": ("missing or empty frontmatter key 'source'",
                               lambda root: (root / "sqli" / "valsql-one.md").write_text(
                                   _raw_chunk("valsql-one", "sqli").replace(
                                       "source: tests/test_rag.py\n", ""), encoding="utf-8")),
            "empty-body": ("empty body",
                           lambda root: (root / "sqli" / "valsql-one.md").write_text(
                               _raw_chunk("valsql-one", "sqli", body="   \n"), encoding="utf-8")),
            "id-filename-mismatch": ("must equal filename stem",
                                     lambda root: [
                                         (root / "sqli" / "valsql-one.md").unlink(),
                                         (root / "sqli" / "wrongname.md").write_text(
                                             _raw_chunk("valsql-one", "sqli"), encoding="utf-8")]),
            "class-mismatch": ("must equal directory",
                               lambda root: (root / "sqli" / "valsql-one.md").write_text(
                                   _raw_chunk("valsql-one", "ssrf"), encoding="utf-8")),
            "bad-kind": ("not in ['context_map', 'technique']",
                         lambda root: (root / "sqli" / "valsql-one.md").write_text(
                             _raw_chunk("valsql-one", "sqli", kind="cheat_sheet"),
                             encoding="utf-8")),
            "duplicate-id": ("duplicate id 'valsql-two'",
                             lambda root: (root / "sqli" / "dup.md").write_text(
                                 _raw_chunk("valsql-two", "sqli"), encoding="utf-8")),
        }
        for label, (snippet, mutate) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = self._fresh_corpus(base)
                store = str(base / "store")
                self._ingest(root, store)  # valid corpus ingests fine
                retriever = ChromaKnowledgeRetriever(
                    "sqli", persist_dir=store, embedding_function=_FakeEmbedding(),
                    embedding_identity="test-fake")
                before = retriever.chunk_ids
                mutate(root)
                with self.assertRaises(ValueError) as caught:
                    self._ingest(root, store)
                self.assertIn(snippet, str(caught.exception))
                self.assertIn("valsql", str(caught.exception))  # errors carry file paths
                after = ChromaKnowledgeRetriever(
                    "sqli", persist_dir=store, embedding_function=_FakeEmbedding(),
                    embedding_identity="test-fake").chunk_ids
                self.assertEqual(after, before)  # refused ingestion left the index intact

    def test_empty_class_directory_is_refused(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "knowledge"
            root.mkdir()
            (root / "sqli").mkdir()
            with self.assertRaisesRegex(ValueError, "has no chunks"):
                self._ingest(root, str(Path(tmp) / "store"))

    def test_shipped_corpus_passes_validation_for_every_class(self):
        for vuln_class in ALL_CLASSES:
            with self.subTest(vuln_class=vuln_class):
                parsed = [(p, *parse_chunk(p))
                          for p in sorted((KNOWLEDGE_ROOT / vuln_class).glob("*.md"))]
                validate_class_chunks(parsed, vuln_class)  # must not raise


class IndexCompatibilityTests(unittest.TestCase):
    """Batch 2.2/2.3: embedding identity is persisted and enforced — identity
    or format changes rebuild every vector; incomplete or incompatible
    indexes are rejected at query construction, never silently used."""

    def _ingest(self, root: Path, store: str, *, dim: int = 64, identity: str = "fake-a") -> dict:
        return ingest_class("sqli", knowledge_root=root, persist_dir=store,
                            embedding_function=_FakeEmbedding(dim),
                            embedding_identity=identity)

    def _query(self, store: str, *, dim: int = 64, identity: str = "fake-a"):
        return ChromaKnowledgeRetriever("sqli", persist_dir=store,
                                        embedding_function=_FakeEmbedding(dim),
                                        embedding_identity=identity)

    def test_custom_embedder_without_identity_is_rejected(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                with self.assertRaisesRegex(ValueError, "embedding_identity"):
                    ingest_class("sqli", knowledge_root=root, persist_dir=str(Path(tmp) / "s"),
                                 embedding_function=_FakeEmbedding())

    def test_identity_change_rebuilds_equal_dimensions(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                store = str(Path(tmp) / "store")
                self.assertFalse(self._ingest(root, store)["rebuilt"])
                second = self._ingest(root, store, dim=64, identity="fake-b")
                self.assertTrue(second["rebuilt"])
                self.assertEqual(second["added_or_updated"], second["chunks"])
                self.assertTrue(self._query(store, identity="fake-b").retrieve("sql error alpha"))
                with self.assertRaisesRegex(ValueError, "embedding identity"):
                    self._query(store, identity="fake-a")

    def test_identity_change_rebuilds_different_dimensions(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                store = str(Path(tmp) / "store")
                self._ingest(root, store, dim=64, identity="fake-a")
                self.assertTrue(self._ingest(root, store, dim=32, identity="fake-b")["rebuilt"])
                self.assertTrue(self._query(store, dim=32, identity="fake-b").chunk_ids)
                with self.assertRaisesRegex(ValueError, "embedding identity"):
                    self._query(store, dim=64, identity="fake-a")

    def test_legacy_unversioned_collection_is_rebuilt(self):
        import chromadb

        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                store = Path(tmp) / "store"
                client = chromadb.PersistentClient(
                    path=str(store), settings=chromadb.Settings(anonymized_telemetry=False))
                legacy = client.get_or_create_collection(
                    "knowledge_sqli", metadata={"hnsw:space": "cosine"})  # pre-versioning shape
                legacy.upsert(ids=["ghost"], embeddings=[[0.5] * 64],
                              documents=["legacy"], metadatas=[{"hash": "old"}])
                stats = self._ingest(root, str(store))
                self.assertTrue(stats["rebuilt"])
                self.assertEqual(self._query(str(store)).chunk_ids,
                                 ["sqli-01-alpha", "sqli-02-beta"])

    def test_building_index_is_rejected_at_query_time(self):
        import chromadb

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = Path(tmp) / "store"
            client = chromadb.PersistentClient(
                path=str(store), settings=chromadb.Settings(anonymized_telemetry=False))
            identity = resolve_embedding_identity(_FakeEmbedding(), "fake-a")
            client.get_or_create_collection("knowledge_sqli", metadata={
                "hnsw:space": "cosine", "status": "building",
                "embedding_identity": identity, "embedding_dim": 64})
            with self.assertRaisesRegex(ValueError, "not safe to query"):
                self._query(str(store))

    def test_dimension_change_under_same_identity_is_refused(self):
        with _MiniCorpus() as root:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                store = str(Path(tmp) / "store")
                self._ingest(root, store, dim=64, identity="fake-a")
                before = self._query(store).chunk_ids
                (root / "sqli" / "sqli-01-alpha.md").write_text(
                    (root / "sqli" / "sqli-01-alpha.md").read_text(encoding="utf-8")
                    + "\nedited to force re-embedding\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "dimension changed"):
                    self._ingest(root, store, dim=32, identity="fake-a")
                # refused re-ingest left the working index intact
                self.assertEqual(self._query(store).chunk_ids, before)


class StaleIndexTests(unittest.TestCase):
    """Batch 2.4: the vector index is bound to a content manifest of its
    source class — hybrid construction fails explicitly on corpus drift,
    get_retriever degrades to lexical, and identical cloned corpora stay
    compatible (manifests are content-addressed, not path-addressed)."""

    def _setup(self, base: Path) -> tuple[Path, str]:
        root = base / "knowledge"
        (root / "ssrf").mkdir(parents=True)
        (root / "ssrf" / "stalessrf-one.md").write_text(
            _raw_chunk("stalessrf-one", "ssrf", body="server fetch " * 30), encoding="utf-8")
        (root / "ssrf" / "stalessrf-two.md").write_text(
            _raw_chunk("stalessrf-two", "ssrf", body="url bypass " * 30), encoding="utf-8")
        store = str(base / "store")
        ingest_class("ssrf", knowledge_root=root, persist_dir=store,
                     embedding_function=_FakeEmbedding(), embedding_identity="test-fake")
        return root, store

    def _hybrid(self, root: Path, store: str) -> HybridKnowledgeRetriever:
        return HybridKnowledgeRetriever("ssrf", persist_dir=store,
                                        embedding_function=_FakeEmbedding(),
                                        embedding_identity="test-fake",
                                        knowledge_root=root)

    def test_hybrid_detects_edited_corpus(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, store = self._setup(Path(tmp))
            self._hybrid(root, store)  # fresh index constructs fine
            (root / "ssrf" / "stalessrf-one.md").write_text(
                _raw_chunk("stalessrf-one", "ssrf", body="server fetch edited " * 30),
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stale"):
                self._hybrid(root, store)

    def test_hybrid_detects_deleted_chunk(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, store = self._setup(Path(tmp))
            (root / "ssrf" / "stalessrf-two.md").unlink()
            with self.assertRaisesRegex(ValueError, "stale"):
                self._hybrid(root, store)

    def test_get_retriever_falls_back_to_lexical_on_stale_index(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, store = self._setup(Path(tmp))
            (root / "ssrf" / "stalessrf-two.md").unlink()
            retriever = get_retriever("ssrf", persist_dir=store,
                                      embedding_function=_FakeEmbedding(),
                                      embedding_identity="test-fake",
                                      knowledge_root=root)
            self.assertIsInstance(retriever, KnowledgeRetriever)

    def test_identical_clone_at_different_path_stays_compatible(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root, store = self._setup(base)
            clone = base / "cloned-knowledge"
            shutil.copytree(root, clone)
            hybrid = self._hybrid(clone, store)  # same content, different path
            self.assertTrue(hybrid.retrieve("server fetch"))


class VectorEndToEndTests(unittest.TestCase):
    """Real-model run: fixture queries through the default (hybrid) engine.

    Gated because it downloads MiniLM (~90 MB, cached) on first use:
        GATECOUNSEL_EMBEDDINGS_E2E=1 python -m unittest tests.test_rag
    """

    def test_real_hybrid_engine_matches_fixture_expectations(self):
        import os

        if not os.getenv("GATECOUNSEL_EMBEDDINGS_E2E"):
            self.skipTest("set GATECOUNSEL_EMBEDDINGS_E2E=1 to run (downloads the model once)")
        from rag.ingest import ingest_all

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as store:
            ingest_all(persist_dir=store)
            checks = [
                ("xss_reflected", "value reflected inside an html tag attribute value= quotes",
                 "xss-02"),
                ("sqli", "database error message in response after quote sql syntax error",
                 "sqli-02"),
                ("jwt_misconfig", "token without signature still works", "jwt-01"),
                ("idor", "user one sees user two data by changing the number", "idor-01"),
                ("auth_bypass", "admin page opens with no login", "auth-01"),
            ]
            for vuln_class, query, expected in checks:
                with self.subTest(vuln_class=vuln_class, query=query):
                    retriever = get_retriever(vuln_class, persist_dir=store)
                    hits = retriever.retrieve(query)
                    self.assertTrue(hits, f"no hits for {query!r}")
                    self.assertTrue(hits[0].chunk_id.startswith(expected),
                                    f"{query!r}: expected {expected}*, got {hits[0].chunk_id}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
