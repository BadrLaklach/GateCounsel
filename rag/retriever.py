"""Per-class retrieval over the knowledge/ chunk store — two engines.

The Tier-1 expert's context source (EXPERT_AGENTS_SPEC §5/§6): each expert
retrieves ONLY from its own vulnerability class's chunks, so cross-class
context leakage is impossible by construction — stronger than trusting a
shared store to keep collections apart.

ChromaKnowledgeRetriever is the primary engine: vector retrieval over
per-class collections ingested by rag/ingest.py (sentence-transformers
MiniLM by default). KnowledgeRetriever is Okapi BM25 over the chunk files
directly — the fallback for fresh clones before the first ingest, and the
offline engine the retrieval-quality fixtures run against (the same
assertions run against the real vector index under
GATECOUNSEL_EMBEDDINGS_E2E=1). get_retriever() picks: vector when the
class's collection exists, lexical otherwise.

The embedding function contract is a plain callable list[str] -> list of
vectors, invoked explicitly on both ingest and query sides, so a
deterministic fake can replace the model in tests without touching
Chroma's embedding-function plumbing.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from pathlib import Path

__all__ = ["RetrievedChunk", "KnowledgeRetriever", "ChromaKnowledgeRetriever",
           "HybridKnowledgeRetriever", "get_retriever", "parse_chunk",
           "context_query", "default_embedding_function"]

KNOWLEDGE_ROOT = Path(__file__).resolve().parents[1] / "knowledge"
DEFAULT_PERSIST_DIR = Path(__file__).resolve().parent / "chroma_index"  # gitignored
DEFAULT_K = 3  # spec §5: "Return top-k (k=3 default) chunks"
DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"


def default_embedding_function():
    """sentence-transformers MiniLM embedder (lazy: no torch at module import)."""
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    return SentenceTransformerEmbeddingFunction(model_name=DEFAULT_EMBEDDING_MODEL)

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Prose noise that matches almost every document and drowns out anchor
# terms at small corpus sizes (found by the paraphrase probe in
# tests/test_rag.py: "backend visits a link i give it" ranked an
# irrelevant chunk first on 'a'/'i'/'it' matches alone).
_STOPWORDS = frozenset("""
a an and are as at be by for from has have i in is it its of on or that
the this to was were will with you your
""".split())


# ------------------------------------------------------------------ #
# Chunk loading
# ------------------------------------------------------------------ #
def parse_chunk(path: Path) -> tuple[dict[str, str], str]:
    """Parse one knowledge chunk: (frontmatter, body).

    Frontmatter is flat 'key: value' lines between two '---' markers (the
    format knowledge/README.md defines and tests/test_knowledge.py enforces).
    Raises ValueError with the filename when the block is missing or a line
    is not 'key: value'.
    """
    text = path.read_text(encoding="utf-8")
    m = re.match(r"\A---\n(.*?)\n---\n(.*)\Z", text, re.S)
    if not m:
        raise ValueError(f"{path.name}: missing '---\\n...\\n---' frontmatter block")

    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"{path.name}: frontmatter line not 'key: value': {line!r}")
        meta[key.strip()] = value.strip()
    return meta, m.group(2).strip()


@dataclass(frozen=True)
class RetrievedChunk:
    """One knowledge chunk as returned to the expert (spec §5 RetrievedChunk)."""

    chunk_id: str
    class_name: str
    title: str
    source: str
    applies_when: str
    text: str
    score: float = 0.0


def context_query(signals: list[str] | None, rationale: str | None) -> str:
    """Combine a PlanTask's evidence into one retrieval query (spec §5).

    The spec defines the query as task.signals + task.rationale; keeping the
    rule in one place means every expert builds queries the same way.
    """
    parts = list(signals or [])
    if rationale:
        parts.append(rationale)
    return " ".join(parts)


# ------------------------------------------------------------------ #
# BM25 index (Okapi, k1/b defaults per Robertson/Sparck Jones usage)
# ------------------------------------------------------------------ #
def _tokenize(text: str) -> list[str]:
    """Lowercase word tokens: stopwords dropped, trailing plural 's' folded.

    The plural fold ("changes"→"change", "quotes"→"quote") is deliberately
    crude — applied after stopword removal, only to words longer than three
    chars — because the paraphrase probe showed tense/plural mismatches
    ("changing the number" vs "changes ... integer") lose the right chunk,
    and a full stemmer is not warranted for this corpus.
    """
    tokens = _TOKEN_RE.findall(text.lower())
    return [t[:-1] if len(t) > 3 and t.endswith("s") else t
            for t in tokens if t not in _STOPWORDS]


def _document_text(meta: dict[str, str], body: str) -> str:
    anchors = f"{meta.get('title', '')} {meta.get('applies_when', '')} {meta.get('tags', '').strip('[]')}"
    # anchors duplicated once: evidence-phrased anchor terms must outweigh
    # body prose when both contain the query terms
    return f"{anchors} {anchors} {body}"


class _Bm25Index:
    def __init__(self, documents: list[list[str]], *, k1: float = 1.5, b: float = 0.75) -> None:
        self._k1, self._b = k1, b
        self._doc_len = [len(d) or 1 for d in documents]
        self._avg_len = sum(self._doc_len) / max(1, len(documents))
        self._tfs: list[dict[str, int]] = []
        self._df: dict[str, int] = {}
        for doc in documents:
            tf: dict[str, int] = {}
            for term in doc:
                tf[term] = tf.get(term, 0) + 1
            self._tfs.append(tf)
            for term in tf:
                self._df[term] = self._df.get(term, 0) + 1

    def score(self, query_terms: list[str], doc_index: int) -> float:
        tf_doc = self._tfs[doc_index]
        doc_len = self._doc_len[doc_index]
        total = len(self._tfs)
        score = 0.0
        for term in query_terms:
            tf = tf_doc.get(term, 0)
            if not tf:
                continue
            df = self._df.get(term, 0)
            idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
            norm = self._k1 * (1 - self._b + self._b * doc_len / self._avg_len)
            score += idf * tf * (self._k1 + 1) / (tf + norm)
        return score


# ------------------------------------------------------------------ #
# Retriever
# ------------------------------------------------------------------ #
class KnowledgeRetriever:
    """Retrieves knowledge chunks for ONE vulnerability class.

    Constructing it for a class loads and indexes only that class's
    directory; results can therefore never contain another class's chunks.
    """

    def __init__(self, vuln_class: str, knowledge_root: str | Path = KNOWLEDGE_ROOT) -> None:
        class_dir = Path(knowledge_root) / vuln_class
        if not class_dir.is_dir():
            raise ValueError(f"no knowledge directory for class {vuln_class!r}")
        self.vuln_class = vuln_class

        chunks: list[RetrievedChunk] = []
        documents: list[list[str]] = []
        for path in sorted(class_dir.glob("*.md")):
            meta, body = parse_chunk(path)
            chunks.append(RetrievedChunk(
                chunk_id=meta.get("id", path.stem),
                class_name=meta.get("class", vuln_class),
                title=meta.get("title", ""),
                source=meta.get("source", ""),
                applies_when=meta.get("applies_when", ""),
                text=body,
            ))
            documents.append(_tokenize(_document_text(meta, body)))
        if not chunks:
            raise ValueError(f"knowledge directory for {vuln_class!r} has no chunks")
        self._chunks = chunks
        self._index = _Bm25Index(documents)

    @property
    def chunk_ids(self) -> list[str]:
        return [c.chunk_id for c in self._chunks]

    def retrieve(self, query: str, k: int = DEFAULT_K) -> list[RetrievedChunk]:
        """Top-k chunks for one query, best score first.

        Returns an empty list when no document shares a term with the
        query — an honest miss rather than arbitrary filler.
        """
        terms = _tokenize(query)
        if not terms:
            return []
        scored = [
            (self._index.score(terms, i), chunk)
            for i, chunk in enumerate(self._chunks)
        ]
        hits = [(score, chunk) for score, chunk in scored if score > 0.0]
        hits.sort(key=lambda pair: (-pair[0], pair[1].chunk_id))
        return [replace(chunk, score=round(score, 4)) for score, chunk in hits[:k]]


# ------------------------------------------------------------------ #
# Vector engine (primary; requires rag/ingest.py to have run)
# ------------------------------------------------------------------ #
class ChromaKnowledgeRetriever:
    """Vector retrieval over one ingested class collection.

    The embedding function must match ingest time (same model, or the same
    fake in tests); collections store precomputed vectors, queries embed
    explicitly.
    """

    def __init__(self, vuln_class: str, *, persist_dir: str | Path = DEFAULT_PERSIST_DIR,
                 embedding_function=None) -> None:
        import chromadb  # lazy: importing rag.retriever never pulls chroma

        self.vuln_class = vuln_class
        self._embed = embedding_function or default_embedding_function()
        client = chromadb.PersistentClient(
            path=str(Path(persist_dir)),
            settings=chromadb.Settings(anonymized_telemetry=False),
        )
        try:
            self._collection = client.get_collection(f"knowledge_{vuln_class}")
        except Exception as exc:  # chroma raises ValueError/NotFoundError by version
            raise ValueError(
                f"no ingested collection for {vuln_class!r} — run: python -m rag.ingest {vuln_class}"
            ) from exc

    @property
    def chunk_ids(self) -> list[str]:
        return list(self._collection.get().get("ids", []))

    def retrieve(self, query: str, k: int = DEFAULT_K) -> list[RetrievedChunk]:
        """Top-k chunks by cosine similarity (score = 1 - distance)."""
        available = self._collection.count()
        if k <= 0 or available == 0:
            return []
        result = self._collection.query(
            query_embeddings=self._embed([query]),
            n_results=min(k, available),
        )
        chunks: list[RetrievedChunk] = []
        for chunk_id, distance, meta, text in zip(
            result["ids"][0], result["distances"][0],
            result["metadatas"][0], result["documents"][0],
        ):
            chunks.append(RetrievedChunk(
                chunk_id=chunk_id,
                class_name=(meta or {}).get("class", self.vuln_class),
                title=(meta or {}).get("title", ""),
                source=(meta or {}).get("source", ""),
                applies_when=(meta or {}).get("applies_when", ""),
                text=text or "",
                score=round(1.0 - distance, 4),
            ))
        return chunks


# ------------------------------------------------------------------ #
# Hybrid engine (default once ingested): reciprocal-rank fusion
# ------------------------------------------------------------------ #
class HybridKnowledgeRetriever:
    """RRF fusion of the lexical and vector engines — the default after ingest.

    Empirical basis (tests/test_rag.py fixtures): on this corpus each single
    engine misses queries the other hits — plain BM25 lost everyday
    phrasings before the anchor-synonym fixes; pure MiniLM retrieval ranks
    adjacent technique chunks nearly tied and flips fixtures (idor
    'changing the number': 0.2012 obfuscation vs 0.1964 tampering). RRF
    (k=60, Cormack et al. 2009) fuses the two ranked lists without
    normalizing incomparable score spaces (unbounded BM25 vs bounded
    cosine), is parameter-free beyond k, and stays deterministic (ties
    break by chunk id).
    """

    RRF_K = 60
    CANDIDATE_POOL = 10  # each engine contributes up to this many candidates

    def __init__(self, vuln_class: str, *, persist_dir: str | Path = DEFAULT_PERSIST_DIR,
                 embedding_function=None) -> None:
        self.vuln_class = vuln_class
        self.lexical = KnowledgeRetriever(vuln_class)
        self.vector = ChromaKnowledgeRetriever(vuln_class, persist_dir=persist_dir,
                                               embedding_function=embedding_function)

    @property
    def chunk_ids(self) -> list[str]:
        return self.lexical.chunk_ids

    def retrieve(self, query: str, k: int = DEFAULT_K) -> list[RetrievedChunk]:
        """Fuse both engines' rankings; top-k by fused RRF score."""
        pool = max(k, self.CANDIDATE_POOL)
        fused: dict[str, float] = {}
        by_id: dict[str, RetrievedChunk] = {}
        for ranked in (self.lexical.retrieve(query, k=pool),
                       self.vector.retrieve(query, k=pool)):
            for rank, chunk in enumerate(ranked, start=1):
                fused[chunk.chunk_id] = fused.get(chunk.chunk_id, 0.0) + 1.0 / (self.RRF_K + rank)
                by_id.setdefault(chunk.chunk_id, chunk)
        ranked_ids = sorted(fused, key=lambda cid: (-fused[cid], cid))
        return [replace(by_id[cid], score=round(fused[cid], 6)) for cid in ranked_ids[:k]]


def get_retriever(
    vuln_class: str,
    *,
    prefer_vector: bool = True,
    persist_dir: str | Path = DEFAULT_PERSIST_DIR,
    embedding_function=None,
) -> "KnowledgeRetriever | ChromaKnowledgeRetriever | HybridKnowledgeRetriever":
    """Hybrid retriever when the class collection exists; lexical otherwise."""
    if prefer_vector:
        import chromadb

        client = chromadb.PersistentClient(
            path=str(Path(persist_dir)),
            settings=chromadb.Settings(anonymized_telemetry=False),
        )
        names = {getattr(c, "name", c) for c in client.list_collections()}
        if f"knowledge_{vuln_class}" in names:
            return HybridKnowledgeRetriever(vuln_class, persist_dir=persist_dir,
                                            embedding_function=embedding_function)
    return KnowledgeRetriever(vuln_class)
