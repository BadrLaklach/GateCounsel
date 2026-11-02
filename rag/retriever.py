"""Per-class lexical retrieval over the knowledge/ chunk store.

The Tier-1 expert's context source (EXPERT_AGENTS_SPEC §5/§6): each expert
retrieves ONLY from its own vulnerability class's chunks. The retriever
loads a single class directory and never sees the others, so cross-class
context leakage is impossible by construction — a stronger guarantee than
separate collections in a shared vector store.

Engine: BM25 over one document per chunk. Title, applies_when and tags are
retrieval anchors, so they are boosted by duplication ahead of body prose.
Pure stdlib, deterministic, offline: the corpus is a few dozen small files,
index build is milliseconds, and identical queries return identical results
(same-score ties break by chunk id) — which is what makes the retrieval
fixtures in tests/test_rag.py a meaningful mini eval harness.

clean-code exception: vector retrieval (ChromaDB, named in the expert spec
§6) is deliberately deferred — it would add a heavy dependency tree and a
runtime embedding-model download for paraphrase robustness this corpus
size does not need. Revisit when the store grows past ~300 chunks or the
eval harness shows paraphrase misses; KnowledgeRetriever.retrieve() is the
seam a vector backend plugs into.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from pathlib import Path

__all__ = ["RetrievedChunk", "KnowledgeRetriever", "parse_chunk", "context_query"]

KNOWLEDGE_ROOT = Path(__file__).resolve().parents[1] / "knowledge"
DEFAULT_K = 3  # spec §5: "Return top-k (k=3 default) chunks"

_TOKEN_RE = re.compile(r"[a-z0-9]+")


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
    return _TOKEN_RE.findall(text.lower())


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
