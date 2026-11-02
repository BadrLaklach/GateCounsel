"""Embedding ingestion for the knowledge/ corpus into per-class ChromaDB collections.

Spec §6: one collection per vulnerability class — ``knowledge_<class>`` —
so an expert's retrieval can never return another class's context. Chunks
are embedded as anchor text (title + applies_when + tags) followed by the
body, because the anchors carry the evidence vocabulary queries are built
from; the vector space then sees the same bridging the lexical engine does.

Idempotent by content hash: each chunk's frontmatter + body is hashed
(sha256) and stored as collection metadata; re-ingesting skips unchanged
chunks, upserts edited ones, and deletes ids that no longer exist on disk.
Ingest after every corpus edit; the persisted index lives in
rag/chroma_index/ (gitignored) and is rebuilt from source by::

    python -m rag.ingest            # all classes
    python -m rag.ingest sqli xss_reflected

The embedding function contract is a plain callable mapping
list[str] -> list[vector], invoked explicitly on both the ingest and query
sides (collections store precomputed vectors). The default is
sentence-transformers MiniLM (``all-MiniLM-L6-v2``, 384-dim, local); tests
inject a deterministic hash-based fake so the suite stays offline and fast.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from rag.retriever import (
    DEFAULT_PERSIST_DIR,
    KNOWLEDGE_ROOT,
    default_embedding_function,
    parse_chunk,
)

__all__ = ["content_hash", "default_embedding_function", "ingest_class", "ingest_all"]


def content_hash(meta: dict[str, str], body: str) -> str:
    """Stable hash over a chunk's full content (sorted frontmatter + body)."""
    payload = "\n".join(f"{k}: {v}" for k, v in sorted(meta.items())) + "\n---\n" + body
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _embedded_document(meta: dict[str, str], body: str) -> str:
    tags = meta.get("tags", "").strip("[]")
    anchors = f"{meta.get('title', '')} {meta.get('applies_when', '')} {tags}"
    return f"{anchors}\n\n{body}"


def ingest_class(
    vuln_class: str,
    *,
    knowledge_root: str | Path = KNOWLEDGE_ROOT,
    persist_dir: str | Path = DEFAULT_PERSIST_DIR,
    embedding_function=None,
) -> dict:
    """(Re)ingest one class's chunks into its collection. Returns change stats."""
    import chromadb

    class_dir = Path(knowledge_root) / vuln_class
    if not class_dir.is_dir():
        raise ValueError(f"no knowledge directory for class {vuln_class!r}")
    embed = embedding_function or default_embedding_function()

    client = chromadb.PersistentClient(
        path=str(Path(persist_dir)),
        settings=chromadb.Settings(anonymized_telemetry=False),
    )
    collection = client.get_or_create_collection(
        f"knowledge_{vuln_class}",
        metadata={"hnsw:space": "cosine"},
    )

    current: dict[str, tuple[dict[str, str], str, str]] = {}  # id -> (meta, body, hash)
    for meta, body in (parse_chunk(p) for p in sorted(class_dir.glob("*.md"))):
        current[meta["id"]] = (meta, body, content_hash(meta, body))

    stored = collection.get(include=["metadatas"]) if collection.count() else {}
    stored_hashes = {
        chunk_id: (meta or {}).get("hash", "")
        for chunk_id, meta in zip(stored.get("ids", []), stored.get("metadatas", []))
    }

    changed_ids = [cid for cid, (_m, _b, digest) in current.items()
                   if stored_hashes.get(cid) != digest]
    if changed_ids:
        picked = [(cid, *current[cid]) for cid in changed_ids]
        collection.upsert(
            ids=[cid for cid, _m, _b, _h in picked],
            embeddings=embed([_embedded_document(meta, body)
                              for _cid, meta, body, _h in picked]),
            documents=[body for _cid, _m, body, _h in picked],
            metadatas=[
                {
                    "class": meta["class"],
                    "kind": meta.get("kind", "technique"),
                    "title": meta.get("title", ""),
                    "source": meta.get("source", ""),
                    "applies_when": meta.get("applies_when", ""),
                    "tags": meta.get("tags", "").strip("[]"),
                    "hash": digest,
                }
                for _cid, meta, _body, digest in picked
            ],
        )

    removed = [cid for cid in stored_hashes if cid not in current]
    if removed:
        collection.delete(ids=removed)

    return {
        "class": vuln_class,
        "chunks": len(current),
        "added_or_updated": len(changed_ids),
        "unchanged": len(current) - len(changed_ids),
        "removed": len(removed),
    }


def ingest_all(
    *,
    knowledge_root: str | Path = KNOWLEDGE_ROOT,
    persist_dir: str | Path = DEFAULT_PERSIST_DIR,
    embedding_function=None,
) -> list[dict]:
    """Ingest every class directory under knowledge_root, in sorted order."""
    root = Path(knowledge_root)
    classes = sorted(d.name for d in root.iterdir() if d.is_dir())
    return [
        ingest_class(name, knowledge_root=root, persist_dir=persist_dir,
                     embedding_function=embedding_function)
        for name in classes
    ]


def _main(argv: list[str]) -> int:
    classes = argv[1:]
    unknown = [c for c in classes if not (KNOWLEDGE_ROOT / c).is_dir()]
    if unknown:
        print(f"error: unknown class(es) {', '.join(unknown)}", file=sys.stderr)
        return 2
    stats = [ingest_class(c) for c in classes] if classes else ingest_all()
    for row in stats:
        print(f"{row['class']:<15} chunks={row['chunks']:<3} "
              f"updated={row['added_or_updated']:<3} unchanged={row['unchanged']:<3} "
              f"removed={row['removed']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
