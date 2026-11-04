"""Embedding ingestion for the knowledge/ corpus into per-class ChromaDB collections.

Spec §6: one collection per vulnerability class — ``knowledge_<class>`` —
so an expert's retrieval can never return another class's context.

Safety model (batch 2):

- **Validate before mutating.** The complete source class is parsed and
  validated (required metadata, nonempty fields, filename/ID and
  class/directory agreement, allowed kinds, duplicate IDs, at least one
  chunk) *before* any ChromaDB client or collection is touched. An invalid
  class raises with per-file paths and leaves an existing index intact.
- **Explicit embedding identity.** Collections record which embedding
  identity (model or caller-supplied name, plus embedded-document format
  version) and dimension produced their vectors. Content hashes alone
  never decide vector compatibility; a legacy/unversioned or
  identity-mismatched index is rebuilt from scratch.
- **Rebuilds cannot masquerade as complete.** A rebuilt collection is
  created with ``status: building`` and flipped to ``ready`` only after
  every vector is upserted; query construction rejects anything not
  ``ready``. The old collection is deleted only *after* the new embeddings
  exist, so a failing embedder never destroys the previous index.
- **Content manifest binding.** Each ready collection records a
  content-addressed manifest of its source class; HybridKnowledgeRetriever
  refuses to fuse when the on-disk corpus has drifted (edits, deletions).

Ingest after every corpus edit; the persisted index lives in
rag/chroma_index/ (gitignored) and is rebuilt from source by::

    python -m rag.ingest            # all classes
    python -m rag.ingest sqli xss_reflected

The embedding function contract is a plain callable mapping
list[str] -> list[vector], invoked explicitly on both the ingest and query
sides. The default is sentence-transformers MiniLM; custom callables must
declare a stable ``embedding_identity`` (see resolve_embedding_identity).
"""

from __future__ import annotations

import sys
from pathlib import Path

from rag.retriever import (
    DEFAULT_PERSIST_DIR,
    EMBEDDING_DOC_FORMAT,
    KNOWLEDGE_ROOT,
    content_hash,
    corpus_manifest,
    default_embedding_function,
    parse_chunk,
    resolve_embedding_identity,
)

__all__ = ["ALLOWED_KINDS", "REQUIRED_KEYS", "content_hash", "corpus_manifest",
           "default_embedding_function", "ingest_class", "ingest_all",
           "validate_class_chunks"]

# Corpus rules shared with tests/test_knowledge.py (single owner: the
# ingestion gate is the enforcement point; the test walks the real repo).
REQUIRED_KEYS = ["id", "class", "kind", "title", "applies_when", "source", "tags"]
ALLOWED_KINDS = {"technique", "context_map"}


def validate_class_chunks(parsed: list[tuple[Path, dict[str, str], str]],
                          vuln_class: str) -> None:
    """Validate one class's parsed chunks; raise ValueError listing every
    problem with its file path, or return silently."""
    problems: list[str] = []
    ids_seen: dict[str, Path] = {}
    for path, meta, body in parsed:
        for key in REQUIRED_KEYS:
            if not meta.get(key, "").strip():
                problems.append(f"{path}: missing or empty frontmatter key {key!r}")
        if meta.get("id") != path.stem:
            problems.append(f"{path}: id {meta.get('id')!r} must equal filename stem {path.stem!r}")
        if meta.get("class") != vuln_class:
            problems.append(f"{path}: class {meta.get('class')!r} must equal directory {vuln_class!r}")
        if meta.get("kind") not in ALLOWED_KINDS:
            problems.append(f"{path}: kind {meta.get('kind')!r} not in {sorted(ALLOWED_KINDS)}")
        if not body.strip():
            problems.append(f"{path}: empty body")
        prior = ids_seen.setdefault(meta.get("id", ""), path)
        if prior != path:
            problems.append(f"{path}: duplicate id {meta.get('id')!r} (already seen in {prior})")
    if problems:
        raise ValueError(f"invalid knowledge class {vuln_class!r}:\n" + "\n".join(problems))


def _embedded_document(meta: dict[str, str], body: str) -> str:
    tags = meta.get("tags", "").strip("[]")
    anchors = f"{meta.get('title', '')} {meta.get('applies_when', '')} {tags}"
    return f"{anchors}\n\n{body}"


def _chunk_metadata(meta: dict[str, str], body: str) -> dict:
    return {
        "class": meta["class"],
        "kind": meta.get("kind", "technique"),
        "title": meta.get("title", ""),
        "source": meta.get("source", ""),
        "applies_when": meta.get("applies_when", ""),
        "tags": meta.get("tags", "").strip("[]"),
        "hash": content_hash(meta, body),
    }


def _version_metadata(identity: str, dim: int, *, status: str,
                      manifest: str | None = None) -> dict:
    metadata = {
        "status": status,
        "embedding_identity": identity,
        "embedding_dim": dim,
        "doc_format_version": EMBEDDING_DOC_FORMAT,
    }
    if manifest is not None:
        metadata["corpus_manifest"] = manifest
    return metadata
    # NOTE: no 'hnsw:space' here — chroma 1.5 refuses modify() calls that
    # carry it (even unchanged). Distance stays cosine from creation time.


def ingest_class(
    vuln_class: str,
    *,
    knowledge_root: str | Path = KNOWLEDGE_ROOT,
    persist_dir: str | Path = DEFAULT_PERSIST_DIR,
    embedding_function=None,
    embedding_identity: str | None = None,
) -> dict:
    """(Re)ingest one class's chunks into its collection. Returns change stats."""
    import chromadb

    class_dir = Path(knowledge_root) / vuln_class
    if not class_dir.is_dir():
        raise ValueError(f"no knowledge directory for class {vuln_class!r}")

    # 1) parse + validate the WHOLE source class before touching the index
    parsed = [(path, *parse_chunk(path)) for path in sorted(class_dir.glob("*.md"))]
    if not parsed:
        raise ValueError(f"knowledge directory for {vuln_class!r} has no chunks")
    validate_class_chunks(parsed, vuln_class)
    chunks = [(meta, body) for _path, meta, body in parsed]

    embed = embedding_function or default_embedding_function()
    identity = resolve_embedding_identity(embedding_function, embedding_identity)

    # 2) inspect the existing collection's version block
    client = chromadb.PersistentClient(
        path=str(Path(persist_dir)),
        settings=chromadb.Settings(anonymized_telemetry=False),
    )
    name = f"knowledge_{vuln_class}"
    stored_meta: dict = {}
    collection = None
    try:
        collection = client.get_collection(name)
        stored_meta = collection.metadata or {}
    except chromadb.errors.NotFoundError:
        pass

    versioned_ready = (
        collection is not None
        and stored_meta.get("status") == "ready"
        and stored_meta.get("embedding_identity") == identity
    )

    if not versioned_ready:
        # 3) full rebuild — legacy/unversioned or different embedding identity.
        # Embed FIRST: a failing embedder must not destroy the old index.
        replaced = collection is not None
        vectors = embed([_embedded_document(meta, body) for meta, body in chunks])
        dim = len(vectors[0])
        manifest = corpus_manifest(chunks)
        if collection is not None:
            client.delete_collection(name)
        collection = client.get_or_create_collection(name, metadata={
            "hnsw:space": "cosine",  # fixed at creation; omitted from later modify()
            **_version_metadata(identity, dim, status="building"),
        })
        collection.upsert(
            ids=[meta["id"] for meta, _body in chunks],
            embeddings=vectors,
            documents=[body for _meta, body in chunks],
            metadatas=[_chunk_metadata(meta, body) for meta, body in chunks],
        )
        collection.modify(metadata=_version_metadata(identity, dim, status="ready",
                                                    manifest=manifest))
        return {"class": vuln_class, "chunks": len(chunks), "added_or_updated": len(chunks),
                "unchanged": 0, "removed": 0, "rebuilt": replaced}

    # 4) incremental path — same identity, ready index: hash-diff as before
    current: dict[str, tuple[dict[str, str], str, str]] = {}  # id -> (meta, body, hash)
    for meta, body in chunks:
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
        vectors = embed([_embedded_document(meta, body)
                         for _cid, meta, body, _h in picked])
        dim = len(vectors[0])
        stored_dim = int(stored_meta.get("embedding_dim", dim))
        if dim != stored_dim:
            raise ValueError(
                f"embedding dimension changed ({stored_dim} -> {dim}) under identity "
                f"{identity!r}; give the changed embedder a distinct embedding_identity "
                f"and re-ingest")
        collection.upsert(
            ids=[cid for cid, _m, _b, _h in picked],
            embeddings=vectors,
            documents=[body for _cid, _m, body, _h in picked],
            metadatas=[_chunk_metadata(meta, body) for _cid, meta, body, _h in picked],
        )

    removed = [cid for cid in stored_hashes if cid not in current]
    if removed:
        collection.delete(ids=removed)

    if changed_ids or removed:
        stored_dim = int(stored_meta.get("embedding_dim", 0))
        collection.modify(metadata=_version_metadata(identity, stored_dim, status="ready",
                                                    manifest=corpus_manifest(chunks)))

    return {
        "class": vuln_class,
        "chunks": len(current),
        "added_or_updated": len(changed_ids),
        "unchanged": len(current) - len(changed_ids),
        "removed": len(removed),
        "rebuilt": False,
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
              f"removed={row['removed']:<3} rebuilt={row['rebuilt']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
