# Knowledge base — per-class RAG chunks for the expert agents

This directory is the retrieval corpus for the Tier-1 expert agents
(`agents/experts/EXPERT_AGENTS_SPEC.md` §6): one directory per vulnerability
class, one technique per Markdown file, sized so that a retrieval hit returns
precise, actionable context instead of an entire page.

It is **reference material only**. It grants no scope, target, or execution
authorization; runtime execution is governed by the ScopePolicy, the
operation allowlist, and the deterministic verifier. Task→verdict JSONL
examples (few-shot exemplar pools) live under `training_resources/`, not here.

## Layout

```
knowledge/
├── README.md            # this file
├── manifest.json        # upstream provenance and curation method
├── xss_reflected/       # 00-context-matching.md + technique chunks
├── sqli/
├── ssrf/
├── idor/
├── open_redirect/
├── jwt_misconfig/       # hand-written (no gathered corpus yet)
└── auth_bypass/         # hand-written (no gathered corpus yet)
```

## Chunk format

Every chunk is YAML-like frontmatter plus a 100–300 word body:

```markdown
---
id: xss-01-html-body-tag-injection
class: xss_reflected
kind: technique            # technique | context_map
title: Reflected XSS into raw HTML body — tag injection
applies_when: the marker value appears in HTML text, outside any attribute or script context
source: HackTricks XSS README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [raw-html, tag-injection, script, img-onerror]
---

Body: what the recon evidence looks like, what to send (representative
payload family, not an exhaustive dump), why it works in this context, and
the expected success signal the Exploit Agent should verify.
```

Rules:

- `id` equals the filename stem and is unique across the whole store.
- `class` equals the directory name; `kind` is `technique` or `context_map`.
- Every class directory has exactly one `00-context-matching.md` decision map.
- `applies_when` is the retrieval anchor — write it in terms of recon
  evidence (reflection context, error strings, redirect behavior), because
  that is what the expert's query is built from.
- `source` names the upstream corpus and license per chunk; `manifest.json`
  holds the pinned upstream identifiers.
- Body is 100–300 words, own-words paraphrase, no verbatim upstream text.

## Quality gate

`tests/test_knowledge.py` walks every chunk and enforces the rules above
(required keys, id/filename agreement, class consistency, word count, one
context map per class, global id uniqueness). Run it with the normal suite:

```
python -m unittest discover -s tests
```

## Retrieval

`rag/retriever.py` provides three engines behind one interface
(`retrieve(query, k=3) -> list[RetrievedChunk]`):

- **HybridKnowledgeRetriever** — the default once the vector index exists:
  reciprocal-rank fusion (RRF, k=60) of the lexical and vector rankings.
  Empirically each single engine misses queries the other hits (see the
  fixture history in `tests/test_rag.py`), so fusion is the shipping
  engine.
- **ChromaKnowledgeRetriever** — vector retrieval over per-class
  collections (`knowledge_<class>`), cosine similarity.
- **KnowledgeRetriever** — BM25 over the chunk files directly; the
  fallback for fresh clones before the first ingest, and the offline
  engine the suite's retrieval-quality fixtures run against.

`get_retriever(vuln_class)` picks the engine automatically: hybrid when
the class's collection exists, lexical otherwise. Every engine is scoped
to one class by construction — it loads only that class's directory or
collection, so cross-class context leakage is impossible.

## Ingestion (embeddings)

```
pip install -r requirements.txt        # adds chromadb + sentence-transformers
python -m rag.ingest                   # all classes
python -m rag.ingest sqli xss_reflected
```

Ingestion embeds each chunk as anchors (title + applies_when + tags)
followed by body, into per-class collections stored in
`rag/chroma_index/` (gitignored — rebuilt from source anytime). It is
idempotent by content hash: unchanged chunks are skipped, edits are
upserted, deleted chunks are removed. Re-run it after every corpus edit.
ChromaDB's anonymized telemetry is explicitly disabled at every client
construction. The first ingest downloads the MiniLM model (~90 MB,
cached in your home directory).

The real-model end-to-end check (fixtures against a genuinely ingested
index) is env-gated to keep the default suite offline and fast:

```
GATECOUNSEL_EMBEDDINGS_E2E=1 python -m unittest tests.test_rag
```

## Adding a chunk

Copy the format, keep one technique per file at 100–300 words, cite the
source, and add the test to your pre-commit run. A chunk that cannot state
its `applies_when` in one evidence sentence is not a chunk yet — split or
merge it until it can.
