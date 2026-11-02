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

## Ingestion (when rag/ is built)

One ChromaDB collection per class (`knowledge_<class>`, per the expert spec)
so retrieval can never leak cross-class context. A chunk file is embedded as
a unit; the frontmatter becomes document metadata, and `source` flows into
`ExpertVerdict.retrieved_sources`.

## Adding a chunk

Copy the format, keep one technique per file at 100–300 words, cite the
source, and add the test to your pre-commit run. A chunk that cannot state
its `applies_when` in one evidence sentence is not a chunk yet — split or
merge it until it can.
