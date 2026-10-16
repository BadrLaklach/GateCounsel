# GateCounsel HackTricks Training Resource

This folder contains a small, curated set of synthetic expert-agent examples for the five GateCounsel MVP classes: reflected XSS, IDOR, SQL injection, SSRF, and open redirect. Its layout follows the class-specific Python examples and JSONL generator in `training_resources/payloads_all_the_things/`.

## Contents

- [`source/`](source/README.md): pinned source provenance and short, paraphrased retrieval notes. Upstream HackTricks pages are referenced, not copied into this folder.
- [`training_data/`](training_data/README.md): one synthetic example module per MVP class and a generator for ExpertVerdict-shaped JSONL.
- [`source/source_manifest.json`](source/source_manifest.json): upstream revision, page paths, page hashes, license attribution, and curated source IDs.

## Source and attribution

The notes are based on selected English-language HackTricks pages by Carlos Polop from the local checkout at `../../../hacktricks`, pinned to commit `f66c437539916b7e87d35c17252a26f90878b40f`. HackTricks states that its text is licensed under [Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/), except where material is otherwise attributed. See the upstream [`src/LICENSE.md`](https://github.com/HackTricks-wiki/hacktricks/blob/f66c437539916b7e87d35c17252a26f90878b40f/src/LICENSE.md).

The local notes and examples are original paraphrases and synthetic scenarios informed by the cited pages; they are not a copy of HackTricks' payload lists or write-ups. HackTricks itself notes that some included external material has separate rights. The source manifest records page hashes so the exact reviewed snapshot can be checked.

## Scope

All examples use synthetic `demo-target` fixtures. IDOR examples compare one pair of seeded test records; SQLi examples are read-only and limited to a known result; SSRF examples can address only the isolated `ssrf-sentinel`; open-redirect checks inspect the first `Location` response and never follow it; XSS canaries only set a test DOM marker. No example uses real credentials, customer data, public targets, cloud metadata, data extraction, or state-changing operations.

The dataset is reference material. It does not change GateCounsel runtime behavior, activate a vulnerability class, or grant network permission. Runtime execution must still enforce the current ScopePolicy, fixed harmless-operation allowlist, and deterministic verifier.

## Generate local JSONL

From this directory, run:

```powershell
python .\training_data\generate.py
```

This writes one JSONL file per class under `training_data/generated/`. Run with `--validate-only` to validate the in-memory examples without writing files. Generated JSONL files are ignored by the repository-wide `*.jsonl` rule; the source modules and generator are the reviewable inputs.
