# GateCounsel HackTricks Training Resource

This folder contains a small, curated set of synthetic expert-agent examples for the five GateCounsel MVP classes: reflected XSS, IDOR, SQL injection, SSRF, and open redirect. Its layout follows the class-specific Python examples and JSONL generator in `training_resources/payloads_all_the_things/`.

## Contents

- [`source/`](source/README.md): pinned source provenance and short, paraphrased retrieval notes. Upstream HackTricks pages are referenced, not copied into this folder.
- [`training_data/`](training_data/README.md): two datasets —
  - the **MVP contract examples** (`data_<class>.py` + `generate.py`): 15 bounded, ExpertVerdict-shaped examples used as the reviewed seed for the five-class MVP pipeline; and
  - the **full technique corpus** (`data_<class>_full.py` + `generate_full.py`): a large, real-world technique dataset in the same chat-JSONL format as `training_resources/payloads_all_the_things/training_data/`, built from the pinned HackTricks pages for expert-model training research.
- [`source/source_manifest.json`](source/source_manifest.json): upstream revision, page paths, page hashes, license attribution, curated source IDs, and the `full_technique_corpus` page list covering the full-scale modules.

## Source and attribution

The notes are based on selected English-language HackTricks pages by Carlos Polop from the local checkout at `../../../hacktricks`, pinned to commit `f66c437539916b7e87d35c17252a26f90878b40f`. HackTricks states that its text is licensed under [Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/), except where material is otherwise attributed. See the upstream [`src/LICENSE.md`](https://github.com/HackTricks-wiki/hacktricks/blob/f66c437539916b7e87d35c17252a26f90878b40f/src/LICENSE.md).

The local notes and examples are original paraphrases and synthetic scenarios informed by the cited pages; they are not a copy of HackTricks' payload lists or write-ups. HackTricks itself notes that some included external material has separate rights. The source manifest records page hashes so the exact reviewed snapshot can be checked.

## Scope

All examples use synthetic `demo-target` fixtures. IDOR examples compare one pair of seeded test records; SQLi examples are read-only and limited to a known result; SSRF examples can address only the isolated `ssrf-sentinel`; open-redirect checks inspect the first `Location` response and never follow it; XSS canaries only set a test DOM marker. No example uses real credentials, customer data, public targets, cloud metadata, data extraction, or state-changing operations.

The dataset is reference material. It does not change GateCounsel runtime behavior, activate a vulnerability class, or grant network permission. Runtime execution must still enforce the current ScopePolicy, fixed harmless-operation allowlist, and deterministic verifier.

## Generate local JSONL

From this directory, run:

```powershell
python .\training_data\generate.py          # MVP contract examples (15, ExpertVerdict shape)
python .\training_data\generate_full.py     # full technique corpus (238, chat-JSONL like the PAT set)
```

`generate.py` writes one `{class}_training_data.jsonl` per class under `training_data/generated/`; run it with `--validate-only` to validate without writing. `generate_full.py` writes `{class}_full_training_data.jsonl` in the same folder. Generated JSONL files are ignored by the repository-wide `*.jsonl` rule; the source modules and generators are the reviewable inputs.

## Two datasets, two purposes

| Dataset | Files | Shape | Purpose |
|---|---|---|---|
| MVP contract examples | `data_<class>.py`, `generate.py` | 16-field `ExpertVerdict`, lab-bounded, `approved_test_values` enforced | Reviewed seed matching the MVP expert/exploit handoff; safe-by-construction |
| Full technique corpus | `data_<class>_full.py`, `generate_full.py` | 7-field chat JSONL (`vuln_class, target_param, payload, injection_point, expected_success_signal, confidence, reasoning`), same format as the PayloadsAllTheThings set | Large-scale expert-model training research covering real-world techniques per class |

The full corpus is deliberately **not** constrained to the lab allowlist — it encodes real technique knowledge (error-based SQLi extraction vectors, cloud metadata SSRF, filter-bypass families, parser differentials, and so on) so the class experts can be trained on the same breadth as the PayloadsAllTheThings modules, with HackTricks as the source of record. Every module maps to pinned, hash-verified upstream pages recorded in the manifest's `full_technique_corpus` section, and the generated system prompts carry the HackTricks attribution. It is reference/training material only: it changes no GateCounsel runtime behavior and grants no scope, target, or execution authorization.
