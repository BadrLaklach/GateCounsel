# GateCounsel HackTricks Training Resource

This folder contains a full-scale expert-agent training corpus for the five GateCounsel classes: reflected XSS, IDOR, SQL injection, SSRF, and open redirect. It follows the same chat-JSONL format as `training_resources/payloads_all_the_things/training_data/`, with the pinned HackTricks checkout as the source of record.

## Contents

- [`source/`](source/README.md): pinned source provenance and short, paraphrased retrieval notes. Upstream HackTricks pages are referenced, not copied into this folder.
- [`training_data/`](training_data/README.md): one full-scale technique module per class (`data_<class>_full.py`, 238 examples total) and `generate_full.py`, which validates them and emits chat-format JSONL.
- [`source/source_manifest.json`](source/source_manifest.json): upstream revision, page paths, page hashes, license attribution, curated source IDs, and the `full_technique_corpus` page list mapping every module to its hash-verified upstream pages.

## Source and attribution

The techniques are taken from selected English-language HackTricks pages by Carlos Polop from the local checkout at `../../../hacktricks`, pinned to commit `f66c437539916b7e87d35c17252a26f90878b40f`. HackTricks states that its text is licensed under [Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/), except where material is otherwise attributed. See the upstream [`src/LICENSE.md`](https://github.com/HackTricks-wiki/hacktricks/blob/f66c437539916b7e87d35c17252a26f90878b40f/src/LICENSE.md).

The scenario framing, evidence strings and reasoning are original to this project; the manifest records per-page SHA-256 hashes so the exact reviewed snapshot can always be checked against the pinned checkout.

## Scope

This corpus encodes real-world technique knowledge on purpose — extraction vectors, filter-bypass families, cloud metadata endpoints, parser differentials — so the class experts can be trained on the same breadth as the PayloadsAllTheThings modules. It is reference and training data only: it does not change GateCounsel runtime behavior and grants no scope, target, or execution authorization. Any runtime executor must still enforce the ScopePolicy, the operation allowlist, and the verifier independently of what a model trained on this corpus proposes.

## Generate local JSONL

From this directory, run:

```powershell
python .\training_data\generate_full.py
```

This writes one `{class}_full_training_data.jsonl` per class under `training_data/generated/`. Generated JSONL files are ignored by the repository-wide `*.jsonl` rule; the source modules and the generator are the reviewable inputs.
