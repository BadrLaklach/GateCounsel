# Curated ExpertVerdict Examples

These modules are original, synthetic examples informed by the source notes in `../source/src/pentesting-web/`. Each output matches the `ExpertVerdict` shape specified in `agents/experts/EXPERT_AGENTS_SPEC.md`; class values match `agents/planner/models/plan_models.py`.

## Class modules

| Module | GateCounsel class | Safe evidence focus |
|---|---|---|
| `data_xss_reflected.py` | `xss_reflected` | Context-aware reflected input and a local DOM canary |
| `data_idor.py` | `idor` | One authenticated principal and a known synthetic foreign object |
| `data_sqli.py` | `sqli` | One seeded row and a read-only query-semantics probe |
| `data_ssrf.py` | `ssrf` | One unique request observed at the Compose-only sentinel |
| `data_open_redirect.py` | `open_redirect` | First `Location` response checked against an internal allowlist; no follow |

Each scenario contains a synthetic `http://demo-target/...` task, sanitized observation, planner rationale, exact list of approved test values, a gold verdict, and source IDs. The generator puts the observations and approved values in the user message and the gold verdict in the assistant message. It never generates arbitrary endpoints or payload alternatives.

## Generate and validate

From `training_resources/hacktricks/`:

```powershell
python .\training_data\generate.py --validate-only
python .\training_data\generate.py
```

The default output is one `{class}_training_data.jsonl` per class in `training_data/generated/`. Pass `--output-dir PATH` to choose another local directory. `--validate-only` checks class/schema consistency, source IDs, endpoint hosts, and every payload against that row's explicit approved-value list without writing output.

The generated JSONL contains a synthetic value for `model_name` (`training-example`) and `tier1_rag` only to satisfy the documented contract. Confidence is the example's estimated chance of producing its stated signal, not a finding verdict. A runtime model must provide its actual provider/model/tier metadata. The files are training candidates, not a claim that a fine-tuning job or RAG integration exists.

## Safety and interpretation

- Run only against the local seeded demo target represented by these examples.
- The only SSRF destination is `ssrf-sentinel/capture/<case-id>`.
- The only off-origin redirect destination is the pre-registered sentinel capture path; automatic redirects are disabled and the request is not followed.
- IDOR probes read one non-sensitive fixture object; they do not enumerate IDs or write/delete anything.
- SQLi probes are read-only and limited to one known row. No schema discovery, extraction, stacked queries, delay probes, or out-of-band traffic is represented.
- XSS examples use a local canary that only sets a DOM marker. They do not access cookies, storage, credentials, page contents, or network APIs.
- `expected_success_signal` describes what the deterministic verifier should observe. It is not itself a confirmed finding; the verifier remains authoritative.
