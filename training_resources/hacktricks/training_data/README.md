# Curated ExpertVerdict Examples + Full Technique Corpus

This folder holds **two datasets**, both traceable to the pinned HackTricks checkout:

1. **MVP contract examples** (`data_<class>.py`, `generate.py`) — original, synthetic examples informed by the curated notes in `../source/src/pentesting-web/`. Each output matches the 16-field `ExpertVerdict` shape specified in `agents/experts/EXPERT_AGENTS_SPEC.md`; class values match `agents/planner/models/plan_models.py`. These remain the reviewed, lab-bounded MVP seed.

2. **Full technique corpus** (`data_<class>_full.py`, `generate_full.py`) — large, real-world technique datasets in the same 9-field tuple / 7-field chat-JSONL format as `../../payloads_all_the_things/training_data/`. Techniques are taken from the pinned HackTricks pages listed in the manifest's `full_technique_corpus` section (entry-point detection, DBMS identification, union/error/blind/time-based/OOB SQLi, WAF bypasses, XSS contexts and encoding bypasses, SSRF schemes and cloud metadata, URL-format bypasses, IDOR enumeration workflows, open-redirect filter evasion, and more).

## Class modules (MVP contract examples)

| Module | GateCounsel class | Safe evidence focus |
|---|---|---|
| `data_xss_reflected.py` | `xss_reflected` | Context-aware reflected input and a local DOM canary |
| `data_idor.py` | `idor` | One authenticated principal and a known synthetic foreign object |
| `data_sqli.py` | `sqli` | One seeded row and a read-only query-semantics probe |
| `data_ssrf.py` | `ssrf` | One unique request observed at the Compose-only sentinel |
| `data_open_redirect.py` | `open_redirect` | First `Location` response checked against an internal allowlist; no follow |

Each scenario contains a synthetic `http://demo-target/...` task, sanitized observation, planner rationale, exact list of approved test values, a gold verdict, and source IDs. The generator puts the observations and approved values in the user message and the gold verdict in the assistant message. It never generates arbitrary endpoints or payload alternatives.

## Full technique modules

| Module | GateCounsel class | Examples | Coverage (from HackTricks) |
|---|---|---|---|
| `data_sqli_full.py` | `sqli` | 71 | Context breaking, comment syntax, logical/arithmetic confirmation, DBMS fingerprinting (MySQL/MSSQL/Oracle/PG/SQLite/Access), timing per engine, union enumeration incl. `information_schema` alternatives, error-based (`floor(rand)`, `updatexml`), blind/error-blind, stacked queries, OOB (DNS/XXE/`xp_dirtree`/`fn_*`), MSSQL `FOR JSON`/AD enumeration, Oracle `UTL_*`/ACL mapping, PG XML/hex/dollar-quote, WAF bypasses (spaces/commas/operators/scientific/`PREPARE`/FTS), auth bypass (raw hashes/GBK/`ON DUPLICATE KEY`), insert extraction, column-name bypass, identifier/AST injection, routed and truncation injection |
| `data_xss_reflected_full.py` | `xss_reflected` | 48 | Raw-HTML and attribute contexts, custom tags, blacklist/space/length bypasses, `javascript:`/`data:` schemes, HTML-entity/unicode/hex/octal encoding bypasses, JS-string and template-literal breakout, JS-in-JS break-inject-repair, `eval(atob())`, parenthesis-free execution, DOM sinks, impact payloads (cookies/beacon/page exfil/internal-IP sweep/CSRF token theft/credential capture), blind XSS, SVG upload, Rails/PHP-filter/Angular quirks, ESI pivot |
| `data_ssrf_full.py` | `ssrf` | 62 | Interaction capture, schemes (`file`/`netdoc`/`tftp`/`ldap`/`gopher` SMTP/Redis/MongoDB), curl globbing, redirect and DNS-rebinding bypasses, SNI proxy, AIA/CA Issuers, CSS `@import`, PDF renderers, CFITSIO filename DSL, proxy parser inconsistencies (Flask `@`, Spring `;@`, PHP `*`, absolute-form), blind upgrades (redirect loops, webhooks), localhost notations (short/decimal/hex/octal/IPv6/circled/CIDR/DNS wildcard), domain parser/confusion, paths/extensions, parameter pollution, IPv6 zones, AWS/GCP/Azure/Oracle/Alibaba/IBM/ECS/EKS/Lambda/Beanstalk metadata, etcd/Docker/Rancher, Referer and command-injection hybrids |
| `data_idor_full.py` | `idor` | 20 | Identifier locations (path/query/body/header), predictable business IDs, same-session tampering, curl/ffuf enumeration, combinatorial two-ID fuzzing, error-message oracles, search-index substring oracles with bidirectional extraction, write-path IDOR, hidden flows, forced browsing, opaque-cursor tampering |
| `data_open_redirect_full.py` | `open_redirect` | 37 | Baselines, loopback notations, wildcard DNS, scheme-relative URLs, userinfo/backslash/bracket parser tricks, prefix/suffix matching flaws, path-based redirects, OAuth/SSO allowlist footguns (regex glob, wildcard path, validate-parsed-redirect-raw), `javascript:` pivots incl. CRLF and scheme-splitting, DOM redirect sinks, fragment smuggling + client-side traversal chains, SVG upload, parser-CVE patterns, parameter discovery workflows, OAuth escalation |

Row format (identical to the PayloadsAllTheThings set): `(endpoint, params, evidence, rationale, payload, injection_point, success_signal, confidence, reasoning)`. `generate_full.py` validates each row (schema, injection point, confidence range, uniqueness) and emits `{class}_full_training_data.jsonl` under `generated/`, with the HackTricks attribution embedded in every system prompt.

## Generate and validate

From `training_resources/hacktricks/`:

```powershell
python .\training_data\generate.py --validate-only    # MVP contract examples: schema + provenance only
python .\training_data\generate.py                    # writes {class}_training_data.jsonl
python .\training_data\generate_full.py               # writes {class}_full_training_data.jsonl
```

`generate.py` defaults to one `{class}_training_data.jsonl` per class in `training_data/generated/` (`--output-dir PATH` to choose another directory). `--validate-only` checks class/schema consistency, source IDs, endpoint hosts, and every payload against that row's explicit approved-value list without writing output. `generate_full.py` writes the full-corpus JSONL files beside them and enforces its own schema/injection-point/confidence/uniqueness checks.

The generated JSONL contains a synthetic value for `model_name` (`training-example`) and `tier1_rag` only to satisfy the documented contract. Confidence is the example's estimated chance of producing its stated signal, not a finding verdict. A runtime model must provide its actual provider/model/tier metadata. The files are training candidates, not a claim that a fine-tuning job or RAG integration exists.

## Safety and interpretation

The two datasets carry different guarantees — read this before wiring either one anywhere:

- **MVP contract examples (`data_<class>.py`)** are bounded by construction: run them only against the local seeded demo target they describe; the only SSRF destination is `ssrf-sentinel/capture/<case-id>`; the only off-origin redirect destination is the pre-registered sentinel capture path with redirects disabled and never followed; IDOR probes read one non-sensitive fixture object; SQLi probes are read-only against one known row; XSS canaries only set a DOM marker.
- **Full technique corpus (`data_<class>_full.py`)** is real-world technique knowledge for expert-model training, mirroring the PayloadsAllTheThings set: it includes extraction, bypass, cloud-metadata and impact techniques on purpose. It is data, not an authorization: nothing in it may be dispatched by the runtime, and any future executor must still enforce the ScopePolicy, the operation allowlist, and the verifier independently of what a model trained on this corpus proposes.
- For both datasets, `expected_success_signal` describes what the verifier should observe. It is not itself a confirmed finding; the verifier remains authoritative.
