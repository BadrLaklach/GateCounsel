# Full Technique Corpus (HackTricks-sourced)

One full-scale technique module per GateCounsel class, in the same 9-field tuple / chat-JSONL format as `../../payloads_all_the_things/training_data/`. Every technique is traceable to a pinned, hash-verified HackTricks page listed in the manifest's `full_technique_corpus` section (`../source/source_manifest.json`, upstream commit `f66c437`).

## Modules

| Module | GateCounsel class | Examples | Coverage (from HackTricks) |
|---|---|---|---|
| `data_sqli_full.py` | `sqli` | 71 | Context breaking, comment syntax, logical/arithmetic confirmation, DBMS fingerprinting (MySQL/MSSQL/Oracle/PG/SQLite/Access), timing per engine, union enumeration incl. `information_schema` alternatives, error-based (`floor(rand)`, `updatexml`), blind/error-blind, stacked queries, OOB (DNS/XXE/`xp_dirtree`/`fn_*`), MSSQL `FOR JSON`/AD enumeration, Oracle `UTL_*`/ACL mapping, PG XML/hex/dollar-quote, WAF bypasses (spaces/commas/operators/scientific/`PREPARE`/FTS), auth bypass (raw hashes/GBK/`ON DUPLICATE KEY`), insert extraction, column-name bypass, identifier/AST injection, routed and truncation injection |
| `data_xss_reflected_full.py` | `xss_reflected` | 48 | All reflection contexts, custom tags, blacklist/space/length bypasses, `javascript:`/`data:` schemes, HTML-entity/unicode/hex/octal encoding bypasses, JS-string and template-literal breakout, JS-in-JS break-inject-repair, `eval(atob())`, parenthesis-free execution, DOM sinks, impact payloads (cookies/beacon/page exfil/internal-IP sweep/CSRF token theft/credential capture), blind XSS, SVG upload, Rails/PHP-filter/Angular quirks, ESI pivot |
| `data_ssrf_full.py` | `ssrf` | 62 | Interaction capture, schemes (`file`/`netdoc`/`tftp`/`ldap`/`gopher` SMTP/Redis/MongoDB), curl globbing, redirect and DNS-rebinding bypasses, SNI proxy, AIA/CA Issuers, CSS `@import`, PDF renderers, CFITSIO filename DSL, proxy parser inconsistencies (Flask `@`, Spring `;@`, PHP `*`, absolute-form), blind upgrades (redirect loops, webhooks), localhost notations (short/decimal/hex/octal/IPv6/circled/CIDR/DNS wildcard), domain parser/confusion, paths/extensions, parameter pollution, IPv6 zones, AWS/GCP/Azure/Oracle/Alibaba/IBM/ECS/EKS/Lambda/Beanstalk metadata, etcd/Docker/Rancher, Referer and command-injection hybrids |
| `data_idor_full.py` | `idor` | 20 | Identifier locations (path/query/body/header), predictable business IDs, same-session tampering, curl/ffuf enumeration, combinatorial two-ID fuzzing, error-message oracles, search-index substring oracles with bidirectional extraction, write-path IDOR, hidden flows, forced browsing, opaque-cursor tampering |
| `data_open_redirect_full.py` | `open_redirect` | 37 | Baselines, loopback notations, wildcard DNS, scheme-relative URLs, userinfo/backslash/bracket parser tricks, prefix/suffix matching flaws, path-based redirects, OAuth/SSO allowlist footguns (regex glob, wildcard path, validate-parsed-redirect-raw), `javascript:` pivots incl. CRLF and scheme-splitting, DOM redirect sinks, fragment smuggling + client-side traversal chains, SVG upload, parser-CVE patterns, parameter discovery workflows, OAuth escalation |

Row format (identical to the PayloadsAllTheThings set): `(endpoint, params, evidence, rationale, payload, injection_point, success_signal, confidence, reasoning)`.

## Generate and validate

From `training_resources/hacktricks/`:

```powershell
python .\training_data\generate_full.py
```

The generator validates every row (schema keys, injection point in {query, body, header, cookie, path}, confidence in [0, 1], (param, payload) uniqueness) and writes one `{class}_full_training_data.jsonl` per class under `generated/`, with the HackTricks attribution embedded in every system prompt. The generated files are versioned with the repo.

## Safety and interpretation

This corpus is real-world technique knowledge for expert-model training, mirroring the PayloadsAllTheThings set: it includes extraction, bypass, cloud-metadata and impact techniques on purpose. It is data, not an authorization — nothing in it may be dispatched by the runtime, and any future executor must still enforce the ScopePolicy, the operation allowlist, and the deterministic verifier independently of what a model trained on this corpus proposes. `expected_success_signal` describes what the verifier should observe; it is never a confirmed finding by itself.
