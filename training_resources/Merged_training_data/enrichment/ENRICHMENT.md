# Enrichment Log — Merged_training_data variant generation

Date: 2026-10-18 · Result: **467 → 599 examples** (+135 accepted, −3 defective
seed rows removed)

## Method

1. **Seeds**: for each class, 24 verified payloads were sampled (spread across
   the existing merged file) and grouped into 8 batches of 3.
2. **Generation**: 40 opencode free-model runs (glm-5.3-flash-free,
   deepseek-v4.1-flash-free, mimo-v2.6-flash-free, space-bunny-free; 3
   concurrent, 330s timeout) each produced 5 scenario variants. Agents were
   required to reuse a seed payload VERBATIM and vary only the scenario
   (endpoint, parameter, recon evidence, rationale, success signal, reasoning).
   201 raw variants returned.
3. **Mechanical gates** (`enrich_verify.py`): payload whitelist membership
   (exact match against the class's verified payloads), 10-key schema,
   injection-point enum, confidence range, minimum field lengths, refusal-text
   check, dedup vs existing rows and within the batch. 144 passed; 57 rejected
   (mostly duplicate (param,payload) keys and one mutated payload caught by the
   whitelist).
4. **Human review** (`review_dump.txt`, `accepted_candidates.json`): all 144
   survivors read; 9 rejected for technical reasons (below). 135 accepted.

## Review rejections (9)

| Class | Reason |
|---|---|
| sqli ×2 | variants of a seed payload that is invalid SQL (`1 AND SELECT SUBSTR...`) |
| sqli ×1 | evidence describes a generic 500 handler (errors suppressed) but payload is error-based EXTRACTVALUE |
| ssrf ×1 | evidence itself states the double-encoded path was blocked — contradicts recommending it |
| ssrf ×1 | raw HTTP request-line payload (`GET @evildomain.com/ HTTP/1.1`) does not fit a parameter-submission scenario |
| ssrf ×1 | payload field contained descriptive prose (`...chain: 302 -> ...`), not a URL |
| idor ×3 | assistant payload path (`/api/user/1233`) did not match the endpoint in the scenario |

## Defective seed rows removed from the pre-existing merged data (3)

Found while tracing bad variants to their seeds:
- `ssrf`: 2 rows whose payload field held a raw request line or prose
  (`GET @evildomain.com/ HTTP/1.1`; `http://ATTACKER/start (chain: 302 -> ...)`).
- `sqli`: 1 row with the syntactically invalid `1 AND SELECT SUBSTR(...)` payload.

## Accepted additions per class

| Class | Before | Added | Removed | After |
|---|---|---|---|---|
| sqli | 141 | 32 | 1 | 172 |
| ssrf | 129 | 31 | 2 | 158 |
| idor | 61 | 11 | 0 | 72 |
| open_redirect | 88 | 26 | 0 | 114 |
| xss_reflected | 48 | 35 | 0 | 83 |

All appended rows reuse payloads already verified in this dataset verbatim; the
generated prose (evidence/rationale/reasoning) passed per-row technical review.
New contexts cover cookie/header/path injection points, WAF-filter variations,
quoted-attribute and JS-string reflection contexts (xss), GraphQL/persisted
query and legacy-route variants (idor), and scheme/prefix-filter variations
(open redirect).

Known residual: the merged files (pre-existing convention) allow the same
(target_param, payload) under different evidence scenarios; the apply step only
prevents exact re-additions, it does not collapse that variety.

## Reproduce

```
python enrichment/enrich_generate.py   # opencode generation -> raw/
python enrichment/enrich_verify.py     # gates -> accepted_candidates.json
python enrichment/enrich_apply.py      # reviewed apply + bad-seed removal
```
