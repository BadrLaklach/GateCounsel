# Data Sources & Verification Log

Provenance for every externally-sourced training example in this directory.
Internal ground truth: the PayloadsAllTheThings markdowns in this repository
(`SQL Injection/`, `Server Side Request Forgery/`, `Insecure Direct Object References/`,
`Open Redirect/`).

## 1. Disclosed HackerOne reports (24 examples added: 6 per vuln class)

Archive: [ajaysenr/HackerOne-Disclosed-Reports](https://github.com/ajaysenr/HackerOne-Disclosed-Reports)
(downloaded `by-weakness/*.md` indexes + top-bounty report files into `sources/h1/reports/`).
Digestion: four sub-agents extracted ONLY facts stated in each report; reports whose
disclosure was program-summary-only ("thin") were excluded.

Authenticity cross-check: every report ID used was independently confirmed in a second
archive, [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports)
(`sources/reddelexc.csv`, 15,050 reports) with matching title and vulnerability class —
23/23 IDs confirmed (`python sources/verify_ids.py` reproduces this).

| Report ID | Class | Technique | Adaptation notes |
|---|---|---|---|
| 298176 (CVE-2017-0914) | sqli | ORDER BY CASE SUBSTR sort-oracle | username generalized to 'target' |
| 150156 | sqli | base64(JSON) blind sleep(12) + mid(user()) enum | base64 blob kept verbatim; decoded payload verified locally |
| 838855 | sqli | CASE/**/WHEN space-filter bypass + conditional SLEEP | zero-width chars from report text stripped |
| 398799 | ssrf | Host-header SSRF (GitLab Jira OAuth) | listener host generalized to ATTACKER_SERVER |
| 776017 (CVE-2020-8555) | ssrf | k8s StorageClass resturl + `#` truncation | attacker domain generalized; 302-to-metadata noted in reasoning |
| 374737 | ssrf | Sentry stacktrace `filename` blind OOB | JSON body compacted, host generalized |
| 1628209 | ssrf | server-side PDF renderer iframe -> AWS metadata | role name kept as ROLE_NAME placeholder |
| 1960765 | ssrf | Matrix preview_url internal enumeration via og:title | redacted internal hosts generalized |
| 826361 | ssrf | CarrierWave remote_attachment_url on import | note JSON compacted, host generalized |
| 2207248 | idor | GraphQL variables.id cross-tenant invoice read | invoice id placeholder VICTIM_BILLING_INVOICE_ID |
| 1658418 | idor | persisted GraphQL subredditName mod-log read | persisted-query id placeholder |
| 3862641 | idor | reference.json 422 error-body leak | request kept verbatim otherwise |
| 1213237 | idor | DELETE DM with own CSRF/session vs victim id | message id kept from report |
| 743953 | idor | project.json issue_ids import attach | payload line verbatim from report |
| 1819832 | idor | DeleteStorySnaps ids array swap | id placeholder VICTIM_SPOTLIGHT_ID |
| 904059 (CVE-2020-8264) | open_redirect | Rails /rails/actions location param | demo target replaced with evil.com |
| 104087 | open_redirect | checkcookie redir -> whitelisted-subdomain SVG onload | slack.com generalized to target.com; file path placeholders |
| 635597 | open_redirect | RTLO (U+202E) host display spoof | payload URL verbatim |
| 683298 | open_redirect | login next= absolute URL (+ javascript:) | target generalized |
| 1788006 | open_redirect | ?logout=<url> flag/URL dual use | target generalized |
| 49759 | open_redirect | follow-action recipient leak of CSRF token | payload value verbatim |

Excluded (thin disclosures, no endpoint/payload detail): 1145428, 1250037, 3124517, 415081,
1409727, 2429894, 2585385, 333419, 746024, 892049, 125932, 206872, 361623, 383127, 403616,
476150, 952501, 1865991, 469803, 781673. (836079 digested but superseded by 838855 - same
payload family; 273946 superseded by 298176 - clearer manual payload.)

## 2. External payload corpora

- [cujanovic/Open-Redirect-Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
  (`sources/Open-Redirect-Payloads/`, 560 unique payloads): diffed against the repo's own
  Intruder list (`sources/diff_cujanovic.py`): 443 not already covered, but all are
  combinatorial variants of technique families already taught (slash counts, dot-dot
  encodings, @-userinfo, %09/%5c smuggling, localdomain.pw wildcard-DNS). Used as
  CORROBORATION only; no new rows (wildcard-DNS family already covered via nip.io row).
- [foospidy/payloads](https://github.com/foospidy/payloads) (GPL-3.0; `sources/foospidy/sqli/`):
  - ACCEPTED (2 examples): `harisec.txt` `'XOR(if(now()=sysdate(),sleep(5*5),0))OR'`
    (also verbatim in this repo's `SQL Injection/MySQL Injection.md` line 370 — double
    corroboration) and `c0rni3sm.txt` `8888'+AND+(@@TEXTSIZE>@@LANGID)+AND+'1'+LIKE+'1 --`
    (valid MSSQL system-variable boolean).
  - REJECTED: `libinjection-bypasses.txt` (474 lines) and `d0znpp.txt` quote-mangled rows —
    tokenizer-fuzz mutations (`or \.<\ or 1=1`), not valid SQL.
  - A SQLite UNION row was added grounded in this repo's SQLite Injection.md
    (sqlite_master), motivated by d0znpp's SQLite entries (which were typographically
    corrupted and thus not used verbatim).

## 3. Audited and REJECTED datasets

- [PurpleAILAB/chatML_SQL_injection_dataset](https://huggingface.co/datasets/PurpleAILAB/chatML_SQL_injection_dataset)
  (1,996 ChatML rows, fetched to `sources/purpleailab_chatml.json`): concept-Q&A rows are
  generic; payload-generation rows are dominated by libinjection-style fuzz mutations
  (`1.<@.' or 1 = 1 -- 1`, `1 +$ .' or 1 = 1 -- 1`) that are not valid SQL. Rejected for
  training; do not mix in.
- Hugging Face `ssrf`/`idor`/`open redirect` dataset searches: empty datasets, personal
  probe sets, or name collisions — nothing usable (verified 2026-10).

## 4. Round 2 — opencode free-model orchestration (17 examples added)

Pipeline (`sources/round2_fetch.py`, `round2_extract.py`, `round2_verify.py`):
1. Downloaded reports ranked 13-30 per class (72 files); dropped 3 IDs not present in the
   reddelexc archive and 29 thin (program-summary-only) files locally -> 41 candidates.
2. Delegated extraction to opencode free models (v2.0.31 desktop CLI): glm-5.3-flash-free,
   deepseek-v4.1-flash-free, nemotron-3.5-lightning-free, mimo-v2.6-flash-free,
   longcat-2.5-preview-free, space-bunny-free; 3 concurrent max, 240-330s per run.
   39/41 extracted (2 persistent no-json drops: idor_2528293, idor_980511).
3. Every agent quote was script-verified as a whitespace-normalized substring of the source
   report file; 27/39 had quality=good with endpoint+payload quotes verified
   (1 auto-rejected on a failed quote: ssrf_1544133).
4. Orchestrator review selected 17; 10 verified-but-redundant extractions rejected.

Accepted (payloads quote-verified; redactions generalized):

| Report ID | Class | Technique |
|---|---|---|
| 1372216 | idor | external_status_check_id instance-wide lookup |
| 1751258 | idor | noteable type swap (issue -> personal_snippet) |
| 1892200 | idor | epic parent_id cross-group attach |
| 514897 | idor | selectedAddressId cookie + zone-gated enumeration |
| 853130 | idor | variant-settings object id cross-store update |
| 1719719 | ssrf | Exchange autodiscover.json path confusion (CVE-2022-41040) |
| 265050 | ssrf | SVG fill url() server-side fetch |
| 429617 | ssrf | reverse-proxy Host misroute -> X-Shopify-Access-Token theft |
| 446593 | ssrf | GitHub-integration repo URL redirect to 127.0.0.1 |
| 855276 | ssrf | import_url .proxy= git-config injection |
| 1650264 | sqli | Android ContentProvider selection injection (GHSL-2022-059) |
| 291764 | sqli | Android ContentProvider projection injection |
| 2958619 | sqli | URL path-segment injection probe |
| 297478 | sqli | User-Agent header XOR timing (real-world use of the harisec payload) |
| 28865 | open_redirect | /../ bypass of a /redirect string filter on a signed endpoint |
| 3930 | open_redirect | OAuth authorize redirect_uri -> access-token theft |
| 55525 | open_redirect | invalid-scope error path honoring redirect_uri |

Verified but rejected (redundant/weak, quality over quantity): 1626508 (dup of unauthenticated
document-download row), 404797 (dup delete-IDOR, weak payload quote), 1066410 (payload not a
concrete URL), 3596 (dup of 3930 technique), 50752 (dup of 49759 authenticity_token family),
1044698 (redundant time-based MySQL), 518669 (same vector as 291764), 844428 (Solr injection,
wrong class), 923020 (payload quote does not demonstrate the injection), ssrf_1624140
(redundant with existing metadata rows).

## 5. Round 3 — opencode free-model orchestration (12 examples added)

Same pipeline on reports ranked 31-55 per class (`sources/round3_*.py`):
100 downloaded -> 99 ID-confirmed, 41 thin-prefiltered -> 58 candidates ->
56 extracted across 7 free models (added beam-free, muse-spark-1.3-contributor-free,
nemotron-3-ultra-free to the rotation) -> 35 good with all quotes script-verified ->
12 accepted after review (34% acceptance; this tier is dominated by technique
duplicates of already-covered material).

Accepted:

| Report ID | Class | Technique |
|---|---|---|
| 1727044 | idor | migration tool prefilled-email oracle |
| 2442008 | idor | summary attachment_ids disclosure via write |
| 2487889 | idor | search organization_id cross-tenant read |
| 297751 | idor | app-password (authtoken) scope tampering |
| 835005 | idor | invitation API organization field -> org takeover |
| 1178239 | open_redirect | custom scheme (test://) redirect merging access_token |
| 158554 | open_redirect | referral-email hyperlink injection via first name |
| 400982 | open_redirect | prejoin_data encoded-slash host smuggling |
| 978680 | open_redirect | meta-refresh attribute breakout + null-byte http-equiv WAF bypass |
| 2209130 | sqli | invite_code ');(SELECT n FROM PG_SLEEP(5))-- time-based |
| 1595006 | ssrf | csstidy css_optimiser.php dependency SSRF (unauthenticated) |
| 3522157 | ssrf | media-proxy encoded @ userinfo bypass -> client-side hosting |

Verified but rejected as redundant/weak (quality over quantity): 1323406, 243943,
308610, 3484601, 544329, 661978, 916704 (generic IDOR variants); 131082, 413426,
972601 (duplicate redirect techniques); 1034625, 1042746, 1069531, 2633959, 865436
(duplicate SQLi timing/auth techniques); 1125752 (mechanism ambiguity around
version-comment syntax on MSSQL), 1628408 (payload quote does not demonstrate the
technique); 220009 (XSS-primary), 223203, 272095, 427835, 514224, 850114 (duplicate
SSRF families).

## 6. Reproduction

```
python generate.py                 # rebuild + validate the four JSONL files
python sources/verify_ids.py       # re-run the H1 ID cross-check (needs reddelexc.csv)
python sources/diff_cujanovic.py   # re-run the payload-list diff
```

Licenses: cujanovic list — none declared; foospidy — GPL-3.0 (copyleft: fine to train
with, avoid redistributing derived lists); ajaysenr/reddelexc archives — no license
declared; content is publicly disclosed HackerOne report data used here as factual
reference with attribution (no verbatim report text embedded in training rows beyond
short payload/URL quotes).
