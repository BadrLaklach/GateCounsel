---
id: sqli-06-dbms-fingerprint-quirks
class: sqli
kind: technique
title: DBMS fingerprints — choosing payloads the vendor will accept
applies_when: an error banner, driver wording, or vendor-specific behavior identified the database product
source: HackTricks SQL Injection pages (commit f66c437, CC-BY-NC-4.0), paraphrased; vendor quirks cross-checked against PayloadsAllTheThings (MIT)
tags: [fingerprint, mysql, postgresql, mssql, oracle, sqlite]
---

Vendor knowledge changes syntax before any payload is sent:

- **Comments**: `--` works almost everywhere; MySQL also accepts `#`; block
  comments `/* */` behave differently on MySQL with a `!` version marker.
- **String concatenation**: `CONCAT(a,b)` (MySQL, MSSQL 2012+), `a || b`
  (PostgreSQL, Oracle, SQLite) — the wrong choice is itself a fingerprint.
- **Delays**: `SLEEP()` / `pg_sleep()` / `WAITFOR DELAY` / none (SQLite) —
  see the time-based chunk.
- **Error helpers**: `extractvalue`/`updatexml` (MySQL), `XMLType` (Oracle),
  `CONVERT` failures (MSSQL) — see the error-based chunk.
- **Quirk tells in error text**: "You have an error in your SQL syntax"
  (MySQL), "unterminated quoted string" (PostgreSQL), "Unclosed quotation
  mark" (MSSQL), "ORA-" prefixes (Oracle), "SQLITE_" prefixes (SQLite).
- **Fingerprint probes without errors**: string-vs-numeric arithmetic that
  only one vendor evaluates (`' AND 1=1` vs vendor-specific functions) —
  the boolean differential carries the signal.

Recon's technology hints (server header, framework) narrow this further: a
PHP/Node app with a `mysql` hint starts at MySQL syntax.

Expected success signal for a fingerprint verdict: a named vendor tell
observed in the response (specific error wording or a vendor-only behavior
confirmed by differential), stated so the next verdict can cite it as
evidence. Fingerprint-only verdicts carry information the whole class
reuses — record it in `reasoning`.
