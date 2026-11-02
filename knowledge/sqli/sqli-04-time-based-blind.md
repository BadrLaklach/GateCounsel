---
id: sqli-04-time-based-blind
class: sqli
kind: technique
title: Time-based blind SQL injection — one bounded delay
applies_when: no error output and no content difference between true and false states
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased; delay functions cross-checked against PayloadsAllTheThings (MIT)
tags: [blind, time-based, sleep, waitfor-delay]
---

When nothing observable changes in the body, timing is the remaining channel
— used sparingly, because it holds a database connection open.

Vendor delays:

- MySQL: `' AND SLEEP(5)-- `
- PostgreSQL: `' AND (SELECT pg_sleep(5))-- `
- MSSQL: `'; WAITFOR DELAY '0:0:5'--`
- SQLite: no native sleep; this family usually does not apply.

Method discipline: measure the baseline latency first; then send one delay
payload with a short, fixed delay (3–5 seconds, never longer); the finding
is the delta, not an absolute. One request per verdict — no timing sweeps,
no conditional cascades. This is the slowest and most intrusive of the
confirmation techniques, so it belongs only when the boolean chunk has
already failed to produce a differential; the verdict's `reasoning` should
say exactly that.

Expected success signal: response time exceeds baseline by at least the
delay amount while the body stays byte-identical to baseline. If latency
jitters, confidence drops — a single slow response proves nothing about the
database.

Boundary reminder: bounded delay only. The class boundary forbids stacked
statements, second queries, and out-of-band callbacks entirely.
