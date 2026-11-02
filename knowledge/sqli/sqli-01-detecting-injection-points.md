---
id: sqli-01-detecting-injection-points
class: sqli
kind: technique
title: Finding the injection point and setting a baseline
applies_when: a task names an endpoint but recon does not yet show which parameter or location reaches the query
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [entry-point, baseline, headers, json-body]
---

Injection reaches SQL from more places than the query string: named
parameters, JSON body fields, `Cookie` values, and headers such as
`X-Forwarded-For`, `Referer`, and `User-Agent` when they are logged or used
in queries. Recon's parameter inventory (`Param.location`) tells the expert
which of these a verdict can target.

Method for a bounded first probe:

1. Request the endpoint once with the seeded value and record the baseline:
   status, body shape, and the seeded record's presence.
2. Send the same request with a single syntax breaker appropriate to context
   (`'` for strings, `)` inside parens, `\"` in JSON strings).
3. Compare to the baseline. Three outcomes: a driver error string (go
   error-based), a stable but *different* application response (go
   boolean-based), or no difference (consider time-based next).

Why the baseline first: response differences only mean something against a
known-good state. A 500 on the first request could be a broken endpoint,
not injection.

Expected success signal for a detection verdict: the breaker request
produces a response that differs from baseline in a *specific, named* way
(error text containing a SQL fragment, seeded record gone) — and the verdict
should carry low-to-mid confidence until a conditional technique confirms
query control.
