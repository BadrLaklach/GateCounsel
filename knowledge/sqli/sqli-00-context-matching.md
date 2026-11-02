---
id: sqli-00-context-matching
class: sqli
kind: context_map
title: SQL injection — matching evidence to technique family
applies_when: a parameter reaches a query and recon shows error strings, response divergence, or timing sensitivity
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [context, decision-map, methodology]
---

Pick the technique from what the evidence already proves, cheapest signal
first:

- **Database error in the response** (quote characters produce driver error
  text) — error-based: `02-error-based`.
- **Two seeded states observable** (a known record shows or hides when the
  condition flips) — boolean-based blind: `03-boolean-based-blind`.
- **No content difference at all** — time-based blind, one bounded delay:
  `04-time-based-blind`.
- **Injection point returns rows to the page** (list/search endpoints) and
  column errors surface — union-based: `05-union-based`.
- **Vendor-specific error wording or banner** — fingerprint before anything:
  `06-dbms-fingerprint-quirks`.
- **Payload rejected or canonicalized** — filter/WAF layer present:
  `07-filter-and-waf-bypass-encodings`.

Ground rules from the class boundary: establish the baseline response for
one seeded record first; an error alone is a clue, not a finding; the
verdict's `expected_success_signal` must describe an application-level
difference (the seeded record appearing, a marker string rendered, one
bounded delay), never schema enumeration, data exfiltration, stacked
statements, or out-of-band calls. Injection points beyond the query string
(header, cookie, JSON body — see `01-detecting-injection-points`) follow the
same technique map.
