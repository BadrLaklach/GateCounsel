---
id: open-redirect-00-context-matching
class: open_redirect
kind: context_map
title: Open redirect — finding destination parameters and reading their validation
applies_when: recon shows a parameter whose value influences where the response or browser navigates next
source: HackTricks Open Redirect page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [context, decision-map, methodology]
---

Destination parameters cluster by name (`url`, `next`, `redirect`,
`return`, `returnTo`, `continue`, `dest`, `target`, `goto`) and by role —
login-failure bounce, logout redirect, deep-link handoff, email
verification links. Evidence: a `30x` whose `Location` echoes the input, or
a page script that reads the parameter into `location`.

Classify the observed validation before choosing a technique:

- **No validation** — any absolute destination works; go straight to the
  confirmation protocol (`04-confirmation-protocol`).
- **Scheme/host check** — `02-filter-evasion-variants` (scheme-relative,
  userinfo, backslash).
- **Allowlist or prefix/suffix match on the trusted host** —
  `02` and `03` (parser discrepancy families).
- **Value rewritten or canonicalized** — `03` (encoded forms the validator
  and emitter read differently).

Two ground rules from the class boundary. First, never follow the redirect
during testing — the finding is the first `Location` header, nothing else.
Second, the only cross-origin-looking destination used in the lab is the
pre-registered fixture host; every payload spells the fixture, never a real
external site.

Expected success signal for the class, always: the first redirect response
carries a `Location` whose origin equals the fixture destination rather
than the application's own.
