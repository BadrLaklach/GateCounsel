---
id: auth-04-protected-surface-mapping
class: auth_bypass
kind: technique
title: Protected-surface mapping — differential access analysis
applies_when: multiple protected endpoints are known and the verdict should decide where a bypass is even plausible before payloads fire
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [mapping, differential, 401-403, gate-analysis]
---

Before attacking, characterize *what kind of gate* each protected endpoint
has — the bypass family depends on it. Using recon's status matrix
(unauthenticated vs authenticated statuses per endpoint):

1. **Token-presence gate**: unauthenticated → `401`, any valid token →
   `200`. Bypass means reaching it without a token: forced browsing,
   normalization, middleware gaps (`01`, `03`).
2. **Claims gate**: valid token → `403` for the low-privilege principal,
   admin token → `200`. Bypass means tampering authority: state
   parameters, JWT claims (`02`, jwt_misconfig).
3. **Route gate**: endpoint vanishes (`404`) unauthenticated but exists
   authenticated. Bypass is spelling/routing: `03`.
4. **Inconsistent pairs**: `/admin` denied but `/admin/api/*` data routes
   open — the UI gate and data gate differ; the data route is the target.

Map first, attack second: one verdict that names the gate type per
endpoint sets up the next verdict's family choice and keeps the report
auditable ("endpoint X has a token-presence gate; forced browsing
applies").

Why it matters: firing claim-tampering at a presence gate wastes requests
and muddies evidence; the differential classifies the gate from data recon
already collected.

Expected success signal for the mapping verdict itself: the status matrix
(unauth/low-priv/admin × endpoint) stated in `reasoning` with the gate type
per endpoint — the follow-up bypass verdict cites it as evidence.
