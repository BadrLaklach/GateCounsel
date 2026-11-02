---
id: auth-00-context-matching
class: auth_bypass
kind: context_map
title: Auth bypass — routing the evidence to the right bypass family
applies_when: recon shows protected endpoints (auth_required, 401/403 statuses) or an unauthenticated surface that hints at hidden functionality
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [context, decision-map, methodology]
---

Recon already produces the map this class feeds on: which endpoints answer
`401/403` unauthenticated (`probe_protected`), which flip after login, and
what the login flow touches. Route by evidence:

- **Endpoint exists, denies unauthenticated requests** — forced browsing
  with path/verb variations: `01-forced-browsing` and
  `03-endpoint-method-and-path-normalization`.
- **Session or profile carries client-visible auth state** (role values in
  cookies, hidden fields, profile JSON) — tamper the state:
  `02-auth-state-parameter-tampering`.
- **Protected surface mapped but boundary unclear** (which endpoints gate
  on token presence versus token claims) — differential mapping first:
  `04-protected-surface-mapping`.

Separation from sibling classes, to keep verdicts honest: swapping an
*object identifier* is IDOR; forging or weakening a *token* is
jwt_misconfig; auth_bypass is reaching a protected surface *without* or
*around* the authentication check itself.

Boundary: probes stay read-only against seeded fixtures; "bypass found" is
asserted only when protected fixture content is actually served to the
unauthenticated or low-privilege request — a bare `200` on an empty page
proves routing, not authorization.

Expected success signal, class-wide: named protected content (fixture
marker) returned to a request that never presented valid elevated
credentials.
