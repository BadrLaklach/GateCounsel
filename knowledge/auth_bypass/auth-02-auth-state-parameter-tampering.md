---
id: auth-02-auth-state-parameter-tampering
class: auth_bypass
kind: technique
title: Auth-state parameter tampering — client-trusted privilege values
applies_when: the application exposes role or auth state in client-modifiable places — cookies, hidden form fields, profile request bodies, or client-readable session payloads
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [role-tampering, cookie, hidden-field, mass-assignment]
---

When privilege lives in client-visible state, the server is trusting the
client's word about it. Tamper points, cheapest first:

- **Cookie roles**: `role=user` in a plain cookie → `role=admin`, same
  session, one request. (Signed cookies that fail validation are a
  negative worth recording — the signature *is* the control.)
- **Hidden form fields**: `<input type="hidden" name="isAdmin" value="0">`
  → submit the form with `isAdmin=1`. Recon's `FormInfo.hidden_values`
  snapshots these.
- **Profile/body fields**: a profile-update request that also accepts
  `role`, `isAdmin`, `user_id`, or `plan` — add the field with the
  elevated value (mass assignment), then make one read-only request as the
  updated self.
- **Session payload claims**: role stored client-side in a readable token
  — tampering the claim crosses into jwt_misconfig; keep the class
  boundary explicit in `reasoning`.

Discipline: change exactly one privilege value per request; the
unauthenticated/low-privilege context stays otherwise identical, and the
proof request is read-only (the update endpoint in the mass-assignment
shape is the minimal necessary write, confined to the attacker's own
seeded profile).

Expected success signal: admin/fixture content or function served after
exactly one privilege value changed — the verifier needs the named field
(`role`, `isAdmin`) and the before/after differential.
