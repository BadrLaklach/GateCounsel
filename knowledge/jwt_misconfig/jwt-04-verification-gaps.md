---
id: jwt-04-verification-gaps
class: jwt_misconfig
kind: technique
title: Verification gaps — unvalidated claims and lifetimes
applies_when: the token decodes cleanly and carries authority or time claims whose enforcement is in question
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [claims, expiry, role, trust]
---

The signature can be perfectly valid and the token still misused — the
gaps live in *which claims the server enforces*:

- **Authority claims trusted blindly**: `role`/`admin`/`scope` from the
  payload decide access with no server-side derivation. Probe: re-issue
  (properly signed, with the lab secret) the same token with one authority
  claim changed — `user` → `admin` — and make one admin-indicative
  read-only request.
- **Lifetime ignored**: no `exp` in the claim set, or an expired lab token
  still accepted. Probe: the fixture's expired token, unchanged.
- **Identity mismatch**: `sub` changed to the second seeded principal
  (properly signed) — if the server serves that principal's data, the
  token is treated as an authority on identity without cross-checking
  session ownership.
- **Issuer/audience ignored**: token minted for another audience accepted
  verbatim — flag in reasoning when the claims name one.

Why one claim per token: acceptance must be attributable to the single
unvalidated claim; a token with three changes proves nothing about which
gap fired.

Expected success signal: the single-claim-modified (or expired) token is
accepted and the response reflects the modified authority — the named
admin fixture content, the other principal's seeded data, or a normal
authenticated response to the expired token.
