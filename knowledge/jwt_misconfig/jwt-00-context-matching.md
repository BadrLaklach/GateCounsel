---
id: jwt-00-context-matching
class: jwt_misconfig
kind: context_map
title: JWT misconfiguration — reading the token before choosing an attack
applies_when: recon reports a JWT (AuthInfo token_type jwt, token_storage, or sample claims) and an endpoint that trusts it
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [context, decision-map, decode-first]
---

Decode before you attack: recon already exposes header and claims
(`jwt_sample_claims`, `AuthInfo.token_storage`). The verdict's first
responsibility is to say what the token *is*:

- **`alg` in header** — `none` accepted? (`01-alg-none`); symmetric
  HS256 with a weak secret? (`02-weak-signing-secret`); asymmetric RS256
  with the public key disclosed? (`03-kid-header-injection` covers the
  RS256→HS256 confusion).
- **`kid` present** — is it looked up dangerously (SQL, path)?
  (`03-kid-header-injection`).
- **Claims carrying authority** (`role`, `admin`, `user_id`) — does the
  server trust them without server-side derivation? (`04-verification-gaps`).
- **No `exp`/`nbf`, or expired tokens still accepted** —
  `04-verification-gaps`.

Evidence sources that answer these without sending anything: the decoded
token itself, recon technology hints, and disclosed JWKS/key endpoints.

Boundary: forgery checks stay lab-scoped — the "attacker" keys and weak
secrets are seeded fixtures, tokens are forged only for the seeded
principal, and a forged token is used for one read-only proof request.

Expected success signal, class-wide: a request whose token was modified in
exactly one aspect is still accepted where it should be rejected —
acceptance of tampered authority is the finding.
