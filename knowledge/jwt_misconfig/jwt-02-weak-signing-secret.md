---
id: jwt-02-weak-signing-secret
class: jwt_misconfig
kind: technique
title: Weak HS256 signing secret — offline crack, then forge
applies_when: the token header shows HS256 (symmetric) and the secret may be a dictionary word or seeded fixture value
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [hs256, weak-secret, offline, forge]
---

Symmetric signing means one secret both signs and verifies — if it is
guessable, anyone can mint valid tokens. The check is offline: no requests
to the target until the forged proof.

1. Take the lab-issued token. Try the seeded lab secret candidates and a
   small dictionary of classic weak secrets against its HMAC. One
   verification success identifies the secret — no network involved.
2. Forge a token for the *same seeded principal* with the same claims,
   re-signed with the recovered key. Change nothing else; the proof is
   that you could sign at all.
3. One read-only request with the self-signed token.

In the lab the weak secret is a deliberate fixture; in the report, the
defense lesson is key length and randomness, not the dictionary.

Why it works: HS256 verification is `HMAC(secret, signing_input)`. Knowing
the secret makes the attacker a legitimate signer — signature validation
becomes theater.

Expected success signal: the endpoint accepts the self-signed token
indistinguishably from the issued one. The verdict records in `reasoning`
that the secret was recovered offline from the fixture token (the audit
trail for "how"), and the payload stayed claim-identical so acceptance is
attributable to signature control alone.
