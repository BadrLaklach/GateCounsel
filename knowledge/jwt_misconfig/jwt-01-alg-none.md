---
id: jwt-01-alg-none
class: jwt_misconfig
kind: technique
title: alg:none — the unsigned-token acceptance gap
applies_when: the decoded token header uses a symmetric or asymmetric alg and the verifier may not pin the expected algorithm
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [alg-none, header-tampering, unsigned, accepted-without-signature, still-works]
---

The server should decide which algorithm it trusts; when it instead
obeys the token's own `alg` header, a token that declares `alg: none` with
an empty signature may pass verification.

Craft, in three steps, changing only the header:

1. Decode the lab-issued token; keep the payload claims byte-identical.
2. Rebuild the header with `"alg": "none"` (or `"NONE"`/`"nOnE"` variants
   when the first is rejected — one per request) and drop the signature
   segment, leaving the trailing dot: `header.payload.`
3. Send one authenticated read-only request carrying the forged token.

Variants worth one probe each: `none` with empty signature versus a dummy
signature string, and algorithm confusion where the header swaps to an
algorithm family the verifier mishandles — but each is its own verdict.

Why it works: the vulnerability is not the payload — it is the verifier
accepting a token whose integrity proof is absent, on the token's own
say-so.

Expected success signal: the endpoint accepts the `alg:none` token and
returns the same authenticated content as the legitimate one. A `401`
rejecting it is a clean negative. `reasoning` must state that only the
header changed, so the acceptance is attributable to algorithm handling —
if the payload also changed, the evidence is contaminated.
