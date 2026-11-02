---
id: idor-01-object-identifier-tampering
class: idor
kind: technique
title: Object identifier tampering — the seeded-pair swap
applies_when: an endpoint returns one identified object to an authenticated identity, and a second seeded identity owns a known object
source: HackTricks IDOR page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [swap, seeded-pair, sequential, leaked-id]
---

The minimal IDOR probe changes exactly one thing — the object identifier —
while holding the authenticated session fixed:

1. Seed: identity A owns object `a-1`; identity B owns object `b-1`. Both
   are synthetic lab fixtures with non-sensitive marker fields.
2. As identity A, request `b-1` through the endpoint under test.
3. Read the result: B's fixture data returned to A is the finding; a
   `403`/`404` is a clean negative.

Identifier sourcing by shape:

- Sequential integers: request B's known adjacent value (never a sweep).
- UUIDs: obtain B's real identifier from a legitimate leak — a listing
  endpoint, a shared receipt, an export — then use it once.
- Composite keys: change the object part only, leaving tenant/user parts
  intact to prove object-level (not tenant-level) authorization failure.

Why one variable: if the request also changes method, session, or
content-type, the evidence cannot attribute success to the missing
ownership check — reviewers and verifiers both need the single-variable
structure.

Expected success signal: the response contains identity B's seeded fixture
field(s), named in the verdict, delivered to identity A's session. The
verifier compares exact fixture content, not status codes — partial or
error responses do not confirm.
