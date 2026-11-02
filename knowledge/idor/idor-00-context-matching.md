---
id: idor-00-context-matching
class: idor
kind: context_map
title: IDOR — matching identifier shape to the tamper technique
applies_when: recon shows an endpoint whose path, query, body, header, or cookie carries an object identifier and an authenticated session exists
source: HackTricks IDOR page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [context, decision-map, methodology]
---

The core question for every identifier: does the server check that *this
authenticated principal* may access *this particular object*? Choose the
tamper by the identifier's shape:

- **Sequential integer** (`?invoice=1042`) — increment/predict swap:
  `01-object-identifier-tampering`.
- **Opaque but decodable** (base64, hashids, encoded path segment) —
  decode, alter, re-encode: `03-identifier-obfuscation-encoding`.
- **UUID/guess-proof** — don't attack the value; find where the app leaks
  valid identifiers of the other principal (listing endpoints, receipts,
  exports): `01` under "leaked identifier" framing.
- **Same object, higher privilege** (admin record while low-privilege) —
  vertical framing: `02-horizontal-vs-vertical`.
- **Access denied on one verb/content-type** — the handler, not the value,
  is the gap: `04-method-and-content-type-changes`.

Ground rules from the class boundary: two seeded synthetic identities; keep
the low-privilege identity and change only the one object identifier; one
read-only request per verdict. A `403`/`404` after the swap is a negative,
not a finding — the finding is identity A's fixture data returned to
identity A. No enumeration sweeps, no writes, no real-user records.
