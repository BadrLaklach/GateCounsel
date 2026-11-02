---
id: idor-03-identifier-obfuscation-encoding
class: idor
kind: technique
title: Encoded and obfuscated identifiers — decode, alter, re-encode
applies_when: the object identifier is not plain text — base64, hashids-style, hex, or embedded in the path segment
source: HackTricks IDOR page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [encoding, base64, hashids, opaque-id]
---

Encoding is not authorization. When the identifier is opaque, the tamper
happens in the decoded space:

1. Decode one of identity B's known identifiers (base64 → bytes, hex →
   value, hashids → number when the salt is app-derivable or the scheme is
   visible in client code).
2. Verify you hold B's *correct* decoded value — decode A's own identifier
   as a schema control: same length, same shape, one differing field.
3. Re-encode exactly (padding, case, URL-segment safety) and substitute in
   the same position the original occupied.

Position discipline matters as much as the value: a path-segment identifier
must stay in its segment (URL-encoding special characters), a body field in
the same field, a cookie value in the same cookie — everything else in the
request byte-identical to A's normal request.

Common decode shapes: `MTA0Mg==` (base64 of "1042"), `68656c6c6f` (hex),
`eyJpZCI6MTA0Mn0` (base64 JSON — decode the inner JSON, alter `id`,
re-encode), and sequential-hashid patterns where two known pairs reveal the
scheme without brute force.

Boundary: obfuscation work uses only the two seeded identifiers — decoding
schemes is fine, enumerating the keyspace is not. Guessability of the
scheme belongs in the report as a defense finding, not in the payload.

Expected success signal: B's fixture data returned to A via the re-encoded
identifier.
