---
id: jwt-03-kid-header-injection
class: jwt_misconfig
kind: technique
title: kid header injection and algorithm confusion
applies_when: the decoded header carries a kid the server uses to locate the verification key, or RS256 tokens coexist with a disclosed public key
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [kid, sql, path-traversal, rs256-hs256-confusion]
---

The `kid` (key ID) header is attacker-controlled input to the server's key
lookup. Three failure shapes:

- **kid into SQL**: the lookup query embeds `kid` unparameterized —
  `' UNION SELECT ...` in the header changes which key verifies. In the
  lab the goal is only to make verification succeed with a key you can
  compute, not to read the key table.
- **kid as path**: the lookup opens a file at `kid` — traversal
  (`../../../../dev/null` or a world-readable file with predictable
  content) selects a key whose value you can also derive.
- **RS256→HS256 confusion**: the verifier accepts the token's `alg`, so an
  RS256 deployment can be handed an HS256 token whose "secret" is the
  *public* key (public keys are not secret — the PEM bytes are the HMAC
  key). Forge with the public key as the shared secret.

Each shape is its own verdict; the craft step differs, the proof is
identical.

Why it works: all three make the server verify against material the
attacker can compute, converting asymmetric trust back into symmetric
knowledge.

Expected success signal: a forged token (same claims, seeded principal) is
accepted. `reasoning` names the confusion used and where the key material
came from. Boundary: key recovery stays within the seeded fixture — no
real user keys, no write endpoints.
