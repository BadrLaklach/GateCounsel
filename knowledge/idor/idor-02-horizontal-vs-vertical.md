---
id: idor-02-horizontal-vs-vertical
class: idor
kind: technique
title: Horizontal versus vertical access-control gaps
applies_when: choosing which privilege axis the evidence actually demonstrates before writing the verdict
source: HackTricks IDOR page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [horizontal, vertical, privilege, admin]
---

Two different findings hide under "IDOR" — the verdict must name which one
the evidence supports:

**Horizontal (BOLA)**: same privilege level, wrong owner. Identity A (user)
requests identity B's (user) object. Evidence: B's fixture data in A's
response. The missing control is object ownership. This is the default
framing; most identifier-tamper findings are horizontal.

**Vertical (privilege escalation)**: lower privilege requests a
higher-privilege object or function. Identity A (user) requests the admin
record, admin endpoint, or admin response. Evidence must show the response
carries privileged content or performs a privileged function — an admin
`403` is not escalation. Vertical findings need the low-privilege session
to stay authenticated as low-privilege; if the session became admin by
other means, that is auth_bypass territory, not IDOR.

Why the distinction matters: the planner's routing, the verifier's
expected signal, and the report's severity all differ. A horizontal finding
is "any user can read any invoice"; a vertical finding is "any user can
read the audit log." Same swap technique, different object classes and
different fixture data.

Expected success signal: name the axis explicitly — "user session receives
another user's fixture" (horizontal) or "user session receives
admin-only fixture content" (vertical) — so the verifier asserts the right
thing.
