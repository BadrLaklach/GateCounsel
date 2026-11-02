---
id: idor-04-method-and-content-type-changes
class: idor
kind: technique
title: Method and content-type changes — authorization checked on one handler only
applies_when: the identifier swap was denied on the normal request, suggesting the check lives in one code path
source: HackTricks IDOR page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [verb-change, content-type, handler, mass-assignment]
---

When the object check exists on the happy path, test whether every handler
for the same object shares it. One change per request:

- **Verb rotation**: `GET /api/orders/1042` denied as B's order — retry the
  same URL as `HEAD`, `POST`, `PUT`, or `PATCH`. A read-only check on GET
  only is a common gap; keep the request read-only in effect (no body that
  would mutate).
- **Content-type rotation**: the JSON API checks ownership but the
  form-encoded or XML path binds to a different controller that does not.
- **Representation changes**: an export/report endpoint
  (`/api/orders/1042?format=pdf`) or an internal batch endpoint referencing
  the same object.
- **Mass-assignment adjacent gap**: an update endpoint that accepts an
  `owner_id`/`user_id` field — moving an object between principals is the
  write-side cousin; flag it but stay read-only in the probe.

Why it works: authorization is usually implemented per-handler, and
routing (verb, content-type, format suffix) selects handlers. The check
protects the default route; the alternates are forgotten.

Expected success signal: B's fixture data (or metadata) returned to A on
the *alternate* verb/content-type with the same identifier — named
explicitly, since the default path already denied it. Boundary: no
destructive verbs with bodies; if only a mutating path is vulnerable, the
verdict flags it for review rather than executing it.
