---
id: auth-03-endpoint-method-and-path-normalization
class: auth_bypass
kind: technique
title: Method and path normalization — auth middleware that misses the route
applies_when: the protected endpoint denies requests, but middleware ordering or route normalization may cover only some spellings of it
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [verb-bypass, path-normalization, middleware, routing]
---

Auth middleware matches routes; anything that changes *how* the request is
matched without changing *what* it reaches can slip past the match:

- **Verb variants**: protected `GET /admin/report` — retry as `HEAD`,
  `POST` (empty body), `OPTIONS`-revealed verbs, or the framework's
  override header (`X-HTTP-Method-Override`). One verb per request.
- **Path padding**: `/admin`, `/admin/`, `//admin`, `/admin/.`,
  `/./admin` — routers normalize after the auth match.
- **Encoding**: `/adm%69n`, `%2fadmin` (double-encoded slash), and
  unicode-normalizing spellings (`%e0%2f` style) that decode late.
- **Case and suffix**: `/Admin`, `/admin.json`, `/admin/` + format suffix —
  case-sensitive matching or format-routed handlers.
- **Trailing segments**: `/admin/report/../..` and semicolon path
  parameters (`/admin;/x` or `/admin;jsessionid=...`) — some servers strip
  the parameter before matching, after middleware has run.

Why it works: the request takes a different spelling through the same
handler, while the authorization rule matched only the canonical spelling.

Expected success signal: protected fixture content served on the variant
spelling for a request that the canonical spelling denied — record both
requests' outcomes in `reasoning`; the differential *is* the finding.
Boundary: read-only verbs and spellings only.
