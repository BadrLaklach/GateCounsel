---
id: auth-01-forced-browsing
class: auth_bypass
kind: technique
title: Forced browsing — requesting the protected route directly
applies_when: recon exposed a protected route (admin panel, internal API, management path) that is denied unauthenticated
source: hand-written decision note (own words; standard published technique categories, no upstream text)
tags: [forced-browsing, unauthenticated, direct-access]
---

The oldest bypass: the page is hidden but the endpoint is not protected.
Applications link to `/admin` only for admins, yet the route itself may
serve anyone.

Method:

1. From recon's endpoint inventory, take the admin/internal-marked route
   (planner hints, sitemap disclosures, `robots.txt` entries, JS-referenced
   paths are the usual leaks).
2. Request it directly, unauthenticated — no token, no session cookie —
   with the exact URL the authenticated flow uses.
3. Read beyond the status code: a `200` must carry protected *content*
   (the admin fixture marker, dashboard data) to count. Redirects to
   login, empty shells, or `403`s are negatives.

Refinements when the direct hit denies: request the route's assets and
sub-routes the UI would load (`/admin`, `/admin/api/summary`,
`/admin/static/app.js`) — protection applied to the page but not to its
data endpoints is the common shape.

Why it works: access control implemented as UI omission (don't render the
link) instead of server-side enforcement on the route.

Expected success signal: protected fixture content served to the
unauthenticated request, named field for the verifier. Boundary: one
read-only request per variant; discovered write/admin actions get flagged
in `reasoning`, never executed.
