---
id: open-redirect-01-destination-parameter-patterns
class: open_redirect
kind: technique
title: Destination parameters — where they hide and what they control
applies_when: enumerating which parameters actually steer navigation before proposing a redirect payload
source: HackTricks Open Redirect page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [parameter-discovery, location-header, client-redirect, visitors, another-domain]
---

Two mechanisms produce redirects, and they need different evidence:

**Server-side**: the application answers `301/302/303/307` with a
`Location` header built from the parameter. Probe by requesting the
endpoint with a benign relative value (`/home`) and one lab-destination
value; compare the `Location` of both. The header is the oracle.

**Client-side**: a page script reads the parameter and assigns it to
`location`/`location.href` after the page loads. The `Location` header
never changes; the evidence is the headless browser navigating. Recon's
SPA/hash-route findings point here.

Parameter shapes worth checking beyond the obvious: destination hidden in
the path (`/redirect/home`, `/goto/https://...`), compound values
(`?next=%2Fhome` URL-encoded), session-carrying redirects
(`?RelayState=...`, SAML/OAuth `redirect_uri` — flag but treat carefully,
those are protocol-level), and referer-based redirects where the header is
the input.

Why catalog first: a payload verdict needs to name the exact parameter and
mechanism; a `next=` value that only ever reaches a template as text is not
a redirect parameter at all.

Expected success signal: with the lab destination in the identified
parameter, either the first response's `Location` equals it (server-side)
or the browser navigates to it after load (client-side) — the verdict says
which mechanism, because the verifier watches a different artifact in each
case.
