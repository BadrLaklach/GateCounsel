---
id: ssrf-00-context-matching
class: ssrf
kind: context_map
title: SSRF — recognizing a server-side fetch and choosing the proof
applies_when: a parameter accepts a URL or hostname and recon suggests the application fetches it
source: HackTricks SSRF pages (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [context, decision-map, methodology]
---

SSRF requires the *server* to initiate a request influenced by input. A URL
echoed into a page is not evidence — one of these is:

- The response contains content fetched from the supplied URL.
- A controlled receiver observes a request with the case ID (strongest
  proof): `01-confirming-with-a-controlled-receiver`.
- Request timing tracks the supplied host's behavior.

Where URL parameters live: `url=`, `fetch=`, `dest=`, `image=`/avatar
upload-from-URL, webhooks, import/export features, PDF renderers, "preview
link" boxes, and proxy-like paths (`/fetch?url=`).

Then choose the technique by the observed defense:

- No validation — receiver confirmation directly.
- Allowlist on hostname — `03-allowlist-filter-bypasses`.
- String/prefix checks that parsers read differently —
  `02-url-format-bypasses`.
- Redirects followed by the fetcher — `05-redirect-chain-bypass`.
- Cloud-hosted target — `04-cloud-metadata` (detection concepts only).

Lab boundary, non-negotiable: the only destination a verdict may propose is
the lab's controlled receiver (`ssrf-sentinel` with a case ID). Bypass
chunks teach pattern recognition; the destination stays in the lab.
Boundary hardening on the defense side: validate one canonical parsed form,
re-check every redirect, and enforce an exact host allowlist at the network
layer — input validation alone must not grant internal-network reach.
