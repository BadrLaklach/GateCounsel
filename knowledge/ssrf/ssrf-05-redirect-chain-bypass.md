---
id: ssrf-05-redirect-chain-bypass
class: ssrf
kind: technique
title: Redirect-chain SSRF — validating the first hop, fetching the second
applies_when: the fetcher validates the supplied URL but follows redirects after validation
source: HackTricks SSRF and URL Format Bypass pages (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [redirect, validation-hop, revalidation]
---

When validation runs once against the submitted URL and the HTTP client
then follows redirects, the attacker only needs one hop the validator
likes: point the parameter at a page you control that answers `302` with a
`Location` pointing where you actually want the fetch to go.

Structure: `parameter → https://my-page.lab/hop` (passes validation, since
the host is allowed or unchecked) `→ 302 → <real destination>` — and the
fetcher follows to the destination without re-validating it.

Why it works: the check and the fetch happen at different times against
different URLs. Any redirecting endpoint under your control becomes a
 laundering hop; in real incidents the second hop is internal services or
metadata — which is exactly why defense-side re-validation must run on
every hop (the same rule GateCounsel's own ScopeGuard applies to its
crawlers).

Lab shape: the redirector and the destination are both lab-internal — the
controlled receiver serves the hop and logs the case ID on arrival, keeping
the proof inside the boundary while demonstrating the two-hop flaw.

Expected success signal: the receiver logs a request for the case ID whose
referrer/history shows it originated from the hop URL — i.e., the fetcher
followed the redirect rather than fetching the destination directly. The
verdict's `payload` is the hop URL; the redirect target belongs in
`reasoning`.
