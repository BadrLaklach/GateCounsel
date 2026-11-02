---
id: open-redirect-04-confirmation-protocol
class: open_redirect
kind: technique
title: Open redirect confirmation protocol — first hop, Location only
applies_when: a candidate destination parameter and payload variant are chosen and the verdict needs a verifier-executable signal
source: HackTricks Open Redirect page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [confirmation, location-header, no-follow, evidence]
---

The confirmation discipline for this class, in four rules:

1. **First hop only.** Send the crafted URL; inspect the immediate `3xx`
   response. The finding is the `Location` header's origin — never follow
   the redirect, never measure what the destination serves.
2. **Fixture destinations only.** The cross-origin value is always the
   pre-registered lab fixture host. A payload spelling a real external site
   is out of bounds even when it would "prove more".
3. **Compare against a control.** Also request the endpoint with the
   application's intended destination (or no parameter). A redirect to the
   fixture when the control redirects internally is the differential; some
   endpoints legitimately bounce everywhere and that is not a finding
   without the unvalidated aspect.
4. **Record the exact emitted form.** The verifier compares the normalized
   `Location` origin to the fixture origin — percent-decoding happens
   before comparison, because the emitted form is the payload's whole point
   in the parser-discrepancy family.

Client-side redirects follow the same spirit in the headless browser:
observe the navigation target, click nothing further, read no content at
the destination.

Why so strict: everything past the first hop belongs to other risk classes
(phishing, SSRF-by-redirect) and to the report narrative — the open
redirect finding itself is complete the moment the wrong origin appears in
`Location`.
