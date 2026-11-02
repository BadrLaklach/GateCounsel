---
id: xss-05-scheme-based-javascript-data
class: xss_reflected
kind: technique
title: Scheme payloads — javascript: and data: URLs
applies_when: the reflected value becomes a URL the browser navigates to or loads, such as href, src, action, or form target attributes
source: HackTricks XSS README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [scheme, javascript-url, data-url, href]
---

When the parameter controls a URL-typed attribute, no markup breakout is
needed — the scheme itself is the payload:

- `javascript:marker()` in an `href` — executes when the link is activated.
- `data:text/html,<svg onload=marker()>` in `href`/`src` contexts that render
  documents — executes on load in some browsers and embedding contexts.

Validation to expect: many applications strip or reject `http(s)`-mismatched
schemes. When the scheme is filtered, the casing and whitespace family
applies (`java\tscript:`, `JaVaScRiPt:`), but each variant needs its own
verdict — do not batch them.

Important execution nuance for the Exploit Agent: a `javascript:` URL in an
anchor only fires on activation, so the `expected_success_signal` must
describe the click action the verifier performs (the headless browser clicks
the crafted link), not just "marker executes". A `data:` URL that opens a
separate document needs the verifier to follow it explicitly.

Why it works: the browser resolves the attribute value as a URL; an
executable scheme turns navigation into script execution without any HTML
injection at all.

Boundary: marker functions only — no exfiltration, no cookie access, no
external callbacks.
