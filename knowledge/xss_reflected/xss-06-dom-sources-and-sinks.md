---
id: xss-06-dom-sources-and-sinks
class: xss_reflected
kind: technique
title: DOM XSS — tracing sources to sinks
applies_when: the value never appears in the server response, but client-side JavaScript reads a URL component and writes it into the DOM
source: HackTricks DOM XSS page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [dom, source, sink, location-hash, innerhtml]
---

A **source** is any browser value the user influences (`location.hash`,
`location.search`, `document.referrer`, `postMessage` data); a **sink** is an
operation that interprets its input as markup or code (`innerHTML`,
`document.write`, `eval`, `setTimeout` with a string, `jQuery(html)`).

The evidence that matters is the data flow: recon reports hash routes or
script-referenced behavior where the fragment reaches a sink. The payload
family is chosen by sink:

- `innerHTML` / `document.write` — markup payloads (`<svg onload=...>`).
- `eval` / string timers — JavaScript expressions (`marker()`), no tags.
- `location` assignment — relative navigation, or scheme payloads if the
  whole URL is sourced.

Why this is its own chunk: server-side reflection evidence does not apply.
The response body can be completely clean while the vulnerability is fully
exploitable, and payloads sent in the query string may need to move to the
fragment (`#`) when the client reads only `location.hash` — check which
component the script consumes.

Expected success signal: the DOM marker appears after the page loads the
crafted URL; the verifier loads the URL in the headless browser and inspects
the DOM. If the sink is unclear from recon, the correct verdict is a probe
of the source-to-sink path with a plain canary first, at lower confidence.
