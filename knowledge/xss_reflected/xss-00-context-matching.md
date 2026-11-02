---
id: xss-00-context-matching
class: xss_reflected
kind: context_map
title: Reflected XSS — matching reflection context to payload family
applies_when: recon reports a parameter whose value is reflected (reflection=raw or reflection=encoded) and the task is to choose the first payload family
source: HackTricks XSS README and DOM XSS page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [context, decision-map, methodology]
---

The reflection context, not the payload list, decides the first shot. Read it
from the recon evidence before proposing anything.

- **Raw HTML body** (marker appears as page text, `<` and `>` survive) — tag
  injection: `01-html-body-tag-injection`.
- **Tag attribute** (marker appears inside `value="..."` or similar) —
  attribute breakout with event handlers: `02-attribute-context-event-handlers`.
- **JavaScript string** (marker inside `<script>var x='...'</script>`) —
  quote breakout or script-tag termination: `03-js-string-context-breakout`.
- **href/src/action attribute** (value becomes a URL) — scheme payloads:
  `05-scheme-based-javascript-data`.
- **Template literal** (marker inside backticks) — `${...}` interpolation:
  `03-js-string-context-breakout`.
- **Value reflected only after the browser moves it** (read from
  `location.hash`/`search` into the DOM) — DOM source/sink flow:
  `06-dom-sources-and-sinks`.
- **Recon says encoded** (special characters escaped or dropped) — work the
  encoding layer first: `04-encoding-and-waf-evasion`.

A reflected canary alone proves nothing — the verifier needs an executable
path in the observed context. Expected success signal is always a unique,
harmless DOM marker set by the payload (never cookie or token reads). When
the context is ambiguous, the verdict should propose the context probe
itself as the payload and say so in `reasoning`.
