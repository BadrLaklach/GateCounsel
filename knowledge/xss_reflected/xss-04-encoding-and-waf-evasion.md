---
id: xss-04-encoding-and-waf-evasion
class: xss_reflected
kind: technique
title: Working through output encoding and WAF blacklists
applies_when: recon reports reflection=encoded, or the first context-matched payload was blocked and the response hints at a filter
source: HackTricks XSS README (commit f66c437, CC-BY-NC-4.0), paraphrased; payload families cross-checked against PayloadsAllTheThings (MIT)
tags: [encoding, entities, unicode, waf, blacklist]
---

Encoding defenses fail when the application decodes the value one more time
than it re-encodes before the sink. Identify which layer decodes, then speak
that layer's language:

- **HTML entities**: if the value is entity-decoded before insertion, send
  `&lt;svg onload=marker()&gt;` so it decodes to live markup at the sink.
- **Unicode/hex escapes in JS context**: `\u003c` / `\x3c` decode to `<`
  inside JavaScript string processing when the value reaches eval-like sinks.
- **URL encoding / double encoding**: `%3C` then `%253C` when the parameter
  is URL-decoded twice (common through redirect and fetch parameters).
- **Blacklist case/format gaps**: mixed case (`ScRiPt`), stray newlines and
  tabs inside tags, `/**/` as a space replacement, and attribute-less tags
  (`<svg/onload=marker()>`).

Method: one variation per request, and let the response choose — reflected
output shows which layer decoded. Never chain five encodings blind; a
verdict should name the specific observed defense (from recon evidence or a
failed probe result) and the single encoding that answers it.

Expected success signal: the marker executes in the headless browser. If the
payload is still reflected inert after two targeted variants, confidence
should drop and `reasoning` should recommend a different context chunk
rather than more encoding guesses.
