---
id: xss-02-attribute-context-event-handlers
class: xss_reflected
kind: technique
title: Reflected XSS into a tag attribute — quote breakout with event handlers
applies_when: the marker value appears inside an HTML attribute such as value="..." and tag creation is not possible
source: HackTricks XSS README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [attribute, breakout, event-handler, onfocus, autofocus, echo, quotes, input-field]
---

When the reflection lands inside an attribute, angle brackets are usually
encoded but the quoting character may not be. Break out of the attribute and
add an event handler inside the existing tag:

- `" onmouseover="marker()"` — classic double-quote breakout; requires the
  victim to hover, so prefer auto-firing events.
- `" autofocus onfocus="marker()` — fires on its own for input elements.
- `" onerror="marker() x="` — for attributes on media-like elements.

If quotes are encoded but `<` is not, invert the approach: close the host tag
and open a new one — `"><svg onload=marker()>`. If both quote and bracket are
encoded, this family fails; switch to the encoding/WAF chunk and determine
what the application decodes before rendering.

Why it works: the breakout terminates the attribute early, and the remaining
text is reparsed as new attributes on the same tag; event handlers need no
new tag, which is what makes them the right family in attribute context.

Expected success signal: the marker executes in the headless browser when the
parameter carries the payload. A payload that requires interaction (hover)
must say so in `expected_success_signal` — the verifier drives the page and
needs to know what action triggers it.
