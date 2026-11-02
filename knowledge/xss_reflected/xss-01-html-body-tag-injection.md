---
id: xss-01-html-body-tag-injection
class: xss_reflected
kind: technique
title: Reflected XSS into raw HTML body — tag injection
applies_when: the marker value appears in HTML text outside any tag, and angle brackets survive reflection unescaped
source: HackTricks XSS README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [raw-html, tag-injection, script, img-onerror, svg]
---

When the value lands as HTML text and `<`/`>` are not encoded, the canonical
first payload opens a new executable element:

- `<script>marker()</script>` — cleanest, but first on every blacklist.
- `<img src=x onerror=marker()>` — survives `<script>` filtering because no
  script tag is needed; the event handler fires on the broken image.
- `<svg onload=marker()>` — compact alternative when `onerror` is filtered.

Substitute a benign DOM marker function for `marker()` (for example setting
`window.name` or a unique attribute the verifier can observe in the headless
browser). Never read cookies, tokens, or page data, and never make the
payload issue network requests.

Why it works: in raw HTML context the parser treats the reflected value as
markup, so opening a tag starts a new element owned by the payload. If recon
reported `reflection=raw` with angle brackets surviving, confidence is high;
if the page is a JSON content type rendered by an SPA framework, it is
probably not raw HTML — lower confidence and prefer the DOM chunk.

Expected success signal: the marker appears in the rendered DOM (or the
marker function executes) in the headless browser after the parameter is set
to the payload.
