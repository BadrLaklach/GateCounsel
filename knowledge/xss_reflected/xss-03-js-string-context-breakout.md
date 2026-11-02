---
id: xss-03-js-string-context-breakout
class: xss_reflected
kind: technique
title: Reflected XSS inside a JavaScript string — quote breakout or tag termination
applies_when: the marker value appears between quotes inside an inline script block or a template literal
source: HackTricks XSS README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [js-string, breakout, template-literal, script-close]
---

When the value is interpolated into inline JavaScript, the goal is to leave
the string literal and reach statement position:

- Single-quoted string: `';marker();//` — close the quote, run the marker,
  comment out the trailing original quote.
- Backtick template literal: `${marker()}` — no quote breakout needed;
  interpolation is native to the context.
- Quotes escaped with backslashes: break the block instead of the string —
  `</script><svg onload=marker()>` — because the HTML parser ends the script
  element at the first `</script>`, regardless of JavaScript string state.

The third variant is the important insight of this context: the HTML parser
and the JavaScript parser disagree about where the string ends. If recon
shows the marker reflected inside `<script>`, always consider closing the
script tag itself before fighting the escaping.

Why it works: the payload changes parser state — string terminator plus
statement, or an HTML-level element boundary the JS escaper cannot protect.

Expected success signal: the marker function executes (observable DOM marker
set) with the payload in the parameter; for the `</script>` variant, the
verifier must observe execution after the original block is truncated, so
page breakage without the marker does not count.
