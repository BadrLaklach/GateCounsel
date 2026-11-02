---
id: sqli-07-filter-and-waf-bypass-encodings
class: sqli
kind: technique
title: Filter and WAF bypasses — answering the observed defense
applies_when: a payload was rejected, blocked, or canonicalized, and the response indicates a filter or WAF layer
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased; encoding families cross-checked against PayloadsAllTheThings (MIT)
tags: [waf, filter, encoding, comments, no-quotes]
---

One observed defense, one answering variant — never a blind spray:

- **Spaces blocked**: comment separators `/**/` (`'/**/AND/**/1=1`), or
  parentheses grouping.
- **Quotes blocked**: numeric-context payloads (drop quotes entirely:
  `AND 1=1`), or hex literals (`0x6d61726b6572` for `marker`) where a string
  constant is needed.
- **Keywords blacklisted**: case variation (`SeLeCt`), inline comment
  splitting on MySQL (`SE/**/LECT`), equivalent keywords (`AND` ↔ `&&`).
- **Characters URL-mangled**: URL-encode the breaker (`%27`), and
  double-encode (`%2527`) when the value is decoded twice before the query.
- **Content-type confusion**: a JSON body that string-escapes quotes may
  still pass a `\\u0027` unicode escape to the driver.

Method: resend the *same* logical payload with exactly one transformation,
and read what comes back — reflected output shows which layer rewrote the
value. The verdict must name the defense it is answering (blocked keyword,
mangled character) in `reasoning`; a variant without an observed defense to
answer is a guess, and confidence should say so.

Expected success signal: the transformed payload achieves the same
application-level differential the original was aiming for (marker row,
error text, boolean flip, or bounded delay per the sibling chunks).
