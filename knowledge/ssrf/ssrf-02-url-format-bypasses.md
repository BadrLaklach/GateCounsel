---
id: ssrf-02-url-format-bypasses
class: ssrf
kind: technique
title: URL format bypasses — one URL, two parsers
applies_when: validation inspects the raw URL string but a different component parses it before the fetch
source: HackTricks URL Format Bypass page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [parser-discrepancy, ip-encoding, userinfo, scheme]
---

Filters that check the URL as text are often bypassed by forms that read
differently to a validator and to the fetcher's URL parser. Pattern
families, each answering a specific observed check:

- **Literal hostname/IP blocked**: alternative encodings of the same
  address — decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`),
  and shortened forms (`127.1`), or IPv6 bracket forms.
- **Scheme checked as prefix**: embedded credentials change where the host
  really is — `http://allowed.example@receiver.lab/` parses to the host
  after `@`, while a prefix check sees `allowed.example`.
- **Backslash confusion**: `http:\\receiver.lab` — some parsers treat `\`
  as `/`, validators often do not.
- **Case and trailing noise**: mixed-case schemes and trailing dots or
  whitespace that one layer strips.

Why it works: URL parsing is not one operation. Validation that runs on the
raw string while the fetch resolves a parsed (or re-parsed) form lets the
two disagree about the destination — the chunk's core lesson for the
defense side is to validate and fetch the *same canonical parsed form*.

Expected success signal: the receiver logs the case ID despite the filter
(having exactly the receiver's address in one of its alternative spellings
where the lab permits). In verdicts, name the observed check being answered
in `reasoning`.
