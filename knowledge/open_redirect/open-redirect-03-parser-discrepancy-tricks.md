---
id: open-redirect-03-parser-discrepancy-tricks
class: open_redirect
kind: technique
title: Parser discrepancy tricks — encoding forms the validator misses
applies_when: validation normalizes or decodes the value differently than the code that emits the Location header
source: HackTricks Open Redirect and URL Format Bypass pages (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [encoding, double-encoding, normalization, validation-vs-use]
---

The class of open redirect where validation and use read *different parsed
forms* of the same input. Families, each a single targeted request:

- **URL-encoded delimiters**: `%2F%2Ffixture.lab%2Fnext` — a validator
  inspecting the raw string sees no slashes; the emitter decodes before
  writing `Location`, producing `//fixture.lab/next`.
- **Double encoding**: `%252F` where the value is decoded twice (once by
  the framework, once before emit) — first decode yields `%2F`, second
  yields `/`.
- **Dot-segment normalization**: `/./fixture` and `/a/../fixture.lab/`
  forms that survive prefix checks (`/trusted/...`) but normalize to an
  external path at emit time.
- **Unicode/scheme tricks**: full-width or encoded scheme separators that
  normalize to `:` or `/` late.
- **Fragment/query carriers**: `https://trusted.example#@fixture.lab/` or
  `?` variants — some parsers honor the fragment as part of the redirect
  base, others discard it.

Why it works: validation ran on one representation; the emitter wrote
another. The chunk's defense lesson mirrors GateCounsel's own scope rule:
parse once, canonicalize, validate the canonical form, and emit exactly
that form.

Expected success signal: the emitted `Location` (after the receiver
normalizes it) resolves to the fixture origin while the raw validated value
did not. Verdict confidence should be low until one request demonstrates
the discrepancy — this family is the most implementation-dependent of the
class.
