---
id: open-redirect-02-filter-evasion-variants
class: open_redirect
kind: technique
title: Filter evasion variants — surviving scheme and host checks
applies_when: a plain absolute destination was rejected or rewritten, showing the application validates scheme or host
source: HackTricks Open Redirect page (commit f66c437, CC-BY-NC-4.0), paraphrased; variant families cross-checked against PayloadsAllTheThings (MIT)
tags: [scheme-relative, userinfo, backslash, case, whitespace]
---

Each variant answers one observed check — send one per request and read
which check it defeats:

- **Scheme-relative**: `//fixture.lab/next` — no scheme for a scheme
  validator to reject; the browser inherits the page's scheme and still
  goes cross-origin.
- **Userinfo confusion**: `https://trusted.example@fixture.lab/` — a check
  reading "does it start with the trusted host" passes while the parser
  fetches the host after `@`.
- **Backslash**: `https:/\fixture.lab/` or `\/fixture.lab` — validators
  treating `\` as inert, parsers (and browsers) treating it as `/`.
- **Third-party-slash**: `https://trusted.example/fixture.lab` or
  `//trusted.example@fixture.lab` — for "contains trusted host" checks.
- **Case and whitespace**: `hTtPs://fixture.lab`, embedded tab/newline —
  normalization differences between the checker and the emitter.
- **Trusted-host prefix**: `https://trusted.example.fixture.lab/` — the
  destination really is a different host whose *name* contains the trusted
  one (only meaningful where such naming exists in the lab).

Why these work: every one is a case where two components disagree about how
to read the same string. The defense-side lesson is exact-match on the
parsed origin, never substring checks on the raw value.

Expected success signal: the first `Location` header resolves to the
fixture origin for exactly one variant, and `reasoning` names the defeated
check.
