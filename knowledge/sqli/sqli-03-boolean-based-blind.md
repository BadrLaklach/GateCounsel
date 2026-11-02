---
id: sqli-03-boolean-based-blind
class: sqli
kind: technique
title: Boolean-based blind SQL injection — flipping an observable condition
applies_when: the response differs between two stable states (seeded record present versus absent) but no error text surfaces
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [blind, boolean, conditional, baseline]
---

With no error output, prove query control by changing a boolean condition
and observing the seeded record's presence:

1. Baseline: `...?id=7` renders the seeded record.
2. True condition: `...?id=7' AND 1=1-- ` — identical to baseline.
3. False condition: `...?id=7' AND 1=2-- ` — record disappears or the page
   changes state.

The differential (true-state == baseline, false-state != baseline) is the
finding. Any stable, application-level difference works: record visibility,
a count label, a redirect target. Length-only differences are weak signals —
name something specific in the verdict.

Numeric contexts need no quotes: `AND 1=1` directly. JSON body injection
follows the same pattern inside the quoted field.

Why it works: the injected predicate participates in the query's `WHERE`
clause, so the attacker-chosen boolean decides which rows return — query
semantics changed, which is the definition of the class.

Expected success signal: with the true payload the seeded record renders
exactly as baseline; with the false payload it does not. Both halves are
required — a single differing response is not boolean confirmation. The
verdict should emit the true-payload as primary and name the false-payload
check in `expected_success_signal` or `reasoning`.
