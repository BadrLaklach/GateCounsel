---
id: sqli-05-union-based
class: sqli
kind: technique
title: UNION-based SQL injection — appending a marker row
applies_when: the endpoint renders query results to the page and a breaker produced a column-count error
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [union, order-by, column-count, marker-row]
---

When the page renders rows, a `UNION SELECT` can append a row the attacker
fully controls — the cleanest marker channel in this class. The only puzzle
is column count and type compatibility:

1. Find the count: `ORDER BY 1`, `ORDER BY 2`, ... until the response
   errors or changes — or binary-search it. Alternatively `UNION SELECT
   NULL` per column until the error stops.
2. Append a constant marker row: `?id=7' UNION SELECT NULL,'marker',NULL--
   ` placed where a string column renders.

Type rules: each `UNION` column must be compatible with the original
query's; start from all `NULL` and replace one column with the marker
string, adjusting position until it renders.

Why it works: `UNION` executes a second read-only `SELECT` and concatenates
its (constant, non-sensitive) result to the result set. The boundary holds
naturally: no table names, no `information_schema`, no data columns — a
constant marker is sufficient proof of control.

Expected success signal: the marker string appears as rendered result
content alongside or instead of the seeded record. A column-count error
that persists across all counts is evidence the endpoint aggregates or
errors out — recommend the boolean chunk instead.
