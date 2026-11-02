---
id: sqli-02-error-based
class: sqli
kind: technique
title: Error-based SQL injection — confirming via driver error output
applies_when: a syntax breaker produced a database error string in the response body
source: HackTricks SQL Injection README (commit f66c437, CC-BY-NC-4.0), paraphrased; technique families cross-checked against PayloadsAllTheThings (MIT)
tags: [error-based, extractvalue, updatexml, xmltype]
---

When errors surface to the response, the cheapest confirmation is a payload
that makes the database echo a marker inside its own error text. The
function that raises the informative error is vendor-specific:

- MySQL: `' AND extractvalue(1, concat(0x7e, (SELECT 'marker')))-- ` or the
  `updatexml` twin.
- MSSQL: conversion failures, e.g. `' AND 1=CONVERT(int, 'marker')--`.
- PostgreSQL: `' AND 1=(SELECT CAST('marker' AS int))--`.
- Oracle: `XMLType` errors, e.g. `' AND XMLType('<x>marker</x>')='1`.

Why it works: these functions are legal expressions whose failure message
embeds their argument, so a constant marker travels into the error path
without reading any schema or data. That keeps the probe read-only and
bounded — the class boundary forbids extraction, and a constant is all the
confirmation needs.

One request, one vendor guess at a time: if recon or a prior error shows the
vendor (see the fingerprint chunk), start with its function; otherwise order
MySQL, PostgreSQL, MSSQL by deployment frequency and let the error wording
correct you.

Expected success signal: response contains the literal marker string inside
a database error message. If the error appears but the marker does not, the
injection point may be blind — fall back to boolean-based.
