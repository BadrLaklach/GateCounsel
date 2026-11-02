---
id: ssrf-04-cloud-metadata
class: ssrf
kind: technique
title: Cloud metadata endpoints — recognition and lab boundary
applies_when: the target environment is cloud-hosted or exposes cloud-style behavior, and an SSRF-capable parameter exists
source: HackTricks SSRF cloud page (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [cloud, metadata, 169.254.169.254, detection]
---

Every major cloud exposes a link-local metadata service at
`169.254.169.254` (and modern variants requiring a session token header).
An SSRF that can reach it can read instance identity, and sometimes
short-lived credentials — the highest-impact SSRF target in real
environments.

This chunk exists for **detection reasoning, not exploitation**: knowing
the metadata pattern explains why URL filters must block link-local and
loopback ranges wholesale, and why a verdict must never propose one.

In GateCounsel's lab both rules apply absolutely:

- No verdict, payload, or probe may target metadata addresses, link-local
  ranges, loopback spellings, or alternate schemes (`file://`, `gopher://`,
  `dict://`) — the destination allowlist permits only the controlled
  receiver.
- If a task's evidence suggests cloud hosting, the correct expert output is
  a low-confidence *flag* in `reasoning` ("metadata exposure is the
  real-world risk class here; lab boundary forbids the probe"), not a
  metadata URL in `payload`.

Expected success signal for legitimate lab use: none — this chunk never
produces a fetchable payload; it informs reasoning, risk framing, and the
defense notes in the report (block link-local at the network layer, enforce
IMDSv2-style session requirements, and never let user input choose the
scheme or address class).
