---
id: ssrf-01-confirming-with-a-controlled-receiver
class: ssrf
kind: technique
title: Confirming SSRF with a controlled receiver and unique case ID
applies_when: a URL-accepting parameter exists and the lab provides a request-logging receiver endpoint
source: HackTricks SSRF README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [receiver, callback, case-id, evidence, backend, fetches, visits, link]
---

The strongest SSRF evidence does not depend on the target's response at
all: give the server a URL that points at a receiver you control, tagged
with a unique case ID, and let the receiver's log prove the fetch.

Method:

1. Mint a case ID unique to this verdict (so no other request can be
  confused with it).
2. Submit the receiver URL carrying that ID as the parameter value.
3. Read the receiver log: a hit containing the ID proves the application
  server made that exact request.

Why this beats response-inspection: fetched-content signals fail when the
application hides the response (background fetch, webhook processors,
fire-and-forget proxies); the receiver observes the request itself. It also
survives silent failures — no hit is a clean negative, not ambiguity.

The verdict's `payload` is the full receiver URL; `expected_success_signal`
is "receiver logs a request containing the case ID" — the verifier checks
the receiver, not the application response.

Boundary: in the GateCounsel lab the receiver is `ssrf-sentinel` and the
path is its fixed capture route; nothing about this technique authorizes
public hosts, loopback tricks, or other internal services — those belong to
the bypass chunks as detection patterns, proven only against the receiver.
