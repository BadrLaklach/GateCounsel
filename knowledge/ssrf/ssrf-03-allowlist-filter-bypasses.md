---
id: ssrf-03-allowlist-filter-bypasses
class: ssrf
kind: technique
title: Hostname allowlist bypasses — prefix, suffix, and subdomain mistakes
applies_when: the application permits only hosts it considers trusted, by string matching on the hostname
source: HackTricks SSRF README (commit f66c437, CC-BY-NC-4.0), paraphrased
tags: [allowlist, prefix-check, subdomain, dns]
---

Allowlists fail on how they compare, not on what they list. Families of
mistakes to test, matched to the failure you can observe:

- **Prefix match**: `startswith("allowed")` accepts
  `allowed.receiver.lab` — attacker-controlled namespace under a shared
  prefix, or `allowed-example.receiver.lab`.
- **Suffix/contains match**: the check sees `receiver.lab/allowed.example`
  or a query string carrying the trusted name
  (`http://receiver.lab/?allowed=allowed.example`) while the fetch goes to
  the attacker host.
- **Subdomain assumption**: a check that any subdomain is trusted
  (`*.allowed.example`) — a wildcard DNS or a takeover under that suffix
  redirects the fetch.
- **DNS trust**: hostname looks benign but resolves wherever its record
  says — rebinding flips the answer between validation time and fetch time.

Why it works: the validator and the resolver answer different questions
("does the string mention the trusted host?" versus "where does this host
point?"), and only the second one moves packets.

Defense-side lesson for the report: exact-match the parsed hostname, pin
the resolved addresses, and re-validate every redirect hop.

Expected success signal: receiver logs the case ID with the payload URL
formed as the bypass spelling. One family per verdict; the `reasoning`
names which matcher flaw (prefix/suffix/subdomain) the evidence suggests.
