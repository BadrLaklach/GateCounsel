# Training Resources Review — Simple Summary for the Team

**Date:** 16 October 2026
**Scope:** A full read-only review of `training_resources/` (HackTricks set, PayloadsAllTheThings set, DVWA knowledge base). Nothing in the project was changed. This note explains what we found, why it matters, and what decisions we need to make.

---

## 1. First, the context in two paragraphs

GateCounsel's MVP needs AI "expert agents" for five vulnerability classes (reflected XSS, IDOR, SQLi, SSRF, open redirect). These experts work in two ways:

- **RAG (retrieval):** before answering, the expert searches a small, curated, local collection of security notes for its own vulnerability class, and uses those notes as context.
- **Fine-tuning (later, optional):** a small model can be trained on example conversations so it learns to produce good test proposals for one class.

Both of these need **training resources**: curated notes + example data. The repo currently has two such resource folders, and the question we reviewed is: **are they good enough and safe enough for the MVP objective?**

The MVP has one golden rule that everything must respect: **expert proposals are unexecuted suggestions only, and every payload must come from a small "harmless lab allowlist"** (synthetic `demo-target` endpoints, read-only checks, lab-only SSRF sentinel, pre-registered redirect destinations). Deterministic code — not the AI — always has the final say.

---

## 2. The short version (TL;DR)

| Resource | Fits the MVP? | One-line reason |
|---|---|---|
| `training_resources/hacktricks/` | ✅ **Yes — make it the canonical resource** | Correct schema, strict safety validation, full provenance (license + pinned commit + hashes) |
| `training_resources/payloads_all_the_things/training_data/*.py` | ❌ **Not as-is** | Raw attack cheat-sheet payloads, old/incompatible output schema, no XSS class, no provenance |
| `payloads_all_the_things/training_data/dvwa_vulns_knowledge_base.json` | ⚠️ **Quarantine** | A live-assessment record of an external-looking server (`server.vulnapp.id`) with no authorization record, sitting in a public repo |
| `EXPLOIT_AGENT_SPEC.md` evidence-vocabulary pointer | ⚠️ **Stale** | Points at the PayloadsAllTheThings dataset; should point at HackTricks |

**Bottom line:** keep HackTricks as the reference resource; decide what to do with PayloadsAllTheThings before anyone wires it into training or the exploit pipeline.

---

## 3. Resource 1 — HackTricks: why it's good

This folder contains three things that work together:

1. **`source/source_manifest.json`** — the provenance record.
2. **`source/src/pentesting-web/*.md`** — 7 short, *paraphrased* notes (not copied text) covering the 5 MVP classes. These are the future RAG corpus.
3. **`training_data/data_*.py` + `generate.py`** — 15 synthetic examples (3 per class) that generate JSONL in the exact format our experts must output.

### 3.1 Provenance is exactly what the roadmap asked for

The manifest records: upstream repo, pinned commit `f66c437...`, the SHA-256 hash of every source page, the license (CC-BY-NC-4.0), and the curation method. The generator (`generate.py`) even **re-verifies the hashes** of the local HackTricks checkout before writing anything. If a page changes upstream, we can detect it.

> **Why this matters:** the full roadmap (Phase 7) says "treat RAG as a dataset: keep provenance, versions, metadata, and evaluation questions." This is the only resource in the repo that does that.

### 3.2 The examples follow the safety philosophy by construction

Every example must pass the generator's validation before a single JSONL line is written. Concretely, the validator enforces:

- endpoint must be `http://demo-target/...` (synthetic), GET only;
- every payload must appear in an explicit `approved_test_values` list — nothing outside the allowlist can be generated;
- SSRF payloads must be exactly `http://ssrf-sentinel/capture/<CASE-ID>` (our lab sentinel);
- open-redirect payloads must be pre-registered internal paths, never followed;
- SQLi payloads must not contain `union`, `select`, `sleep`, `load_file`, etc. (no extraction/mutation/delay);
- XSS payloads must be the inert DOM-marker canary;
- a hard boundary check bans `169.254.*` (cloud metadata), `localhost`, `127.0.0.1`, `gopher:`, `file:`.

**Example of the result (from `data_sqli.py`):** instead of a real injection payload, the "attack" is `41 AND 1=1` against a seeded fixture row — the test only checks whether the input is interpreted as SQL, and the expected signal is "the response returns only the same seeded record LAB-ITEM-41." Read-only, bounded, verifiable.

**Another good detail:** `HT-XSS-003` is a deliberate **negative control** — reflection is present but encoded, so the example's confidence is 0.10 and its expected signal says "if the browser displays escaped text, do not confirm XSS." This teaches the model *when not to claim a finding*, which is the core of our evidence-first design.

### 3.3 The output schema matches the expert contract exactly

`EXPERT_AGENTS_SPEC.md` §4 defines `ExpertVerdict` with **16 fields** (task_id, vuln_class, endpoint_url, method, target_param, payload, payload_encoding, injection_point, expected_success_signal, confidence, reasoning, alternate_payloads, requires_auth_context, tier, model_name, retrieved_sources). The HackTricks generator produces exactly these 16 fields in exactly this order. That means a model fine-tuned (or few-shot prompted) on this data produces output the future Exploit Agent can consume directly.

### 3.4 Honest limitations (not defects)

- **Volume:** 15 examples total. Fine as a floor/few-shot/eval seed; far too small for actual LoRA fine-tuning (which is deferred anyway, so this is fine for now).
- **Only one negative control** (in XSS). IDOR/SQLi/SSRF/open-redirect examples are all positive cases. The MVP requires positive *and* negative lab cases — the dataset should eventually mirror that.
- **RAG corpus is thin:** 7 short notes for 5 classes. Enough to bootstrap retrieval; not enough to meaningfully measure "does retrieval improve plan quality" (research question 2).
- **License note:** CC-BY-NC-4.0 is *NonCommercial*. Fine for an academic project; would constrain a future open-source release. It is correctly recorded — just remember it for the thesis write-up.

---

## 4. Resource 2 — PayloadsAllTheThings: why it doesn't fit as-is

This folder (`training_resources/payloads_all_the_things/`) was built **before** HackTricks and follows a different philosophy. It contains four data modules (`data_sqli.py`, `data_ssrf.py`, `data_idor.py`, `data_open_redirect.py`), a generator, and the DVWA knowledge base (section 5). Problems:

### 4.1 The payloads are real-world attack material, not lab-bounded proposals

The examples are verbatim cheat-sheet payloads aimed at real infrastructure. A few actual examples from the files:

- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — stealing AWS IAM credentials via SSRF;
- `gopher://127.0.0.1:6379/_...CONFIG SET dir /var/www/html...` — a full Redis-to-PHP-webshell attack chain;
- `file:///etc/passwd` — local file read;
- `DELETE /api/messages/697413` — "victim's message permanently deleted" (a **destructive** IDOR example);
- dozens of WAF/filter bypass encodings aimed at internal networks.

Each of these is a *legitimate technique reference* for a professional pentester. But our MVP's central design decision is the opposite: expert proposals must match a **finite harmless-lab allowlist**, and the verifier stays bounded. Training a model on this corpus teaches it to propose exactly the class of payloads our runtime is designed to reject.

> The clearest sign of the contradiction: the HackTricks generator's boundary check **bans** `169.254.*`, `localhost`, `gopher:`, `file:` — which are precisely the payloads this dataset is full of. The two resources enforce opposite rules.

### 4.2 The output schema is incompatible with the expert contract

`generate.py` here emits a **7-field** verdict (`vuln_class, target_param, payload, injection_point, expected_success_signal, confidence, reasoning`). Compared to the 16-field `ExpertVerdict`, it is missing `task_id`, `endpoint_url`, `method`, `payload_encoding`, `alternate_payloads`, `requires_auth_context`, `tier`, `model_name`, `retrieved_sources` — and it allows `"path"` as an injection point, which the contract does not. Anything trained or evaluated on this data cannot be consumed by the Exploit Agent as specified. The Exploit Agent joins verdicts to tasks by `task_id`; these examples have none.

### 4.3 Class coverage is incomplete

Only 4 of the 5 MVP classes — there is **no XSS module**.

### 4.4 No provenance

No README, no source manifest, no license record. The `source/` folder contains a single off-topic PDF (ImageMagick upload RCE — file upload is not an MVP class). Compare with HackTricks, which records everything.

### 4.5 What it's still good for

Don't delete the idea of it: methodologically this set is much richer (contexts, encodings, bypass families). It's a good **research reference** for later phases. But before it ever feeds training or the evidence-vocabulary contract, it needs the same treatment HackTricks got: manifest + license, regeneration against the 16-field schema, an XSS module, and — most importantly — the `approved_test_values` allowlist discipline.

---

## 5. The DVWA knowledge base — the provenance/authorization concern

`dvwa_vulns_knowledge_base.json` is not training examples — it is a **record of a live assessment** against `https://server.vulnapp.id/dvwa`. It documents, with "live_verified" evidence: PHP 5.2.4 / nginx 1.24 fingerprints, phpinfo dumped via an **uploaded PHP file** (`info2.php`), a discovered inventory of **17+ pre-existing uploaded webshells** (`MARIJUANA.php`, `dvwa-shell.php`, `pwn.php`, ...), and per-module vulnerability ground truth.

The file self-declares: "Authorized lab assessment (user-owned DVWA training instance)". But:

- there is **no authorization record anywhere in the repository**, and the same host (`server.vulnapp.id`) also appears in the tracked `plan.json`, which our own audit doc (section 4 of `CURRENT_PROJECT_STATE_AND_MVP_NEXT_STEPS.md`) already flagged as "unverified historical data — do not execute";
- the README and roadmap state testing is **lab-only**; two tracked artifacts referencing an undocumented, external-looking host contradict that narrative;
- publishing an inventory of a specific internet-facing server's vulnerabilities in a public repo is a **legal/reputational liability** for an academic project, even if the host is genuinely ours.

**Recommendation to discuss:** either document the authorization explicitly (who owns it, when, signed by whom) or replace the KB with a synthetic fixture. Until then, treat it as quarantined reference.

---

## 6. One inconsistency that will bite us during the exploit build

`EXPLOIT_AGENT_SPEC.md` (§6, §9) contains an "alignment rule": the exploit agent's tier-1 evidence strings must be phrased in lockstep with

> `training_resources/payloads_all_the_things/training_data/*_training_data.jsonl` — "because that is what the fine-tuned experts were trained on."

That pointer is now **stale**: it was written before the HackTricks dataset existed. It points at (a) the old 7-field dataset, (b) a dataset with no XSS coverage, (c) a dataset with the opposite safety philosophy. If we build the exploit agent's `evidence.py` per the spec as written, we will align the evidence vocabulary with the wrong corpus.

**Decision needed (one line):** HackTricks becomes the canonical vocabulary anchor, and the spec pointer gets updated — or we consciously keep PAT and accept its constraints.

---

## 7. Side-by-side comparison

| Criterion | HackTricks set | PayloadsAllTheThings set |
|---|---|---|
| Classes covered | 5 / 5 ✅ | 4 / 5 (no XSS) ❌ |
| Output schema | 16-field ExpertVerdict, exact match ✅ | 7-field legacy ❌ |
| Payload policy | approved-test-values allowlist, lab-only ✅ | Real-world payloads incl. metadata theft, RCE chains, destructive ops ❌ |
| Provenance (license, commit, hashes) | Full manifest ✅ | None ❌ |
| Negative-control examples | 1 (XSS) ⚠️ | 0 ⚠️ |
| Provenance of target hosts | Synthetic `demo-target` / `ssrf-sentinel` ✅ | External-looking hosts, undocumented ❌ |
| Volume | 15 examples (floor) ⚠️ | ~100+ examples (rich but unusable as-is) ⚠️ |

---

## 8. What we should decide (nothing has been changed yet)

1. **Adopt HackTricks as the canonical resource** for MVP RAG and expert examples. (No action needed — it's already correct.)
2. **Decide the fate of the PAT dataset**: either (a) upgrade it to HackTricks standards (manifest + 16-field schema + XSS module + allowlist discipline), or (b) explicitly label it as quarantined research reference, not training input.
3. **Decide the DVWA knowledge base question**: document authorization or replace with a synthetic fixture. Also resolve `plan.json` (same host) — the audit already recommended replacing it or documenting it.
4. **Update the stale pointer** in `EXPLOIT_AGENT_SPEC.md` §6/§9 to the canonical dataset.
5. **Later (post-MVP):** grow the HackTricks RAG notes (more chunks per class) and add negative-control examples for the other four classes — needed to answer research question 2 credibly.

---

## 9. Anticipated questions

**"Aren't the PayloadsAllTheThings payloads what a real pentest expert should know?"**
Yes — for a real-world tool. But GateCounsel's MVP is a *scope-constrained lab verifier*, not a real-world pentester. Its experts must propose payloads from a small harmless allowlist; anything outside it is rejected by design. Training data should teach the behavior the runtime can accept, not behavior the runtime must reject.

**"Is anything in the repo currently dangerous?"**
No. Nothing is wired to runtime; the resources are inert reference data. The issues are about *future* use (fine-tuning, RAG, evidence vocabulary) and about repository hygiene (undocumented host in a public repo).

**"What did you actually check?"**
Every file under `training_resources/` was read in full, plus `EXPERT_AGENTS_SPEC.md`, `EXPLOIT_AGENT_SPEC.md`, the MVP roadmap, the target architecture doc, and the 13 October audit. No files were modified; the review was read-only.
