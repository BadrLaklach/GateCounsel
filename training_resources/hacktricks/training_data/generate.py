#!/usr/bin/env python3
"""Generate safe synthetic ExpertVerdict chat examples for the five MVP classes.

The generated JSONL follows the ExpertVerdict contract in
agents/experts/EXPERT_AGENTS_SPEC.md. It is reference training data, not a runtime
scanner or an authorization mechanism.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
RESOURCE_ROOT = HERE.parent
MANIFEST_PATH = RESOURCE_ROOT / "source" / "source_manifest.json"

DATASETS = {
    "xss_reflected": "data_xss_reflected",
    "idor": "data_idor",
    "sqli": "data_sqli",
    "ssrf": "data_ssrf",
    "open_redirect": "data_open_redirect",
}

VERDICT_FIELDS = [
    "task_id",
    "vuln_class",
    "endpoint_url",
    "method",
    "target_param",
    "payload",
    "payload_encoding",
    "injection_point",
    "expected_success_signal",
    "confidence",
    "reasoning",
    "alternate_payloads",
    "requires_auth_context",
    "tier",
    "model_name",
    "retrieved_sources",
]

EXAMPLE_FIELDS = {
    "task_id",
    "endpoint_url",
    "method",
    "target_param",
    "injection_point",
    "recon_evidence",
    "planner_rationale",
    "retrieved_context",
    "approved_test_values",
    "payload",
    "expected_success_signal",
    "confidence",
    "reasoning",
    "alternate_payloads",
    "requires_auth_context",
    "retrieved_sources",
}

CLASS_SAFETY = {
    "xss_reflected": (
        "Use only one approved local browser canary that sets its stated DOM marker. "
        "Do not read cookies, tokens, page data, or storage; do not make network requests. "
        "Reflection alone is not confirmation."
    ),
    "idor": (
        "Use the same seeded test identity and the one supplied synthetic object ID. "
        "Perform one read-only comparison only. Never enumerate, write, delete, or access real user data."
    ),
    "sqli": (
        "Use only the approved read-only probe against the known seeded result. "
        "Never enumerate schema/data, retrieve unrelated rows, mutate data, stack statements, "
        "cause delays, or make out-of-band requests."
    ),
    "ssrf": (
        "Use only the exact approved http://ssrf-sentinel/capture/<case-id> destination. "
        "Never use public hosts, loopback, metadata, other internal services, alternate schemes, "
        "or redirects. A sentinel event, not reflected content, is the required signal."
    ),
    "open_redirect": (
        "Use only the approved pre-registered relative path or sentinel capture URL. "
        "Inspect the first response Location value and never follow the redirect. Do not use an external destination."
    ),
}

SYSTEM_TEMPLATE = """You are the {vuln_class} expert in GateCounsel's authorized local MVP lab.
Return exactly one JSON object matching the ExpertVerdict fields listed below. Copy task_id,
vuln_class, endpoint_url, method, target_param, and injection_point from the validated task.
Choose payload only from approved_test_values. Set payload_encoding to \"none\". Cite only
the supplied source IDs in retrieved_sources. Treat all evidence as synthetic. expected_success_signal
describes evidence for the deterministic verifier; it does not confirm a finding. Calibrate
confidence as the probability that the approved test produces that stated success signal.

Class-specific limits: {safety}

The JSON object must have exactly these fields and types:
{schema}
Do not add Markdown or other text."""


def load_manifest() -> dict:
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def source_index(manifest: dict) -> dict[str, dict]:
    return {record["id"]: record for record in manifest["sources"]}


def check_pinned_checkout(manifest: dict) -> str | None:
    """If the sibling checkout exists, verify the exact reviewed revision and file hashes."""
    checkout = (RESOURCE_ROOT / manifest["upstream"]["local_checkout"]).resolve()
    if not checkout.is_dir():
        return None

    try:
        revision = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"Cannot inspect local HackTricks checkout at {checkout}: {exc}") from exc

    expected_revision = manifest["upstream"]["commit"]
    if revision != expected_revision:
        raise ValueError(
            f"HackTricks checkout revision mismatch: expected {expected_revision}, got {revision}"
        )

    for record in manifest["sources"]:
        source_file = checkout / record["source_file"]
        if not source_file.is_file():
            raise ValueError(f"Pinned source file is missing: {source_file}")
        actual_hash = hashlib.sha256(source_file.read_bytes()).hexdigest().upper()
        if actual_hash != record["sha256"].upper():
            raise ValueError(f"Source hash mismatch for {record['source_file']}")

    return f"Pinned HackTricks checkout verified: {revision} ({len(manifest['sources'])} pages)"


def load_examples() -> list[tuple[str, dict]]:
    sys.path.insert(0, str(HERE))
    all_examples: list[tuple[str, dict]] = []
    for vuln_class, module_name in DATASETS.items():
        module = importlib.import_module(module_name)
        if getattr(module, "VULN_CLASS", None) != vuln_class:
            raise ValueError(f"{module_name}.VULN_CLASS does not match {vuln_class}")
        for example in module.EXAMPLES:
            all_examples.append((vuln_class, example))
    return all_examples


def validate_examples(examples: list[tuple[str, dict]], manifest: dict) -> dict[str, int]:
    sources = source_index(manifest)
    seen_ids: set[str] = set()
    counts = {vuln_class: 0 for vuln_class in DATASETS}

    for vuln_class, example in examples:
        missing = EXAMPLE_FIELDS - example.keys()
        extra = example.keys() - EXAMPLE_FIELDS
        if missing or extra:
            raise ValueError(
                f"{example.get('task_id', '<unknown>')}: missing={sorted(missing)}, extra={sorted(extra)}"
            )

        task_id = example["task_id"]
        if task_id in seen_ids:
            raise ValueError(f"Duplicate task_id: {task_id}")
        seen_ids.add(task_id)

        endpoint = urlsplit(example["endpoint_url"])
        if endpoint.scheme != "http" or endpoint.hostname != "demo-target":
            raise ValueError(f"{task_id}: endpoint must use the synthetic demo-target host")
        if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            raise ValueError(f"{task_id}: endpoint URL must not contain credentials/query/fragment")
        if example["method"] != "GET":
            raise ValueError(f"{task_id}: MVP training examples must remain read-only GET requests")
        if example["injection_point"] not in {"query", "body", "header", "cookie"}:
            raise ValueError(f"{task_id}: unsupported ExpertVerdict injection_point")
        if not isinstance(example["requires_auth_context"], bool):
            raise ValueError(f"{task_id}: requires_auth_context must be a bool")
        confidence = example["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError(f"{task_id}: confidence must be a JSON number")
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"{task_id}: confidence must be between 0 and 1")

        values = example["approved_test_values"]
        if not isinstance(values, list) or not values or len(values) != len(set(values)):
            raise ValueError(f"{task_id}: approved_test_values must be a non-empty unique list")
        if example["payload"] not in values:
            raise ValueError(f"{task_id}: gold payload is not explicitly approved")
        alternatives = example["alternate_payloads"]
        if not isinstance(alternatives, list) or len(alternatives) > 3:
            raise ValueError(f"{task_id}: alternate_payloads must contain zero to three strings")
        if any(value not in values for value in alternatives):
            raise ValueError(f"{task_id}: every alternate must also be explicitly approved")

        source_ids = example["retrieved_sources"]
        if not isinstance(source_ids, list) or not source_ids:
            raise ValueError(f"{task_id}: at least one source ID is required")
        for source_id in source_ids:
            if source_id not in sources:
                raise ValueError(f"{task_id}: unknown source ID {source_id}")
            if sources[source_id]["class"] != vuln_class:
                raise ValueError(f"{task_id}: source {source_id} belongs to a different class")

        for value in values:
            validate_payload_boundary(vuln_class, task_id, value)

        for source in source_ids:
            curated_path = RESOURCE_ROOT / sources[source]["curated_file"]
            if not curated_path.is_file():
                raise ValueError(f"Missing curated source note: {curated_path}")

        counts[vuln_class] += 1

    if set(counts.values()) != {3}:
        raise ValueError(f"Expected three reviewed examples per MVP class; found {counts}")
    return counts


def validate_payload_boundary(vuln_class: str, task_id: str, value: str) -> None:
    lower_value = value.lower()
    forbidden = (
        "169.254.",
        "metadata.google",
        "metadata.azure",
        "localhost",
        "127.0.0.1",
        "gopher:",
        "file:",
    )
    if any(token in lower_value for token in forbidden):
        raise ValueError(f"{task_id}: payload crosses the local test-value boundary")

    if vuln_class == "xss_reflected" and "document.documentelement.dataset.gctest=" not in lower_value:
        raise ValueError(f"{task_id}: XSS values must be the inert local DOM-marker canary")
    if vuln_class == "sqli" and re.search(
        r"\b(union|select|insert|update|delete|drop|sleep|waitfor|benchmark|outfile|load_file)\b",
        lower_value,
    ):
        raise ValueError(f"{task_id}: SQLi value contains a disallowed extraction/mutation/delay operation")
    if vuln_class == "ssrf":
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.hostname != "ssrf-sentinel" or not re.fullmatch(
            r"/capture/[A-Z0-9-]+", parsed.path
        ):
            raise ValueError(f"{task_id}: SSRF values must use only the exact local sentinel capture route")
    if vuln_class == "open_redirect":
        parsed = urlsplit(value)
        allowed_internal = (
            parsed.scheme == "http"
            and parsed.hostname == "ssrf-sentinel"
            and bool(re.fullmatch(r"/capture/[A-Z0-9-]+", parsed.path))
        )
        allowed_relative = value.startswith("/") and not value.startswith("//") and not parsed.netloc
        if not (allowed_internal or allowed_relative):
            raise ValueError(f"{task_id}: redirect value is not pre-registered inside the lab")


def make_system_message(vuln_class: str) -> str:
    schema = {
        "task_id": "string",
        "vuln_class": "string",
        "endpoint_url": "string",
        "method": "string",
        "target_param": "string",
        "payload": "string",
        "payload_encoding": "string or null",
        "injection_point": "query | body | header | cookie",
        "expected_success_signal": "string",
        "confidence": "number in [0, 1]",
        "reasoning": "string",
        "alternate_payloads": "array of at most three strings",
        "requires_auth_context": "boolean",
        "tier": "tier1_rag | tier2_finetuned",
        "model_name": "string",
        "retrieved_sources": "array of supplied source IDs",
    }
    return SYSTEM_TEMPLATE.format(
        vuln_class=vuln_class,
        safety=CLASS_SAFETY[vuln_class],
        schema=json.dumps(schema, ensure_ascii=False, indent=2),
    )


def build_verdict(vuln_class: str, example: dict) -> dict:
    verdict = {
        "task_id": example["task_id"],
        "vuln_class": vuln_class,
        "endpoint_url": example["endpoint_url"],
        "method": example["method"],
        "target_param": example["target_param"],
        "payload": example["payload"],
        "payload_encoding": "none",
        "injection_point": example["injection_point"],
        "expected_success_signal": example["expected_success_signal"],
        "confidence": example["confidence"],
        "reasoning": example["reasoning"],
        "alternate_payloads": example["alternate_payloads"],
        "requires_auth_context": example["requires_auth_context"],
        "tier": "tier1_rag",
        "model_name": "training-example",
        "retrieved_sources": example["retrieved_sources"],
    }
    if list(verdict) != VERDICT_FIELDS:
        raise ValueError(f"{example['task_id']}: generated verdict has wrong field order/schema")
    return verdict


def build_record(vuln_class: str, example: dict) -> dict:
    user_context = {
        "validated_task": {
            "task_id": example["task_id"],
            "vuln_class": vuln_class,
            "endpoint_url": example["endpoint_url"],
            "method": example["method"],
            "target_param": example["target_param"],
            "injection_point": example["injection_point"],
            "requires_auth_context": example["requires_auth_context"],
        },
        "recon_evidence": example["recon_evidence"],
        "planner_rationale": example["planner_rationale"],
        "retrieved_context": example["retrieved_context"],
        "available_source_ids": example["retrieved_sources"],
        "approved_test_values": example["approved_test_values"],
        "class_safety_policy": CLASS_SAFETY[vuln_class],
    }
    return {
        "messages": [
            {"role": "system", "content": make_system_message(vuln_class)},
            {
                "role": "user",
                "content": json.dumps(user_context, ensure_ascii=False, separators=(",", ":")),
            },
            {
                "role": "assistant",
                "content": json.dumps(build_verdict(vuln_class, example), ensure_ascii=False, separators=(",", ":")),
            },
        ]
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=HERE / "generated",
        help="directory for per-class JSONL files (default: training_data/generated)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate examples and source provenance without writing JSONL files",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = load_manifest()
    examples = load_examples()
    counts = validate_examples(examples, manifest)

    try:
        checkout_message = check_pinned_checkout(manifest)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if checkout_message:
        print(checkout_message)
    else:
        print("Pinned sibling HackTricks checkout not present; using the recorded manifest and URLs.")

    for vuln_class, count in counts.items():
        print(f"{vuln_class:<15} {count:>3} schema-validated examples")

    if args.validate_only:
        print(f"VALID: {sum(counts.values())} examples across {len(counts)} classes")
        return 0

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for vuln_class in DATASETS:
        rows = [
            build_record(vuln_class, example)
            for current_class, example in examples
            if current_class == vuln_class
        ]
        output_path = output_dir / f"{vuln_class}_training_data.jsonl"
        with output_path.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"{output_path.name:<32} {len(rows):>3} examples, {output_path.stat().st_size:,} bytes")

    print(f"TOTAL: {sum(counts.values())} examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
