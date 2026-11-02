"""Structural quality gate for the knowledge/ RAG corpus.

Walks every chunk under knowledge/ and enforces the format rules from
knowledge/README.md: required frontmatter keys, id/filename agreement,
class/directory consistency, one context map per class, 100-300 word
bodies, and globally unique ids. Run with the normal suite:

    python -m unittest discover -s tests
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"
EXPECTED_CLASSES = [
    "auth_bypass", "idor", "jwt_misconfig", "open_redirect", "sqli", "ssrf",
    "xss_reflected",
]
REQUIRED_KEYS = ["id", "class", "kind", "title", "applies_when", "source", "tags"]
ALLOWED_KINDS = {"technique", "context_map"}
MIN_BODY_WORDS, MAX_BODY_WORDS = 100, 300


def _parse_chunk(path: Path) -> tuple[dict, str]:
    """Parse frontmatter (flat key: value, tags as [a, b]) and body."""
    text = path.read_text(encoding="utf-8")
    m = re.match(r"\A---\n(.*?)\n---\n(.*)\Z", text, re.S)
    if not m:
        raise ValueError(f"{path.name}: missing '---\\n...\\n---' frontmatter block")

    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"{path.name}: frontmatter line not 'key: value': {line!r}")
        meta[key.strip()] = value.strip()

    body = m.group(2).strip()
    return meta, body


def _iter_chunks() -> list[tuple[Path, dict, str]]:
    chunks = []
    for class_dir in sorted(KNOWLEDGE_DIR.iterdir()):
        if not class_dir.is_dir():
            continue
        for path in sorted(class_dir.glob("*.md")):
            meta, body = _parse_chunk(path)
            chunks.append((path, meta, body))
    return chunks


class KnowledgeCorpusTests(unittest.TestCase):
    def test_expected_class_directories_exist(self):
        actual = sorted(d.name for d in KNOWLEDGE_DIR.iterdir() if d.is_dir())
        self.assertEqual(actual, EXPECTED_CLASSES)
        for name in EXPECTED_CLASSES:
            self.assertTrue(
                any((KNOWLEDGE_DIR / name).glob("*.md")),
                f"class directory {name} has no chunks",
            )

    def test_required_frontmatter_and_field_rules(self):
        for path, meta, _body in _iter_chunks():
            for key in REQUIRED_KEYS:
                self.assertIn(key, meta, f"{path.name}: missing frontmatter key '{key}'")
            self.assertEqual(
                meta["id"], path.stem,
                f"{path.name}: id {meta['id']!r} must equal filename stem {path.stem!r}",
            )
            self.assertEqual(
                meta["class"], path.parent.name,
                f"{path.name}: class {meta['class']!r} must equal directory {path.parent.name!r}",
            )
            self.assertIn(meta["kind"], ALLOWED_KINDS, f"{path.name}: bad kind {meta['kind']!r}")
            self.assertRegex(meta["tags"], r"^\[.+\]$", f"{path.name}: tags must look like [a, b]")

    def test_one_context_map_per_class(self):
        maps: dict[str, int] = {}
        for path, meta, _body in _iter_chunks():
            if meta["kind"] == "context_map":
                maps[meta["class"]] = maps.get(meta["class"], 0) + 1
                self.assertTrue(
                    path.stem.endswith("-00-context-matching"),
                    f"{path.name}: the context map must be named <class>-00-context-matching.md",
                )
        for name in EXPECTED_CLASSES:
            self.assertEqual(maps.get(name), 1, f"class {name}: expected exactly one context map")

    def test_body_word_count_100_to_300(self):
        for path, _meta, body in _iter_chunks():
            words = len(body.split())
            self.assertTrue(
                MIN_BODY_WORDS <= words <= MAX_BODY_WORDS,
                f"{path.name}: body has {words} words (allowed {MIN_BODY_WORDS}-{MAX_BODY_WORDS})",
            )

    def test_ids_globally_unique(self):
        seen: dict[str, str] = {}
        for path, meta, _body in _iter_chunks():
            first = seen.setdefault(meta["id"], path.name)
            self.assertEqual(
                first, path.name,
                f"duplicate id {meta['id']!r} in {path.name} (already in {first})",
            )

    def test_manifest_lists_every_class(self):
        import json
        manifest = json.loads((KNOWLEDGE_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(manifest["classes"]), EXPECTED_CLASSES)
        self.assertTrue(manifest["upstream"], "manifest must carry upstream provenance")
        self.assertEqual(sorted(manifest["curation"]["hand_written_classes"]),
                         ["auth_bypass", "jwt_misconfig"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
