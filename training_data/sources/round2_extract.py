#!/usr/bin/env python3
"""Round 2 pipeline step 2: delegate H1 report extraction to opencode free models.

- 3 free models rotated round-robin (glm-5.3-flash-free, deepseek-v4.1-flash-free,
  nemotron-3.5-lightning-free), max 3 concurrent runs, 240s per run.
- Output per report: round2_extractions/<key>.json  with parsed fields + raw text.
"""
import concurrent.futures as cf
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = json.load(open(os.path.join(HERE, "round2_manifest.json"), encoding="utf-8"))
OC = os.path.join(os.environ["LOCALAPPDATA"], "Programs", "@opencodedesktop", "resources", "opencode-cli.exe")
MODELS = [
    "opencode/mimo-v2.6-flash-free",
    "opencode/longcat-2.5-preview-free",
    "opencode/space-bunny-free",
]
MODEL_TIMEOUT = 330

CLASS_PHRASE = {
    "idor": "Insecure Direct Object Reference (IDOR)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "sqli": "SQL injection",
    "open_redirect": "open redirect",
}

def prompt_for(key):
    cls = next(v["class"] for k, v in MANIFEST.items() if k == key)
    return (
        f"Read the file h1/round2/{key}.md in this directory. It is a disclosed HackerOne report about a "
        f"{CLASS_PHRASE[cls]} vulnerability. Do not create or modify any files. "
        "Output ONLY one JSON object with exactly these keys: title, endpoint, param, payload, evidence, signal, quality. "
        "The values for endpoint, param, payload, evidence and signal must be SHORT VERBATIM quotes copied "
        "character-for-character from the file (max 200 characters each); use null when the file does not state it. "
        "quality must be the string 'good' only if endpoint AND param AND payload are all present, otherwise 'thin'. "
        "No other text, no markdown fences."
    )

def parse_json_block(raw):
    raw = re.sub(r"```(?:json)?", "", raw)
    starts = [m.start() for m in re.finditer(r"\{", raw)]
    for s in reversed(starts):
        depth = 0
        for i in range(s, len(raw)):
            if raw[i] == "{":
                depth += 1
            elif raw[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(raw[s:i+1])
                    except json.JSONDecodeError:
                        break
    return None

def run_one(job):
    key, model = job
    outdir = os.path.join(HERE, "round2_extractions")
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, f"{key}.json")
    if os.path.exists(outfile):
        return key, "cached"
    try:
        proc = subprocess.run(
            [OC, "run", "-m", model, prompt_for(key)],
            cwd=HERE, capture_output=True, text=True, timeout=MODEL_TIMEOUT,
        )
        raw = (proc.stdout or "") + (proc.stderr or "")
        parsed = parse_json_block(raw)
        if parsed is None:
            return key, f"no-json (exit {proc.returncode})"
        rec = {
            "key": key, "model": model,
            "title": parsed.get("title"), "endpoint": parsed.get("endpoint"),
            "param": parsed.get("param"), "payload": parsed.get("payload"),
            "evidence": parsed.get("evidence"), "signal": parsed.get("signal"),
            "quality": parsed.get("quality"), "raw_tail": raw[-600:],
        }
        json.dump(rec, open(outfile, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        return key, f"ok ({parsed.get('quality')})"
    except subprocess.TimeoutExpired:
        return key, "timeout"
    except Exception as e:  # noqa: BLE001 - driver must survive per-job errors
        return key, f"error: {type(e).__name__}"

def main():
    manifest = json.load(open(os.path.join(HERE, "round2_manifest.json")))
    candidates = [k for k, v in manifest.items()
                  if v["confirmed_independent"] and not v["thin_prefilter"] and v["size"] > 0]
    jobs = [(k, MODELS[i % len(MODELS)]) for i, k in enumerate(sorted(candidates))]
    print(f"{len(jobs)} extraction jobs across {len(MODELS)} free models (3 concurrent)", flush=True)
    stats = {}
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        for key, status in ex.map(run_one, jobs):
            stats[key] = status
            print(f"  {key}: {status}", flush=True)
    ok = sum(1 for s in stats.values() if s.startswith("ok"))
    good = sum(1 for s in stats.values() if s == "ok (good)")
    print(f"\ndone: {ok}/{len(jobs)} extracted, {good} marked good")

if __name__ == "__main__":
    main()
