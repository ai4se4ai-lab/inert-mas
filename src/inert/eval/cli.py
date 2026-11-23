"""Command line: lint/compile models, generate attack suites, run manifest shards.

  inert lint models/examples/email_summary.inert.yaml
  inert gen-attacks --topology chain --size 5 --family email --out suite.yaml
  inert run-manifest --manifest hpc/manifests/smoke.yaml --backend mock --out results/smoke.jsonl
  inert run-manifest --manifest ... --backend ollama --host http://127.0.0.1:11434 --model qwen2.5:7b \
        --shard 0/4 --parallel 8 --out results/x.jsonl
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from ..agents.llm import LLM, Decoding, MockLLM, OllamaClient, OpenAIClient
from ..attacks.coverage import benchmark_suite, generate
from ..attacks.spec import AttackTest
from ..compiler.ir import IR, compile_model
from ..model import lint, load_yaml
from .harness import run_case
from .zoo import build_model, tasks


def git_commit() -> str:
    if os.environ.get("INERT_COMMIT"):
        return os.environ["INERT_COMMIT"]
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              cwd=Path(__file__).resolve().parents[3], timeout=10).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def model_digest(host: str, name: str) -> str:
    try:
        req = urllib.request.Request(host.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=20) as r:
            tags = json.loads(r.read())
        for m in tags.get("models", []):
            if m.get("name") == name or m.get("model") == name:
                return str(m.get("digest", ""))
    except Exception:
        pass
    return ""


# ----------------------------------------------------------------------------- manifests
_IR_CACHE: dict[tuple[str, int, str], IR] = {}
_LOCK = threading.Lock()


def zoo_ir(t: str, s: int, f: str) -> IR:
    with _LOCK:
        if (t, s, f) not in _IR_CACHE:
            _IR_CACHE[(t, s, f)] = compile_model(build_model(t, s, f))
        return _IR_CACHE[(t, s, f)]


def expand(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic list of cases (each with a stable id)."""
    cases: list[dict[str, Any]] = []
    for suite in manifest["suites"]:
        kind = suite.get("kind", "zoo")
        seeds = suite.get("seeds", [0])
        defenses = suite["defenses"]
        if kind == "zoo":
            for t in suite["topologies"]:
                for s in suite["sizes"]:
                    for f in suite["families"]:
                        if (t == "pcr") != (f == "code") and t == "pcr":
                            continue
                        if t == "pcr" and f != "code":
                            continue
                        ir = zoo_ir(t, s, f)
                        for task in tasks(f, suite.get("tasks", 5)):
                            primary = next(iter(task.resources))
                            atts: list[AttackTest | None] = []
                            mode = suite.get("attacks", "benign")
                            if mode in ("benign", "all"):
                                atts.append(None)
                            if mode in ("bench", "all", "bench+generated"):
                                atts += benchmark_suite(ir, f, primary)
                            if mode in ("generated", "all", "bench+generated"):
                                gen, _ = generate(ir, f, primary, seed=suite.get("gen_seed", 0),
                                                  criteria=tuple(suite["criteria"]) if suite.get("criteria") else None,
                                                  max_tests=suite.get("max_tests"))
                                atts += gen
                            for a in atts:
                                for d in defenses:
                                    for sd in seeds:
                                        cid = f"{suite.get('name', 'zoo')}|{ir.data['name']}|{task.id}|{d}|" \
                                              f"{a.id if a else 'benign'}|{sd}"
                                        cases.append({"id": cid, "suite": suite.get("name", "zoo"), "kind": "zoo",
                                                      "zoo": [t, s, f], "task": task.id, "defense": d,
                                                      "attack": a.to_dict() if a else None, "seed": sd})
        elif kind == "tamas":
            from adapters.tamas.adapter import tamas_cases
            cases += tamas_cases(suite)
        elif kind == "adaptive":
            for t in suite["topologies"]:
                for s in suite["sizes"]:
                    for f in suite["families"]:
                        if t == "pcr" and f != "code":
                            continue
                        ir = zoo_ir(t, s, f)
                        for task in tasks(f, suite.get("tasks", 5)):
                            for d in defenses:
                                for sd in seeds:
                                    cases.append({"id": f"{suite.get('name', 'adaptive')}|{ir.data['name']}|{task.id}|"
                                                        f"{d}|adaptive|{sd}", "suite": suite.get("name", "adaptive"),
                                                  "kind": "adaptive", "zoo": [t, s, f], "task": task.id,
                                                  "defense": d, "attack": None, "seed": sd,
                                                  "budget": suite.get("budget", 10)})
    return cases


def run_one(case: dict[str, Any], llm: LLM, attacker_llm: LLM | None = None) -> dict[str, Any]:
    if case["kind"] == "tamas":
        from adapters.tamas.adapter import run_tamas_case
        return run_tamas_case(case, llm)
    t, s, f = case["zoo"]
    ir = zoo_ir(t, s, f)
    task = next(x for x in tasks(f, 50) if x.id == case["task"])
    if case["kind"] == "adaptive":
        from ..attacks.adaptive import run_adaptive
        return run_adaptive(ir, task, case["defense"], llm, attacker_llm or llm, case["seed"], case.get("budget", 10))
    att = AttackTest.from_dict(case["attack"]) if case["attack"] else None
    return run_case(ir, task, case["defense"], att, llm, case["seed"])


def make_llm(a: argparse.Namespace) -> LLM:
    dec = Decoding(temperature=a.temperature, top_p=a.top_p, num_ctx=a.num_ctx, num_predict=a.num_predict)
    if a.backend == "mock":
        return MockLLM(susceptibility=a.mock_susceptibility)
    if a.backend == "ollama":
        return OllamaClient(a.host, a.model, dec)
    return OpenAIClient(a.host, a.model, dec)


def cmd_run_manifest(a: argparse.Namespace) -> int:
    manifest = yaml.safe_load(Path(a.manifest).read_text())
    cases = expand(manifest)
    i, n = (int(x) for x in a.shard.split("/"))
    cases = [c for k, c in enumerate(cases) if k % n == i]
    if a.limit:
        cases = cases[: a.limit]
    llm = make_llm(a)
    meta = {"git_commit": git_commit(), "backend": a.backend, "llm": a.model if a.backend != "mock" else "mock",
            "model_digest": model_digest(a.host, a.model) if a.backend == "ollama" else "",
            "decoding": {"temperature": a.temperature, "top_p": a.top_p, "num_ctx": a.num_ctx,
                         "num_predict": a.num_predict},
            "manifest": manifest.get("name"), "manifest_sha256": hashlib.sha256(Path(a.manifest).read_bytes()).hexdigest(),
            "shard": a.shard, "benchmark_versions": {"tamas": "545c112a"}}
    for kv in (a.meta or "").split(";"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            meta[k] = v
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    done: set[str] = set()
    if out.exists():
        for line in out.read_text().splitlines():
            try:
                r = json.loads(line)
                if not r.get("error"):
                    done.add(r["case_id"])
            except (json.JSONDecodeError, KeyError):
                pass
    todo = [c for c in cases if c["id"] not in done]
    print(f"manifest={manifest.get('name')} shard={a.shard} cases={len(cases)} todo={len(todo)}", flush=True)
    lock = threading.Lock()
    t0 = time.time()
    k = 0

    def work(c: dict[str, Any]) -> dict[str, Any]:
        try:
            r = run_one(c, llm)
        except Exception as e:  # recorded as a failed case, never silently dropped
            import traceback
            r = {"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-1500:]}
        r.update({"case_id": c["id"], "suite": c["suite"], "meta": meta, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                                               time.gmtime())})
        return r

    with out.open("a") as fh, cf.ThreadPoolExecutor(a.parallel) as ex:
        for r in ex.map(work, todo):
            with lock:
                fh.write(json.dumps(r, default=str) + "\n")
                fh.flush()
                k += 1
                if k % 25 == 0 or k == len(todo):
                    el = time.time() - t0
                    print(f"{k}/{len(todo)} {el:.0f}s {k / max(el, 1e-9):.2f} case/s", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="inert")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lint")
    p.add_argument("path")
    p = sub.add_parser("compile")
    p.add_argument("path")
    p = sub.add_parser("gen-attacks")
    p.add_argument("--topology", required=True)
    p.add_argument("--size", type=int, required=True)
    p.add_argument("--family", required=True)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", required=True)
    p = sub.add_parser("run-manifest")
    p.add_argument("--manifest", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--backend", choices=["mock", "ollama", "openai"], default="mock")
    p.add_argument("--host", default="http://127.0.0.1:11434")
    p.add_argument("--model", default="qwen2.5:7b")
    p.add_argument("--shard", default="0/1")
    p.add_argument("--parallel", type=int, default=4)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--top-p", type=float, default=1.0)
    p.add_argument("--num-ctx", type=int, default=8192)
    p.add_argument("--num-predict", type=int, default=768)
    p.add_argument("--mock-susceptibility", type=float, default=0.8)
    p.add_argument("--meta", default="")
    a = ap.parse_args(argv)
    if a.cmd == "lint":
        issues = lint(load_yaml(a.path))
        for i in issues:
            print(f"{i.code} {i.slot}: {i.message}")
        return 1 if issues else 0
    if a.cmd == "compile":
        sys.stdout.buffer.write(compile_model(load_yaml(a.path)).to_bytes() + b"\n")
        return 0
    if a.cmd == "gen-attacks":
        ir = compile_model(build_model(a.topology, a.size, a.family))
        primary = next(iter(tasks(a.family, 1)[0].resources))
        tests, obs = generate(ir, a.family, primary, seed=a.seed)
        Path(a.out).write_text(yaml.safe_dump({"model": ir.data["name"], "plan_hash": ir.plan_hash,
                                               "obligations": [o.__dict__ for o in obs],
                                               "tests": [t.to_dict() for t in tests]}, sort_keys=False))
        print(f"{len(tests)} tests, {sum(o.feasible for o in obs)}/{len(obs)} feasible obligations")
        return 0
    if a.cmd == "run-manifest":
        return cmd_run_manifest(a)
    return 2


if __name__ == "__main__":
    sys.exit(main())
