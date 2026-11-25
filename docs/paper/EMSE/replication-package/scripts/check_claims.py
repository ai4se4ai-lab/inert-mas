#!/usr/bin/env python3
"""Independent recount of the headline claims of the manuscript from the raw result records.

This script deliberately does NOT import analysis/make_assets.py: it re-implements the few
definitions it needs (de-duplication, suites, ASR, utility) with the Python standard library, so a
reviewer can check the published numbers against a second, short implementation.

    python docs/paper/EMSE/replication-package/scripts/check_claims.py [results-dir]

Sections:
  1. provenance   every record names a manifest whose SHA-256 matches hpc/manifests/, a model digest,
                  a decoding configuration and a code version with an archived snapshot
  2. results      run counts, Table 8 (main), RQ3 distinct obligations, RQ5 adaptive, TAMAS IPI
  3. example      the running example of Sections 2.7 and 5 (needs the `inert` package installed)

Exit code 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]

# Values as printed in the manuscript (docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex).
# Percentages are rounded to one decimal, as in the paper.
EXPECTED = {
    "runs": 106_382,
    "failed": 0,
    "llms": 6,
    "zoo_attacked_runs": 60_690,
    "main": {  # defense: (n_att, ASR %, U_ben %)        Table "Overall results on the topology zoo"
        "B0": (8670, 82.4, 71.4), "B1": (8670, 63.9, 71.1), "B2": (8670, 77.5, 68.5),
        "B3": (8670, 0.0, 44.0), "B4": (8670, 58.8, 61.1), "I1": (8670, 16.6, 91.9),
        "I2": (8670, 0.0, 82.2),
    },
    "rq3_distinct": {"B0:generated": 761, "B0:bench": 153},   # Table "RQ3"
    "rq5_asr": {"B1": 88.9, "B4": 75.0, "B3": 0.0, "I2": 0.0},  # adaptive attacker, 10 attempts
    "tamas_ipi": {"B0": 51.7, "B4": 15.0, "B3": 2.3, "I2": 8.0},  # TAMAS indirect injection, goal met %
    "goal": {"B0": 56.3, "B1": 11.8, "B2": 47.6, "B3": 0.0, "B4": 46.2, "I1": 7.1, "I2": 0.0},  # Table 8, Goal
    # Sec. 7: benign runs with an off-model handoff to the executor agent (the baseline P1 clause)
    "p1_benign": {"B0": 52.5, "B1": 51.6, "B2": 50.5, "B4": 26.1},
    "runs_by_suite": {"zoo-benign": 8568, "zoo-attack": 60690, "zoo-ablation": 11900, "seeds": 3780,
                      "adaptive": 144, "tamas": 16800, "tamas-split2": 2100, "tamas-scope": 2400},  # Table 7
    "i2key_a5": {"replay": 70.5, "tool_meta": 100.0},  # Sec. 7.2
    "i2_util_code": 54.2, "i1_util_code": 88.1,  # Sec. 7.4
    "tamas_i2_overlap": {"IPI": (23, 24), "DPI-split": (17, 21)},  # Sec. 7.7: successes also seen on benign run
    "residual": {"whole": 369, "split": 257},  # Sec. 8: I2 successes per TAMAS configuration
    "i2_util_by_llm": {"llama3.1:8b": 52.2, "qwen2.5:72b": 100.0},  # Sec. 7.5, Table 10: extremes
    "i2_code_zero": ["llama3.1:8b", "llama3.3:70b"],  # Sec. 7.5: no code task completed under I2
}
GENERATED = ("EDGE", "SLOT", "SEL", "TAINT", "RECONF", "COLL")

failures: list[str] = []


def check(name: str, got: object, want: object) -> None:
    ok = got == want
    print(f"  [{'ok' if ok else 'FAIL'}] {name}: {got}" + ("" if ok else f" (paper: {want})"))
    if not ok:
        failures.append(name)


def pct(xs: list[bool | int]) -> float:
    return round(100 * sum(xs) / len(xs), 1) if xs else float("nan")


def load(results: Path) -> tuple[list[dict], int]:
    """De-duplicate by (case_id, llm), as resumed shards may repeat rows; a successful row wins."""
    best: dict[tuple[str, str], dict] = {}
    raw = 0
    for p in sorted(results.rglob("shard_*.jsonl")):
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            raw += 1
            r = json.loads(line)
            k = (r.get("case_id", ""), (r.get("meta") or {}).get("llm", r.get("llm", "")))
            if k not in best or (best[k].get("error") and not r.get("error")):
                best[k] = r
    return list(best.values()), raw


def provenance(rows: list[dict]) -> None:
    print("1. Provenance")
    manifests = {}
    for m in (ROOT / "hpc" / "manifests").glob("final_*.yaml"):
        manifests[hashlib.sha256(m.read_bytes()).hexdigest()] = m.name
    seen_manifests: Counter[str] = Counter()
    missing_fields = 0
    codes: Counter[str] = Counter()
    digests: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        meta = r.get("meta") or {}
        if not all(meta.get(k) for k in ("git_commit", "model_digest", "decoding", "manifest_sha256")) \
                or "seed" not in r:
            missing_fields += 1
        seen_manifests[manifests.get(meta.get("manifest_sha256", ""), "UNKNOWN")] += 1
        codes[str(meta.get("git_commit", "")).rsplit("code.", 1)[-1]] += 1
        digests[meta.get("llm", "")].add(meta.get("model_digest", ""))
    check("records missing commit, model digest, decoding, manifest hash or seed", missing_fields, 0)
    check("records whose manifest hash matches no committed manifest", seen_manifests.get("UNKNOWN", 0), 0)
    for name, n in sorted(seen_manifests.items()):
        print(f"       {n:>7} records from {name}")
    check("LLMs with exactly one model digest", sum(len(v) == 1 for v in digests.values()), len(digests))
    snapdir = ROOT / "hpc" / "fetched" / "code"
    if snapdir.exists():
        missing = sorted(c for c in codes if not (snapdir / f"code-{c}.tar.gz").exists())
        check("code versions without an archived code snapshot", missing, [])
    else:
        print("  [skip] hpc/fetched/code not present (it is in the archive, not in git)")
    for c, n in codes.most_common():
        print(f"       {n:>7} records from code snapshot {c}")


def results(rows: list[dict], raw: int) -> None:
    print("2. Results")
    ok_rows = [r for r in rows if not r.get("error")]
    print(f"       {raw} raw lines, {len(rows)} after de-duplication by (case, model)")
    check("runs", len(ok_rows), EXPECTED["runs"])
    check("failed runs", len(rows) - len(ok_rows), EXPECTED["failed"])
    check("LLMs", len({r.get("llm") for r in ok_rows}), EXPECTED["llms"])

    zoo = [r for r in ok_rows if r.get("family") != "tamas" and r.get("suite") in ("zoo-benign", "zoo-attack")]
    att = [r for r in zoo if r.get("criterion") not in ("BENIGN", "ADAPTIVE")]
    check("attacked runs on the topology zoo (B0-B4, I1, I2)",
          sum(1 for r in att if not r["defense"].startswith("I2-")), EXPECTED["zoo_attacked_runs"])
    for d, (n_att, asr, uben) in EXPECTED["main"].items():
        a = [r["asr"] for r in att if r["defense"] == d]
        u = [r["utility"] for r in zoo if r["defense"] == d and r.get("criterion") == "BENIGN"]
        check(f"Table main {d}: n_att, ASR %, U_ben %", (len(a), pct(a), pct(u)), (n_att, asr, uben))

    for key, want in EXPECTED["rq3_distinct"].items():
        d, suite = key.split(":")
        crit = GENERATED if suite == "generated" else ("BENCH",)
        xs = [r for r in zoo if r["defense"] == d and r.get("criterion") in crit]
        check(f"RQ3 distinct violated obligations {key}",
              len({(r["model_name"], r.get("obligation")) for r in xs if r["asr"]}), want)

    adaptive = [r for r in ok_rows if r.get("family") != "tamas" and r.get("criterion") == "ADAPTIVE"]
    for d, want in EXPECTED["rq5_asr"].items():
        check(f"RQ5 adaptive attacker ASR % {d}", pct([r["asr"] for r in adaptive if r["defense"] == d]), want)

    tam = [r for r in ok_rows if r.get("family") == "tamas"]
    for d, want in EXPECTED["tamas_ipi"].items():
        xs = [r["goal_met"] for r in tam if r["defense"] == d and r.get("tamas_attack") == "IPI"]
        check(f"TAMAS IPI goal met % {d}", pct(xs), want)

    for d, want in EXPECTED["goal"].items():
        check(f"Table main {d}: Goal %", pct([r["goal_met"] for r in att if r["defense"] == d]), want)
    for d, want in EXPECTED["p1_benign"].items():
        ben = [r for r in zoo if r["defense"] == d and r.get("criterion") == "BENIGN"]
        # in every zoo workflow the executor agent `actor` owns the attacker's target tool
        check(f"benign runs with an off-model handoff to the executor, {d} %",
              pct(["actor" in (r.get("off_model_targets") or []) for r in ben]), want)
    for suite, want in EXPECTED["runs_by_suite"].items():
        check(f"runs in sub-study {suite}", sum(1 for r in ok_rows if r.get("suite") == suite), want)
    abl = [r for r in ok_rows if r.get("suite") == "zoo-ablation" and r["defense"] == "I2-key"
           and r.get("attacker") == "A5"]
    for kind, want in EXPECTED["i2key_a5"].items():
        check(f"I2-key A5 success %, {kind} tests",
              pct([r["asr"] for r in abl if str(r.get("obligation", "")).split(":")[1] == kind]), want)
    for d, want in (("I2", EXPECTED["i2_util_code"]), ("I1", EXPECTED["i1_util_code"])):
        check(f"benign utility on the code family {d} %",
              pct([r["utility"] for r in zoo if r["defense"] == d and r["family"] == "code"
                   and r.get("criterion") == "BENIGN"]), want)
    ben_calls = {(r["defense"], r["domain"], r["index"], r["llm"]): {c["tool"] for c in r["tool_calls"]}
                 for r in tam if r.get("tamas_attack") == "Benign"}

    def also(r: dict) -> bool:
        return all(t in ben_calls.get((r["defense"], r["domain"], r["index"], r["llm"]), set())
                   for t in r.get("targets") or [])
    for col, want in EXPECTED["tamas_i2_overlap"].items():
        att_, var = ("IPI", None) if col == "IPI" else ("DPI", "split")
        # DPI-split counts only the re-run (suite tamas-split2), as in the analysis
        succ = [r for r in tam if r["defense"] == "I2" and r.get("tamas_attack") == att_ and r["goal_met"]
                and (var is None or (r.get("variant") == var and r.get("suite") == "tamas-split2"))]
        check(f"TAMAS {col} I2 successes whose target the benign run also calls", (sum(map(also, succ)), len(succ)),
              want)
    llms = sorted({r.get("llm") for r in zoo})
    check("I2 attack success % on every model", sorted({pct([r["asr"] for r in att if r["defense"] == "I2"
                                                             and r.get("llm") == m_]) for m_ in llms}), [0.0])
    for m_, want in EXPECTED["i2_util_by_llm"].items():
        check(f"I2 benign utility % on {m_}", pct([r["utility"] for r in zoo if r["defense"] == "I2"
                                                  and r.get("llm") == m_ and r.get("criterion") == "BENIGN"]), want)
    check("models completing no code task under I2", sorted(
        m_ for m_ in llms if not any(r["utility"] for r in zoo if r["defense"] == "I2" and r.get("llm") == m_
                                     and r["family"] == "code" and r.get("criterion") == "BENIGN")),
        EXPECTED["i2_code_zero"])
    fixed = {r.get("llm") for r in tam if r.get("suite") == "tamas-split2"}
    used = [r for r in tam if not (r.get("suite") == "tamas" and r.get("variant") == "split" and r.get("llm") in fixed)]
    for cfg, want in EXPECTED["residual"].items():
        n = sum(1 for r in used if r["defense"] == "I2" and r.get("asr")
                and not (r.get("tamas_attack") == "DPI" and r.get("variant") != cfg))
        check(f"successful attacks against I2 on TAMAS, DPI labelled {cfg}", n, want)


def example() -> None:
    print("3. Running example (chain3_email)")
    try:
        sys.path.insert(0, str(ROOT / "src"))
        sys.path.insert(0, str(ROOT))
        from inert.agents.llm import MockLLM
        from inert.attacks.coverage import benchmark_suite, obligations
        from inert.audit.log import verify_chain
        from inert.compiler import compile_model
        from inert.eval.harness import run_case
        from inert.eval.zoo import tasks
        from inert.model import load_yaml
        from inert.model.lint import lint, static_labels
    except ImportError as e:
        print(f"  [skip] inert package not importable ({e}); install with pip install -e '.[dev,analysis]'")
        return
    m = load_yaml(ROOT / "models" / "zoo" / "chain3_email.inert.yaml")
    ir = compile_model(m)
    check("compilation is byte-identical", ir.to_bytes() == compile_model(m).to_bytes(), True)
    lab = {k: v.value for k, v in static_labels(m).items()}
    check("static labels task/intent/fetch/a1/act",
          [lab[s] for s in ("task", "intent", "fetch", "a1", "act")],
          ["user", "agent_untrusted", "external_untrusted", "external_untrusted", "external_untrusted"])
    check("L3 issues (slot)", sorted((i.code, i.slot) for i in lint(m)), [("L3", "act"), ("L3", "do")])
    obs = obligations(ir, "email", "email/0")
    feas = Counter(o.criterion for o in obs if o.feasible)
    check("obligations total / feasible", (len(obs), sum(feas.values())), (46, 38))
    check("feasible per criterion", dict(sorted(feas.items())),
          {"COLL": 1, "EDGE": 7, "RECONF": 7, "SEL": 4, "SLOT": 16, "TAINT": 3})
    bench = benchmark_suite(ir, "email", "email/0")
    r = run_case(ir, tasks("email")[0], "I2", bench[0], MockLLM(susceptibility=1.0), 0, keep_log=True)
    events = r["log"]
    check("logged events of an attacked I2 run", len(events), 26)
    check("hash chain verifies", verify_chain(events)[0], True)
    events[5] = {**events[5], "slot": str(events[5].get("slot")) + "x"}
    check("one altered event breaks the chain at that event", verify_chain(events), (False, 5))
    check("attack goal met under I2 (mock LLM, fully susceptible)", r["goal_met"], False)


def main() -> int:
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "final"
    if results_dir.exists():
        rows, raw = load(results_dir)
        provenance(rows)
        results(rows, raw)
    else:
        print(f"  [skip] {results_dir} not found: sections 1 and 2 need the archived result records")
    example()
    print(f"\n{len(failures)} failed check(s)" + (": " + "; ".join(failures) if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
