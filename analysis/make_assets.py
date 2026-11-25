"""Regenerate every table and figure of the paper from result JSONL files.

  python analysis/make_assets.py results/final/*.jsonl --out paper/

Reads only results (append-only) and writes only to the output directory (paper/ by
default): LaTeX tables (*.tex), figures (*.pdf) and a machine-readable numbers.json that the
manuscript macros are generated from. Statistics (pre-registered, analysis/preregistration.md):
  * paired McNemar tests per defense vs B0 and vs B4 on attack success, with the conditional odds
    ratio and a 95% bootstrap CI (10,000 resamples of discordant pairs);
  * Wilcoxon signed-rank with Cliff's delta for latency and tokens (paired by case);
  * logistic mixed-effects model (defense + LLM fixed, task random intercept), Bayesian
    variational fit from statsmodels;
  * Holm correction within each research question.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

ORDER = ["B0", "B1", "B2", "B3", "B4", "I1", "I2", "I2S", "I2-tokens", "I2-key", "I2-validator", "I2-tsel", "I2-tacc"]
NAMES = {"B0": "B0 native", "B1": "B1 detector", "B2": "B2 tagging", "B3": "B3 plan+quarantine",
         "B4": "B4 permitted graph", "I1": "I1 INERT structural", "I2": "I2 INERT full", "I2S": "I2S + task scope (post hoc)",
         "I2-tokens": "I2 $-$ tokens", "I2-key": "I2 $-$ key match", "I2-validator": "I2 $-$ validators",
         "I2-tsel": "I2 $-$ taint at selection", "I2-tacc": "I2 $-$ taint at acceptance"}


def load(paths: list[str]) -> list[dict[str, Any]]:
    """Load result records, de-duplicated by (case, model): a resumed shard may contain rows that
    also exist in an earlier copy of the same shard. A successful row wins over a failed one."""
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for p in paths:
        for line in Path(p).read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            k = (r.get("case_id", ""), (r.get("meta") or {}).get("llm", r.get("llm", "")))
            if k not in best or (best[k].get("error") and not r.get("error")):
                best[k] = r
    return list(best.values())


def mean(xs: list[float]) -> float:
    return float(sum(xs) / len(xs)) if xs else float("nan")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def mcnemar(pairs: list[tuple[bool, bool]], rng: random.Random, B: int = 10_000) -> dict[str, float]:
    """pairs = (defense success, reference success). Exact binomial McNemar; OR = b/c."""
    from scipy.stats import binomtest
    b = sum(1 for x, y in pairs if x and not y)
    c = sum(1 for x, y in pairs if y and not x)
    n = b + c
    p = binomtest(b, n, 0.5).pvalue if n else 1.0
    orr = (b + 0.5) / (c + 0.5)
    boots = []
    disc = [1] * b + [0] * c
    for _ in range(B if n else 0):
        s = [disc[rng.randrange(n)] for _ in range(n)]
        bb = sum(s)
        boots.append((bb + 0.5) / (n - bb + 0.5))
    lo, hi = (float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))) if boots else (orr, orr)
    return {"b": b, "c": c, "n_pairs": len(pairs), "p": float(p), "or": orr, "or_lo": lo, "or_hi": hi}


def cliffs_delta(x: list[float], y: list[float]) -> float:
    gt = sum(1 for a in x for b in y if a > b)
    lt = sum(1 for a in x for b in y if a < b)
    return (gt - lt) / (len(x) * len(y)) if x and y else float("nan")


def holm(ps: dict[str, float]) -> dict[str, float]:
    items = sorted(ps.items(), key=lambda kv: kv[1])
    m = len(items)
    out, running = {}, 0.0
    for i, (k, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        out[k] = running
    return out


def pair_key(r: dict[str, Any]) -> tuple[Any, ...]:
    return (r.get("llm"), r.get("model_name"), r.get("task"), r.get("attack") or r.get("obligation"), r.get("seed"),
            r.get("variant"))


def fmt(x: float, d: int = 2) -> str:
    return "--" if x != x else f"{x:.{d}f}"


def pfmt(p: float) -> str:
    if p == 0:
        return r"$<10^{-300}$"
    if p < 1e-3:
        m, e = f"{p:.1e}".split("e")
        return f"${m}\\cdot 10^{{{int(e)}}}$"
    return f"{p:.3f}"


def pct(x: float) -> str:
    return "--" if x != x else f"{100 * x:.1f}"


SUBSTUDIES = [  # (suite, label in the run-accounting table)
    ("zoo-benign", "Topology zoo, benign tasks"), ("zoo-attack", "Topology zoo, attacked (Table~\\ref{tab:main})"),
    ("zoo-ablation", "Ablation suite (RQ2)"), ("seeds", "Seed sub-study (temperature 0.7)"),
    ("adaptive", "Adaptive attacker (RQ5)"), ("tamas", "TAMAS"), ("tamas-split2", "TAMAS DPI-split re-run"),
    ("tamas-scope", "TAMAS task scope (I2S)")]


def review_numbers(rows: list[dict[str, Any]], zoo: list[dict[str, Any]], ablation: list[dict[str, Any]],
                   tam: list[dict[str, Any]], numbers: dict[str, Any], out: Path) -> None:
    """Counts that make the accounting and the metric definitions of the paper checkable."""
    # ---- run accounting per sub-study (Section 6.3)
    acc: dict[str, dict[str, Any]] = {}
    for suite, _ in SUBSTUDIES:
        xs = [r for r in rows if r.get("suite") == suite]
        acc[suite] = {"runs": len(xs), "llms": len({r.get("llm") for r in xs}),
                      "defenses": len({r["defense"] for r in xs}),
                      "workflows": len({r["model_name"] if r.get("family") != "tamas" else (r.get("domain"), r.get("index"))
                                        for r in xs})}
    fixed = set(numbers.get("tamas_split_fixed_llms", []))
    acc["tamas"]["superseded"] = sum(1 for r in rows if r.get("suite") == "tamas" and r.get("variant") == "split"
                                     and r.get("llm") in fixed)
    numbers["accounting"] = acc
    def thousands(x: int) -> str:
        return f"{x:,}".replace(",", "{,}")
    lines = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Sub-study & LLMs & Conditions & Workflows or instances & Runs \\", r"\midrule"]
    for suite, label in SUBSTUDIES:
        a = acc[suite]
        lines.append(f"{label} & {a['llms']} & {a['defenses']} & {a['workflows']} & {thousands(a['runs'])} \\\\")
    lines += [r"\midrule", f"Total & & & & {thousands(sum(a['runs'] for a in acc.values()))} \\\\",
              r"\botrule", r"\end{tabular}"]
    (out / "tab_runs.tex").write_text("\n".join(lines) + "\n")
    att = [r for r in zoo if r.get("criterion") not in ("BENIGN", "ADAPTIVE")]
    numbers["zoo_composition"] = {
        "bench": sum(1 for r in att if r["defense"] == "B0" and r.get("criterion") == "BENCH"),
        "generated": sum(1 for r in att if r["defense"] == "B0" and r.get("criterion") != "BENCH"),
        "workflows": len({r["model_name"] for r in zoo}),
        "declassifier_workflows": len({r["model_name"] for r in zoo if r.get("family") in ("reply", "code")})}
    # ---- baselines: P1 counts an off-model handoff that reaches the owner of the attacker's target tool.
    # The same handoff happens without any attack; its benign rate is the base rate of that clause.
    from inert.attacks.payloads import GOALS
    from inert.compiler.export import agent_graph
    from inert.eval.cli import zoo_ir
    owners: dict[str, set[str]] = {}
    for r in zoo:
        if r["model_name"] not in owners:
            t, rest = r["model_name"].split("_")[0], r["family"]
            topo = "".join(ch for ch in t if not ch.isdigit())
            g = agent_graph(zoo_ir(topo, int("".join(ch for ch in t if ch.isdigit())), rest))
            owners[r["model_name"]] = {a for a, ts in g["tools"].items() if GOALS[rest].tool in ts}
    base = {}
    for d in ("B0", "B1", "B2", "B4"):
        ben = [r for r in zoo if r["defense"] == d and r.get("criterion") == "BENIGN"]
        ax = [r for r in att if r["defense"] == d]
        base[d] = {"benign_offmodel": mean([bool(owners[r["model_name"]] & set(r.get("off_model_targets") or []))
                                            for r in ben]),
                   "attack_p1_only": mean([bool(r.get("violations")) and not r.get("goal_met") for r in ax])}
    numbers["p1_base_rate"] = base
    # ---- benign utility by task family (RQ4)
    fam: dict[str, dict[str, float]] = defaultdict(dict)
    for d in ORDER:
        for fa in ("email", "reply", "web", "code"):
            xs = [r["utility"] for r in zoo if r["defense"] == d and r["family"] == fa and r.get("criterion") == "BENIGN"]
            if xs:
                fam[d][fa] = mean(xs)
    numbers["util_by_family"] = dict(fam)
    lf: dict[str, dict[str, dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
    for llm in sorted({r.get("llm") for r in zoo}):
        for d in ("I1", "I2"):
            for fa in ("email", "reply", "web", "code"):
                xs = [r["utility"] for r in zoo if r["defense"] == d and r.get("llm") == llm and r["family"] == fa
                      and r.get("criterion") == "BENIGN"]
                lf[llm][d][fa] = mean(xs)
    numbers["util_by_llm_family"] = {k: dict(v) for k, v in lf.items()}
    fams = ("email", "reply", "web", "code")
    lines = [r"\begin{tabular}{@{}lrrrrr@{}}", r"\toprule",
             r"Def. & email & reply & web & code & all \\", r"\midrule"]
    for d in ORDER:
        if d in fam and not d.startswith("I2-"):
            allv = mean([r["utility"] for r in zoo if r["defense"] == d and r.get("criterion") == "BENIGN"])
            lines.append(f"{d} & " + " & ".join(pct(fam[d][x]) for x in fams) + f" & {pct(allv)} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_family.tex").write_text("\n".join(lines) + "\n")
    dec = [ok for r in zoo if r["defense"] == "I2" and r.get("criterion") == "BENIGN" and r["family"] == "reply"
           for _, ok in r.get("declassified", [])]
    numbers["reply_declass_ok"] = mean(dec) if dec else float("nan")
    # ---- RQ2: what a success is (goal met vs audited violation only) and A5 by reconfiguration type
    kind: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: {"goal": 0, "audit": 0, "n": 0}))
    a5: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
    for r in ablation:
        if r.get("criterion") in ("BENIGN", "ADAPTIVE"):
            continue
        k = kind[r["defense"]][r.get("attacker")]
        k["n"] += 1
        if r["asr"]:
            k["goal" if r.get("goal_met") else "audit"] += 1
        if r.get("attacker") == "A5":
            a5[r["defense"]][str(r.get("obligation", "")).split(":")[1]].append(r["asr"])
    numbers["rq2_success_kind"] = {d: dict(v) for d, v in kind.items()}
    numbers["rq2_a5"] = {d: {k: {"asr": mean(v), "n": len(v)} for k, v in x.items()} for d, x in a5.items()}
    reasons: dict[str, Counter[str]] = defaultdict(Counter)
    for r in ablation:
        if r["defense"] == "I2" and r.get("attacker") in ("A2", "A4"):
            reasons[r["attacker"]].update(r.get("reasons") or {})
    numbers["rq2_i2_reasons"] = {k: dict(v) for k, v in reasons.items()}
    # ---- TAMAS: successes whose target tool is also called on the benign run of the same instance
    ben = {(r["defense"], r["domain"], r["index"], r["llm"]): {c["tool"] for c in r["tool_calls"]}
           for r in tam if r.get("tamas_attack") == "Benign"}
    orc: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for d in sorted({r["defense"] for r in tam}):
        for col, att_, var in (("IPI", "IPI", None), ("DPI-split", "DPI", "split"), ("DPI-whole", "DPI", "whole")):
            xs = [r for r in tam if r["defense"] == d and r.get("tamas_attack") == att_
                  and (var is None or r.get("variant") == var)]
            if not xs:
                continue

            def also(r: dict[str, Any]) -> bool:
                return all(t in ben.get((r["defense"], r["domain"], r["index"], r["llm"]), set())
                           for t in r.get("targets") or [])
            orc[d][col] = {"n": len(xs), "succ": sum(bool(r["goal_met"]) for r in xs),
                           "succ_also_benign": sum(bool(r["goal_met"]) and also(r) for r in xs),
                           "base": sum(also(r) for r in xs)}
    numbers["tamas_oracle"] = dict(orc)
    numbers["tamas_n_per_cell"] = sum(1 for r in tam if r["defense"] == "B0" and r.get("tamas_attack") == "IPI")
    # ---- residual successes against I2 per TAMAS configuration (the two DPI labelings are alternatives)
    from residual import category
    cfg: dict[str, Counter[str]] = {"whole": Counter(), "split": Counter()}
    for r in tam:
        if r["defense"] != "I2" or not r.get("asr"):
            continue
        for c in ("whole", "split"):
            if r.get("tamas_attack") == "DPI" and r.get("variant") != c:
                continue
            cat = category(r)
            if cat == "plausible" and all(t in ben.get((r["defense"], r["domain"], r["index"], r["llm"]), set())
                                          for t in r.get("targets") or []):
                cat = "benign-overlap"
            cfg[c][cat] += 1
    numbers["residual_by_config"] = {k: dict(v) for k, v in cfg.items()}
    numbers["zoo_success_i2"] = sum(1 for r in rows if r.get("family") != "tamas" and r["defense"] == "I2"
                                    and r.get("asr"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", default="paper")
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = [r for r in load(a.files) if not r.get("error")]
    errors = [r for r in load(a.files) if r.get("error")]
    rng = random.Random(a.seed)
    numbers: dict[str, Any] = {"rows": len(rows), "errors": len(errors)}
    allzoo = [r for r in rows if r.get("family") != "tamas"]
    zoo = [r for r in allzoo if r.get("suite") in ("zoo-benign", "zoo-attack")]
    ablation = [r for r in allzoo if r.get("suite") == "zoo-ablation"]
    seeds_rows = [r for r in allzoo if r.get("suite") == "seeds"]
    adaptive = [r for r in allzoo if r.get("criterion") == "ADAPTIVE"]
    tam = [r for r in rows if r.get("family") == "tamas"]
    # DPI-split: only the re-run after the provenance-split fix counts (docs/open-questions.md item 12)
    fixed = {(r.get("llm")) for r in tam if r.get("suite") == "tamas-split2"}
    tam = [r for r in tam if not (r.get("suite") == "tamas" and r.get("variant") == "split")
           or r.get("llm") not in fixed]
    numbers["tamas_split_fixed_llms"] = sorted(x for x in fixed if x)
    numbers["llms"] = sorted({r.get("llm") for r in rows})

    # ---------------------------------------------------------------- main table (zoo)
    by = defaultdict(lambda: defaultdict(list))
    for r in zoo:
        d = r["defense"]
        if r.get("criterion") == "BENIGN":
            by[d]["u_ben"].append(r["utility"])
            if "honest_proposals" in r:
                by[d]["fr_k"].append(r["honest_rejected"])
                by[d]["fr_n"].append(r["honest_proposals"])
            elif r.get("messages_checked"):
                by[d]["fr_k"].append(r["flagged_benign"])
                by[d]["fr_n"].append(r["messages_checked"])
            elif d in ("B3", "B4"):
                # blocked actions over attempted actions (executed tool calls + blocked ones)
                by[d]["fr_k"].append(r.get("blocked", 0))
                by[d]["fr_n"].append(len(r.get("tool_calls", [])) + r.get("blocked", 0))
            by[d]["sec"].append(r["seconds"])
            by[d]["tok"].append(r.get("prompt_tokens", 0) + r.get("completion_tokens", 0))
            by[d]["calls"].append(r.get("llm_calls", 0))
        elif r.get("criterion") not in ("ADAPTIVE",):
            by[d]["asr"].append(r["asr"])
            by[d]["goal"].append(r["goal_met"])
            by[d]["u_att"].append(r["utility"])
            by[d]["inf"].append(r.get("infected_agents", 0))
            by[d]["blast"].append(r.get("blast_radius", 0))
    lines = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
             r"Def. & $n_{att}$ & ASR & 95\% CI & Goal & $U_{ben}$ & $U_{att}$ & FRR & Calls \\",
             r"\midrule"]
    main = {}
    for d in ORDER:
        if d not in by or d.startswith("I2-"):
            continue
        x = by[d]
        k, n = sum(x["asr"]), len(x["asr"])
        lo, hi = wilson(k, n)
        frr = sum(x["fr_k"]) / max(1, sum(x["fr_n"])) if x["fr_n"] else float("nan")
        main[d] = {"asr": mean(x["asr"]), "asr_lo": lo, "asr_hi": hi, "goal": mean(x["goal"]),
                   "u_ben": mean(x["u_ben"]), "u_att": mean(x["u_att"]), "frr": frr, "calls": mean(x["calls"]),
                   "sec": mean(x["sec"]), "tok": mean(x["tok"]), "n_att": n, "n_ben": len(x["u_ben"]),
                   "inf": mean(x["inf"]), "blast": mean(x["blast"])}
        lines.append(f"{d} & {n} & {pct(main[d]['asr'])} & [{pct(lo)}, {pct(hi)}] & {pct(main[d]['goal'])} & "
                     f"{pct(main[d]['u_ben'])} & {pct(main[d]['u_att'])} & {pct(frr)} & {fmt(main[d]['calls'], 1)} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_main.tex").write_text("\n".join(lines) + "\n")
    numbers["main"] = main

    # ---------------------------------------------------------------- RQ1 propagation by topology (B0)
    topo = defaultdict(lambda: defaultdict(list))
    tamper: dict[str, list[bool]] = defaultdict(list)  # H1, second clause: transport tampering by topology
    for r in zoo:
        if r["defense"] == "B0" and r.get("criterion") not in ("BENIGN", "ADAPTIVE"):
            name = r["model_name"]
            t = "".join(ch for ch in name.split("_")[0] if not ch.isdigit())
            size = int("".join(ch for ch in name.split("_")[0] if ch.isdigit()))
            topo[(t, size)]["asr"].append(r["asr"])
            topo[(t, size)]["inf"].append(r.get("infected_agents", 0))
            topo[(t, size)]["blast"].append(r.get("blast_radius", 0))
            topo[(t, size)]["depth"].append(r.get("depth", 0))
            if r.get("attacker") == "A3":
                tamper[t].append(r["asr"])
    lines = [r"\begin{tabular}{@{}llrrrrr@{}}", r"\toprule",
             r"Topology & Agents & $n$ & ASR (\%) & Infected agents & Blast radius & Depth \\", r"\midrule"]
    rq1 = {}
    for (t, s) in sorted(topo):
        x = topo[(t, s)]
        rq1[f"{t}{s}"] = {"asr": mean(x["asr"]), "inf": mean(x["inf"]), "blast": mean(x["blast"]),
                          "depth": mean(x["depth"]), "n": len(x["asr"])}
        lines.append(f"{t} & {s} & {len(x['asr'])} & {pct(mean(x['asr']))} & {fmt(mean(x['inf']))} & "
                     f"{fmt(mean(x['blast']))} & {fmt(mean(x['depth']))} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_rq1.tex").write_text("\n".join(lines) + "\n")
    numbers["rq1"] = rq1
    numbers["rq1_tamper"] = {t: {"asr": mean(v), "n": len(v)} for t, v in tamper.items()}
    abl_n = [r for r in allzoo if r.get("suite") == "zoo-ablation"]
    numbers["ablation_design"] = {"runs": len(abl_n), "workflows": len({r["model_name"] for r in abl_n}),
                                  "llms": len({r.get("llm") for r in abl_n})}

    # ---------------------------------------------------------------- RQ2 ablation x attacker class
    abl = defaultdict(lambda: defaultdict(list))
    first = defaultdict(lambda: defaultdict(int))
    for r in ablation:
        if r["defense"].startswith("I") and r.get("criterion") not in ("BENIGN", "ADAPTIVE"):
            abl[r["defense"]][r.get("attacker")].append(r["asr"])
            if r.get("first_reject"):
                first[r.get("attacker")][r["first_reject"]] += 1
    atts = sorted({k for d in abl.values() for k in d})
    lines = [r"\begin{tabular}{@{}l" + "r" * len(atts) + r"@{}}", r"\toprule",
             "Condition & " + " & ".join(f"{x} (\\%)" for x in atts) + r" \\", r"\midrule"]
    rq2 = {}
    for d in ORDER:
        if d in abl:
            rq2[d] = {k: mean(abl[d][k]) for k in atts}
            lines.append(f"{NAMES[d]} & " + " & ".join(pct(mean(abl[d][k])) for k in atts) + r" \\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_rq2.tex").write_text("\n".join(lines) + "\n")
    numbers["rq2"] = rq2
    au = defaultdict(list)
    for r in ablation:
        if r.get("criterion") not in ("BENIGN", "ADAPTIVE"):
            au[r["defense"]].append(r["utility"])
    numbers["rq2_util_attack"] = {d: mean(v) for d, v in au.items()}
    numbers["first_reject"] = {k: dict(v) for k, v in first.items()}
    i1a2: dict[str, int] = defaultdict(int)  # which obligations a compromised agent wins under I1 (H2)
    for r in ablation:
        if r["defense"] == "I1" and r.get("attacker") == "A2" and r["asr"]:
            i1a2[r.get("criterion", "")] += 1
    numbers["i1_a2_success_by_criterion"] = dict(i1a2)
    fi2: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))  # I2 only, "none" = no rejection
    for r in ablation:
        if r["defense"] == "I2" and r.get("criterion") not in ("BENIGN", "ADAPTIVE"):
            fi2[r.get("attacker")][r.get("first_reject") or "none"] += 1
    numbers["first_reject_I2"] = {k: dict(v) for k, v in fi2.items()}

    # ---------------------------------------------------------------- RQ3 generated vs benchmark suites
    rq3 = {}
    for d in ("B0", "B4", "I2"):
        for crit_set, name in ((("BENCH",), "bench"), (("EDGE", "SLOT", "SEL", "TAINT", "RECONF", "COLL"), "generated")):
            xs = [r for r in zoo if r["defense"] == d and r.get("criterion") in crit_set]
            if not xs:
                continue
            succ = sum(r["asr"] for r in xs)
            calls = sum(r.get("llm_calls", 0) for r in xs)
            uniq = len({(r["model_name"], r.get("obligation")) for r in xs if r["asr"]})
            rq3[f"{d}:{name}"] = {"n": len(xs), "succ": succ, "calls": calls,
                                  "per_kcall": 1000 * succ / max(1, calls), "unique": uniq,
                                  "asr": succ / len(xs)}
    crits = defaultdict(lambda: defaultdict(list))
    for r in zoo:
        if r.get("criterion") in ("EDGE", "SLOT", "SEL", "TAINT", "RECONF", "COLL", "BENCH"):
            crits[r["defense"]][r["criterion"]].append(r["asr"])
    numbers["rq3"] = rq3
    numbers["rq3_by_criterion"] = {d: {c: mean(v) for c, v in x.items()} for d, x in crits.items()}
    lines = [r"\begin{tabular}{@{}llrrrrr@{}}", r"\toprule",
             r"Target & Suite & Tests & Succ. & Calls & Succ./1k & Distinct \\", r"\midrule"]
    for k, v in rq3.items():
        d, s = k.split(":")
        lines.append(f"{d} & {s} & {v['n']} & {v['succ']} & {v['calls']} & {fmt(v['per_kcall'])} & {v['unique']} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_rq3.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- RQ4 cost
    lines = [r"\begin{tabular}{@{}lrrrrr@{}}", r"\toprule",
             r"Defense & Util.\ benign (\%) & FRR (\%) & LLM calls & Tokens & Seconds \\", r"\midrule"]
    for d in ORDER:
        if d in main:
            m = main[d]
            lines.append(f"{NAMES[d]} & {pct(m['u_ben'])} & {pct(m['frr'])} & {fmt(m['calls'], 1)} & "
                         f"{fmt(m['tok'], 0)} & {fmt(m['sec'], 1)} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_rq4.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- paired tests (RQ2/RQ4) vs B0 and B4
    idx = defaultdict(dict)
    for r in zoo:
        if r.get("criterion") not in ("BENIGN", "ADAPTIVE"):
            idx[pair_key(r)][r["defense"]] = r
    tests: dict[str, Any] = {}
    for ref in ("B0", "B4"):
        ps = {}
        for d in ORDER:
            if d == ref:
                continue
            pairs = [(bool(v[d]["asr"]), bool(v[ref]["asr"])) for v in idx.values() if d in v and ref in v]
            if len(pairs) >= 5:
                tests[f"{d}_vs_{ref}"] = mcnemar(pairs, rng)
                ps[f"{d}_vs_{ref}"] = tests[f"{d}_vs_{ref}"]["p"]
        for k, v in holm(ps).items():
            tests[k]["p_holm"] = v
    # utility (benign) paired vs B0
    bidx = defaultdict(dict)
    for r in zoo:
        if r.get("criterion") == "BENIGN":
            bidx[pair_key(r)][r["defense"]] = r
    from scipy.stats import wilcoxon
    ps = {}
    for d in ORDER:
        if d == "B0":
            continue
        pairs = [(bool(v[d]["utility"]), bool(v["B0"]["utility"])) for v in bidx.values() if d in v and "B0" in v]
        if len(pairs) >= 5:
            tests[f"util_{d}_vs_B0"] = mcnemar(pairs, rng)
            ps[f"util_{d}_vs_B0"] = tests[f"util_{d}_vs_B0"]["p"]
        lat = [(v[d]["seconds"], v["B0"]["seconds"]) for v in bidx.values() if d in v and "B0" in v]
        tok = [(v[d].get("prompt_tokens", 0) + v[d].get("completion_tokens", 0),
                v["B0"].get("prompt_tokens", 0) + v["B0"].get("completion_tokens", 0)) for v in bidx.values()
               if d in v and "B0" in v]
        if len(lat) >= 5:
            try:
                tests[f"lat_{d}_vs_B0"] = {"p": float(wilcoxon([x for x, _ in lat], [y for _, y in lat]).pvalue),
                                           "delta": cliffs_delta([x for x, _ in lat], [y for _, y in lat])}
                tests[f"tok_{d}_vs_B0"] = {"p": float(wilcoxon([x for x, _ in tok], [y for _, y in tok]).pvalue),
                                           "delta": cliffs_delta([x for x, _ in tok], [y for _, y in tok])}
            except ValueError:
                pass
    for k, v in holm(ps).items():
        tests[k]["p_holm"] = v
    numbers["tests"] = tests
    lines = [r"\begin{tabular}{@{}lrrrrr@{}}", r"\toprule",
             r"Comparison & Pairs & $b$ & $c$ & OR [95\% CI] & $p_{Holm}$ \\", r"\midrule"]
    for k, v in tests.items():
        if "or" in v and not k.startswith("util_"):
            d, ref = k.split("_vs_")
            lines.append(f"{NAMES.get(d, d)} vs {ref} & {v['n_pairs']} & {v['b']} & {v['c']} & "
                         f"{fmt(v['or'])} [{fmt(v['or_lo'])}, {fmt(v['or_hi'])}] & {pfmt(v.get('p_holm', v['p']))} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_tests.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- mixed-effects model on ASR
    try:
        import pandas as pd
        from statsmodels.genmod.bayes_mixed_glm import BinomialBayesMixedGLM
        df = pd.DataFrame([{"y": int(r["asr"]), "defense": r["defense"], "llm": r.get("llm"), "task": r["task"]}
                           for r in zoo if r.get("criterion") not in ("BENIGN", "ADAPTIVE")
                           and not r["defense"].startswith("I2-")])
        if len(df) > 50 and df["defense"].nunique() > 1:
            df["defense"] = pd.Categorical(df["defense"], categories=[d for d in ORDER if d in set(df["defense"])])
            formula = "y ~ C(defense)" + (" + C(llm)" if df["llm"].nunique() > 1 else "")
            md = BinomialBayesMixedGLM.from_formula(formula, {"task": "0 + C(task)"}, df)
            fit = md.fit_vb()
            numbers["glmm"] = {n: {"mean": float(m), "sd": float(s)} for n, m, s in
                               zip(md.exog_names, fit.fe_mean, fit.fe_sd, strict=False)}
    except Exception as e:  # reported, never hidden
        numbers["glmm_error"] = f"{type(e).__name__}: {e}"

    # ---------------------------------------------------------------- RQ5 adaptive
    ad = defaultdict(list)
    att = defaultdict(list)
    for r in adaptive:
        if r.get("criterion") == "ADAPTIVE":
            ad[r["defense"]].append(r["asr"])
            att[r["defense"]].append(r.get("attempts", 0))
    numbers["rq5"] = {d: {"asr": mean(v), "n": len(v), "attempts": mean(att[d])} for d, v in ad.items()}
    lines = [r"\begin{tabular}{@{}lrrr@{}}", r"\toprule", r"Defense & Cases & ASR (\%) & Mean attempts \\", r"\midrule"]
    for d in ORDER:
        if d in ad:
            lines.append(f"{NAMES[d]} & {len(ad[d])} & {pct(mean(ad[d]))} & {fmt(mean(att[d]), 1)} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_rq5.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- per-LLM breakdown
    per = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for r in zoo:
        if r["defense"] in ("B0", "B3", "B4", "I1", "I2"):
            key = "u" if r.get("criterion") == "BENIGN" else "a"
            per[r.get("llm")][r["defense"]][key].append(r["utility"] if key == "u" else r["asr"])
    defs = ["B0", "B3", "B4", "I1", "I2"]
    lines = [r"\begin{tabular}{@{}l" + "rr" * len(defs) + r"@{}}", r"\toprule",
             " & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{d}}}" for d in defs) + r" \\",
             "Model & " + " & ".join("ASR & $U$" for _ in defs) + r" \\", r"\midrule"]
    numbers["per_llm"] = {}
    for llm in sorted(per):
        numbers["per_llm"][llm] = {d: {"asr": mean(per[llm][d]["a"]), "util": mean(per[llm][d]["u"])} for d in defs}
        lines.append(f"\\texttt{{{llm}}} & " + " & ".join(f"{pct(mean(per[llm][d]['a']))} & {pct(mean(per[llm][d]['u']))}"
                                                     for d in defs) + r" \\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_llm.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- seed variance (temperature 0.7)
    sv = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for r in seeds_rows:
        key = "u" if r.get("criterion") == "BENIGN" else "a"
        sv[r["defense"]][key][r["seed"]].append(r["utility"] if key == "u" else r["asr"])
    numbers["seeds"] = {}
    orders = set()
    for sd in {s for d in sv for s in sv[d]["a"]}:
        orders.add(tuple(sorted((d for d in sv if sd in sv[d]["a"]), key=lambda d: mean(sv[d]["a"][sd]))))
    numbers["seeds_order_stable"] = len(orders) == 1
    lines = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Defense & ASR mean (\%) & ASR sd across seeds & Utility mean (\%) & Utility sd \\", r"\midrule"]
    for d in ORDER:
        if d in sv:
            a_s = [mean(v) for v in sv[d]["a"].values()]
            u_s = [mean(v) for v in sv[d]["u"].values()]
            numbers["seeds"][d] = {"asr": mean(a_s), "asr_sd": float(np.std(a_s, ddof=1)) if len(a_s) > 1 else 0.0,
                                   "util": mean(u_s), "util_sd": float(np.std(u_s, ddof=1)) if len(u_s) > 1 else 0.0,
                                   "n_seeds": len(a_s)}
            v = numbers["seeds"][d]
            lines.append(f"{NAMES[d]} & {pct(v['asr'])} & {pct(v['asr_sd'])} & {pct(v['util'])} & {pct(v['util_sd'])} \\\\")
    lines += [r"\botrule", r"\end{tabular}"]
    (out / "tab_seeds.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- TAMAS
    tb = defaultdict(lambda: defaultdict(list))
    for r in tam:
        key = r["tamas_attack"] + ("-" + r["variant"] if r.get("variant") not in (None, "-") else "")
        if r["tamas_attack"] == "Benign":
            tb[r["defense"]]["Benign util."].append(r["utility"])
        else:
            tb[r["defense"]][key].append(r["goal_met"])
    cols = ["DPI-whole", "DPI-split", "IPI", "Colluding", "Impersonation", "Byzantine", "Contradicting", "Benign util."]
    short = {"DPI-whole": "DPI-w", "DPI-split": "DPI-s", "IPI": "IPI", "Colluding": "Coll.", "Impersonation": "Imp.",
             "Byzantine": "Byz.", "Contradicting": "Contr.", "Benign util.": "$U_{ben}$"}
    cols = [c for c in cols if any(c in tb[d] for d in tb)]
    lines = [r"\begin{tabular}{@{}l" + "r" * len(cols) + r"@{}}", r"\toprule",
             "Def. & " + " & ".join(short[c] for c in cols) + r" \\", r"\midrule"]
    numbers["tamas"] = {}
    for d in ORDER:
        if d in tb:
            numbers["tamas"][d] = {c: mean(tb[d][c]) for c in cols}
            lines.append(f"{d} & " + " & ".join(pct(mean(tb[d][c])) for c in cols) + r" \\")
    lines += [r"\botrule", r"\end{tabular}"]
    if not cols:
        lines = [r"\begin{tabular}{@{}l@{}}", r"\toprule", r"No TAMAS runs in these results. \\", r"\botrule",
                 r"\end{tabular}"]
    (out / "tab_tamas.tex").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- figure: ASR vs utility
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(4.6, 3.4))
        for d, m in main.items():
            ax.errorbar(100 * m["u_ben"], 100 * m["asr"],
                        yerr=[[100 * (m["asr"] - m["asr_lo"])], [100 * (m["asr_hi"] - m["asr"])]],
                        fmt="o" if d.startswith("B") else "s", color="#4a4a4a" if d.startswith("B") else "#1f5fa8",
                        capsize=2, ms=5)
            ax.annotate(d, (100 * m["u_ben"], 100 * m["asr"]), textcoords="offset points", xytext=(5, 4), fontsize=8)
        ax.set_xlabel("Benign utility (%)")
        ax.set_ylabel("Attack success rate (%)")
        ax.grid(alpha=0.3)
        fig.tight_layout()
        fig.savefig(out / "fig_tradeoff.pdf")
        plt.close(fig)
        if rq1:
            fig, ax = plt.subplots(figsize=(4.6, 3.2))
            tops = sorted({k.rstrip("0123456789") for k in rq1})
            for t in tops:
                xs = sorted(int(k[len(t):]) for k in rq1 if k.rstrip("0123456789") == t)
                ax.plot(xs, [rq1[f"{t}{s}"]["blast"] for s in xs], marker="o", label=t)
            ax.set_xlabel("Agents")
            ax.set_ylabel("Blast radius under B0")
            ax.legend(fontsize=7)
            ax.grid(alpha=0.3)
            fig.tight_layout()
            fig.savefig(out / "fig_propagation.pdf")
            plt.close(fig)
    except Exception as e:
        numbers["figure_error"] = str(e)
    # ---------------------------------------------------------------- residual risk (rule-based categories)
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from residual import category
    res = defaultdict(int)
    for r in rows:
        if r.get("defense") == "I2" and r.get("asr") and not (r.get("suite") == "tamas" and r.get("variant") == "split"
                                                               and r.get("llm") in fixed):
            res[category(r)] += 1
    numbers["residual"] = dict(res)
    review_numbers(rows, zoo, ablation, tam, numbers, out)
    (out / "numbers.json").write_text(json.dumps(numbers, indent=1, default=str))
    print(json.dumps({"rows": len(rows), "errors": len(errors), "defenses": list(main)}, indent=None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
