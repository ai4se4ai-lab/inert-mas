"""Quick per-defense summary of result JSONL files (development aid; paper tables: analysis/tables.py)."""
import json
import sys
from collections import defaultdict

rows = []
for p in sys.argv[1:]:
    rows += [json.loads(line) for line in open(p) if line.strip()]
errs = [r for r in rows if r.get("error")]
print(f"rows={len(rows)} errors={len(errs)}")
for e in errs[:3]:
    print("ERR", e["case_id"], e["error"], e.get("trace", "")[-600:])
rows = [r for r in rows if not r.get("error")]
agg = defaultdict(lambda: defaultdict(list))
for r in rows:
    d = r["defense"]
    if r.get("attack") is None and r.get("criterion") == "BENIGN":
        agg[d]["util_benign"].append(r["utility"])
        if "honest_proposals" in r:
            agg[d]["fr"].append((r["honest_rejected"], r["honest_proposals"]))
        if r.get("messages_checked"):
            agg[d]["fr"].append((r["flagged_benign"], r["messages_checked"]))
    else:
        agg[d]["asr"].append(r["asr"])
        agg[d]["goal"].append(r["goal_met"])
        agg[d]["util_att"].append(r["utility"])
        agg[d]["inf"].append(r.get("infected_agents", 0))
    agg[d]["calls"].append(r.get("llm_calls", 0))
    agg[d]["sec"].append(r.get("seconds", 0))
    if "replay_ok" in r:
        agg[d]["replay"].append(r["replay_ok"])
def mean(xs):
    return sum(xs) / len(xs) if xs else float("nan")
print(f"{'def':12} {'n_att':>5} {'ASR':>6} {'goal':>6} {'U_att':>6} {'n_ben':>5} {'U_ben':>6} {'FRR':>6} {'inf':>5} {'calls':>6} {'sec':>6} replay")
for d in sorted(agg):
    a = agg[d]
    fr = a["fr"]
    frr = sum(x for x, _ in fr) / max(1, sum(y for _, y in fr)) if fr else float("nan")
    print(f"{d:12} {len(a['asr']):5d} {mean(a['asr']):6.3f} {mean(a['goal']):6.3f} {mean(a['util_att']):6.3f} "
          f"{len(a['util_benign']):5d} {mean(a['util_benign']):6.3f} {frr:6.3f} {mean(a['inf']):5.2f} "
          f"{mean(a['calls']):6.1f} {mean(a['sec']):6.2f} {mean(a['replay']) if a['replay'] else ''}")
if "--by" in sys.argv:
    pass
