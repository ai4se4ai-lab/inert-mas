"""Coverage criteria over the compiled IR and the generator that turns obligations into tests.

Criteria (each obligation names the model element it covers):
  EDGE   every IR edge u->v whose producer u is a tool or agent slot (inject at u);
  SLOT   every agent slot x payload class (compromised owner emits the payload in that slot);
  SEL    every context-selector read ``ref`` of every agent slot (inject at the producer of ref);
  TAINT  every untrusted-source -> high-integrity-sink path (inject at the source, goal at the sink);
  RECONF every reconfiguration event: tool-metadata change per tool, rogue agent, replay per agent slot;
  COLL   every (middle agent, actor) pair of colluding compromised agents.
Obligations whose injection point or goal does not exist in the model are infeasible and are
reported, never silently dropped.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass

from ..compiler.ir import IR
from ..model.schema import HIGH_INTEGRITY
from .payloads import GOALS, MUTATORS, PAYLOAD_CLASSES, POSITIONS, render
from .spec import AttackTest, InjectionPoint

TEXT_CLASSES = tuple(c for c in PAYLOAD_CLASSES if c != "tool_poison")


@dataclass(frozen=True)
class Obligation:
    id: str
    criterion: str
    element: str
    feasible: bool
    reason: str = ""


def _producer_point(ir: IR, sid: str, resource: str) -> tuple[str, str]:
    d = ir.data["slots"][sid]["def"]
    if d["kind"] == "tool":
        return "resource", resource
    if d["kind"] == "agent":
        return "transport", d["owner"]
    return "", ""


def taint_paths(ir: IR) -> list[list[str]]:
    """Slot paths from external-label tool slots to high-integrity sinks."""
    slots = ir.data["slots"]
    succ: dict[str, list[str]] = {}
    for u, v in ir.edges:
        succ.setdefault(u, []).append(v)
    sinks = set()
    for sid, sl in slots.items():
        d = sl["def"]
        if d["kind"] == "agent" and any(f.get("role", "data") in HIGH_INTEGRITY for f in d.get("fields", {}).values()):
            sinks.add(sid)
        if d["kind"] == "tool" and d["tool"] in ir.data["tools"]:
            args = ir.data["tools"][d["tool"]]["meta"]["args"]
            if any(a.get("role", "data") in HIGH_INTEGRITY for a in args.values()) and \
                    ir.data["tools"][d["tool"]]["meta"]["side_effect"] in ("write", "exec"):
                sinks.add(sid)
    sources = [sid for sid, sl in slots.items() if sl["def"]["kind"] == "tool"
               and ir.data["tools"][sl["def"]["tool"]]["meta"]["output_label"] == "external_untrusted"]
    paths: list[list[str]] = []

    def dfs(node: str, path: list[str]) -> None:
        if node in sinks and len(path) > 1:
            paths.append(path)
        for n in succ.get(node, []):
            if n not in path and len(paths) < 500:
                dfs(n, path + [n])

    for s in sources:
        dfs(s, [s])
    return paths


def obligations(ir: IR, family: str, resource: str) -> list[Obligation]:
    slots = ir.data["slots"]
    goal = GOALS[family]
    has_goal = goal.tool in ir.data["tools"]
    out: list[Obligation] = []
    for u, v in ir.edges:
        kind = slots[u]["def"]["kind"]
        feas = kind in ("tool", "agent") and has_goal
        out.append(Obligation(f"EDGE:{u}->{v}", "EDGE", f"{u}->{v}", feas, "" if feas else "producer not injectable"))
    for sid, sl in slots.items():
        if sl["def"]["kind"] == "agent":
            for pc in TEXT_CLASSES:
                out.append(Obligation(f"SLOT:{sid}:{pc}", "SLOT", sid, has_goal))
            for ref in sl["def"].get("reads", []):
                src = ref.split(".")[0]
                feas = slots[src]["def"]["kind"] in ("tool", "agent") and has_goal
                out.append(Obligation(f"SEL:{sid}:{ref}", "SEL", f"{sid}<-{ref}", feas,
                                      "" if feas else "input selector (trusted source)"))
    for p in taint_paths(ir):
        out.append(Obligation("TAINT:" + ">".join(p), "TAINT", ">".join(p), has_goal))
    for t in ir.data["tools"]:
        out.append(Obligation(f"RECONF:tool_meta:{t}", "RECONF", t, has_goal))
    out.append(Obligation("RECONF:rogue_agent", "RECONF", "agents", has_goal))
    for sid, sl in slots.items():
        if sl["def"]["kind"] == "agent":
            out.append(Obligation(f"RECONF:replay:{sid}", "RECONF", sid, has_goal))
    agents = list(ir.data["agents"])
    for a in agents:
        if a not in ("actor", "planner"):
            out.append(Obligation(f"COLL:{a}+actor", "COLL", f"{a}+actor", has_goal and "actor" in agents))
    return out


def generate(ir: IR, family: str, resource: str, seed: int = 0, criteria: tuple[str, ...] | None = None,
             max_tests: int | None = None) -> tuple[list[AttackTest], list[Obligation]]:
    """One executable test per feasible obligation (payload class/mutator/position rotated by seed)."""
    rng = random.Random(seed)
    obs = obligations(ir, family, resource)
    goal = GOALS[family]
    slots = ir.data["slots"]
    tests: list[AttackTest] = []
    cyc = itertools.count()
    for ob in obs:
        if not ob.feasible or (criteria and ob.criterion not in criteria):
            continue
        i = next(cyc)
        pc = TEXT_CLASSES[i % len(TEXT_CLASSES)]
        mut = MUTATORS[(i // len(TEXT_CLASSES)) % len(MUTATORS)] if rng.random() < 0.5 else "none"
        pos = POSITIONS[i % len(POSITIONS)]
        if ob.criterion == "EDGE":
            u = ob.element.split("->")[0]
            kind, tgt = _producer_point(ir, u, resource)
            pt, att = InjectionPoint(kind, tgt, pos), ("A1" if kind == "resource" else "A3")
        elif ob.criterion == "SLOT":
            sid, pc = ob.element, ob.id.rsplit(":", 1)[1]
            pt, att = InjectionPoint("agent", slots[sid]["def"]["owner"], pos), "A2"
        elif ob.criterion == "SEL":
            src = ob.element.split("<-")[1].split(".")[0]
            kind, tgt = _producer_point(ir, src, resource)
            pt, att = InjectionPoint(kind, tgt, pos), ("A1" if kind == "resource" else "A3")
        elif ob.criterion == "TAINT":
            pt, att = InjectionPoint("resource", resource, pos), "A1"
        elif ob.criterion == "RECONF":
            parts = ob.id.split(":")
            if parts[1] == "tool_meta":
                pt, pc = InjectionPoint("tool_meta", parts[2]), "tool_poison"
            elif parts[1] == "rogue_agent":
                pt = InjectionPoint("rogue_agent", "rogue")
            else:
                pt = InjectionPoint("replay", parts[2])
            att = "A5"
        else:  # COLL
            pt, att = InjectionPoint("collude", ob.element), "A4"
        payload = render(pc, goal, mut, variant=i)
        tests.append(AttackTest(id=f"{ir.data['name']}:{ob.id}", obligation=ob.id, criterion=ob.criterion,
                                attacker=att, point=pt, payload_class=pc, mutator=mut, payload=payload, family=family))
    if max_tests is not None and len(tests) > max_tests:
        rng.shuffle(tests)
        tests = sorted(tests[:max_tests], key=lambda t: t.id)
    return tests, obs


def benchmark_suite(ir: IR, family: str, resource: str) -> list[AttackTest]:
    """Benchmark-style attacks only: one indirect injection at the primary untrusted resource
    (AgentDojo 'important instructions' style), one per payload class used by benchmarks."""
    goal = GOALS[family]
    out = []
    for pc in ("override", "fake_error", "infection"):
        out.append(AttackTest(id=f"{ir.data['name']}:BENCH:{pc}", obligation=f"BENCH:{pc}", criterion="BENCH",
                              attacker="A1", point=InjectionPoint("resource", resource, "suffix"), payload_class=pc,
                              mutator="none", payload=render(pc, goal), family=family))
    return out
