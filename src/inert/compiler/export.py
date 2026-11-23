"""Exports of the same IR for baselines (B0/B4 run the *same* workflow without the controller).

``agent_graph`` gives the agent-level topology (who talks to whom, which tools each agent may
call) used by the native free-form runner. ``to_langgraph`` builds a LangGraph ``StateGraph``
when the optional ``langgraph`` package is installed.
"""

from __future__ import annotations

from typing import Any

from .ir import IR


def agent_graph(ir: IR) -> dict[str, Any]:
    slots = ir.data["slots"]
    owner_of: dict[str, str] = {}
    for sid in ir.order:
        d = slots[sid]["def"]
        if d["kind"] == "agent":
            owner_of[sid] = d["owner"]
    # A tool slot is attributed to the agent whose fields feed its executor arguments.
    tools_of: dict[str, list[str]] = {a: [] for a in ir.data["agents"]}
    for sid in ir.order:
        d = slots[sid]["def"]
        if d["kind"] == "tool":
            srcs = [v.split(".")[0] for v in d.get("args_from", {}).values() if not v.startswith("=")]
            callers = [owner_of[s] for s in srcs if s in owner_of]
            for a in callers[:1] or list(tools_of)[:1]:
                if d["tool"] not in tools_of[a]:
                    tools_of[a].append(d["tool"])

    def upstream_agents(sid: str, seen: set[str]) -> set[str]:
        out: set[str] = set()
        for p in slots[sid]["prereqs"]:
            if p in seen:
                continue
            seen.add(p)
            if p in owner_of:
                out.add(owner_of[p])
            else:
                out |= upstream_agents(p, seen)
        return out

    edges: set[tuple[str, str]] = set()
    for sid, a in owner_of.items():
        for u in upstream_agents(sid, set()):
            if u != a:
                edges.add((u, a))
    order: list[str] = []
    for sid in ir.order:
        if sid in owner_of and owner_of[sid] not in order:
            order.append(owner_of[sid])
    instructions: dict[str, list[str]] = {a: [] for a in ir.data["agents"]}
    for sid, a in owner_of.items():
        instructions[a].append(slots[sid]["def"].get("instruction", ""))
    return {"agents": order, "edges": sorted(edges), "tools": tools_of, "instructions": instructions,
            "roles": {a: v["def"]["role"] for a, v in ir.data["agents"].items()}}


def to_langgraph(ir: IR) -> Any:  # pragma: no cover - optional dependency
    try:
        from langgraph.graph import END, StateGraph  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError("langgraph is not installed; use agent_graph() with the native runner") from e
    g = agent_graph(ir)
    sg = StateGraph(dict)
    for a in g["agents"]:
        sg.add_node(a, lambda state, _a=a: state)
    for u, v in g["edges"]:
        sg.add_edge(u, v)
    sg.set_entry_point(g["agents"][0])
    sg.add_edge(g["agents"][-1], END)
    return sg
