"""Minimal Mermaid statechart importer (MindPortalix front-end subset).

Supported lines (``stateDiagram-v2``)::

    state "Planner: write a plan" as plan      %% slot 'plan' owned by agent 'Planner'
    [*] --> plan                               %% plan reads the user input slot 'task'
    plan --> code                              %% code reads plan

Every state becomes an agent slot with one bounded-free-text data field ``text``; the
designer then refines contracts in YAML. ``[*] -->`` edges read the input slot ``task``.
"""

from __future__ import annotations

import re

from .schema import Agent, FieldSpec, Label, MASModel, Release, Slot

_STATE = re.compile(r'^\s*state\s+"(?P<owner>[^:"]+):\s*(?P<instr>[^"]*)"\s+as\s+(?P<id>\w+)\s*$')
_EDGE = re.compile(r"^\s*(?P<src>\[\*\]|\w+)\s*-->\s*(?P<dst>\[\*\]|\w+)\s*(?::.*)?$")


def import_mermaid(text: str, name: str = "imported") -> MASModel:
    states: dict[str, tuple[str, str]] = {}
    reads: dict[str, list[str]] = {}
    finals: list[str] = []
    for line in text.splitlines():
        line = line.split("%%", 1)[0].rstrip()
        if not line.strip() or line.strip().startswith("stateDiagram"):
            continue
        if m := _STATE.match(line):
            states[m["id"]] = (m["owner"].strip(), m["instr"].strip())
            continue
        if m := _EDGE.match(line):
            src, dst = m["src"], m["dst"]
            if dst == "[*]":
                finals.append(src)
                continue
            reads.setdefault(dst, []).append("task" if src == "[*]" else src)
            continue
        raise ValueError(f"unsupported mermaid line: {line!r}")
    ids = list(dict.fromkeys(list(states) + list(reads)))
    owners = sorted({states.get(i, (i, ""))[0] for i in ids})
    agent_ids = {o: re.sub(r"\W+", "_", o.lower()).strip("_") for o in owners}
    slots = [Slot(id="task", kind="input", label=Label.user, fields={"text": FieldSpec(type="string")})]
    for sid in ids:
        owner, instr = states.get(sid, (sid, ""))
        slots.append(Slot(id=sid, kind="agent", owner=agent_ids[owner], instruction=instr or f"Perform step {sid}.",
                          reads=tuple(reads.get(sid, ["task"])), fields={"text": FieldSpec(type="string")}))
    return MASModel(name=name, agents=tuple(Agent(id=agent_ids[o], role=o) for o in owners),
                    slots=tuple(slots), release=Release(outputs=tuple(finals or ids[-1:])))
