"""M2 compiler: model -> frozen, canonical, content-hashed intermediate representation.

Each element gets a SHA-256 over its canonical JSON. A slot's *contract hash* covers its
instruction, fields, validators, guard, declassifier and (for tool slots) the tool-metadata
hash; the *plan hash* covers every element hash and the policy, so any field change changes
it. Compiling the same model twice gives byte-identical output (``IR.to_bytes``).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from ..canon import canonical_bytes, sha256_hex
from ..model.io import to_dict
from ..model.lint import static_labels, topo_order
from ..model.schema import MASModel

IR_VERSION = "inert-ir/1"


def _strip(d: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in keys}


@dataclass(frozen=True)
class IR:
    data: dict[str, Any] = field(repr=False)
    model: MASModel = field(repr=False)

    # --------------------------------------------------------------- access
    @property
    def plan_hash(self) -> str:
        return str(self.data["plan_hash"])

    @property
    def order(self) -> list[str]:
        return list(self.data["order"])

    @property
    def edges(self) -> list[tuple[str, str]]:
        return [(a, b) for a, b in self.data["edges"]]

    def slot(self, sid: str) -> dict[str, Any]:
        return copy.deepcopy(self.data["slots"][sid])

    def contract_hash(self, sid: str) -> str:
        return str(self.data["slots"][sid]["contract_hash"])

    def tool_hash(self, name: str) -> str:
        return str(self.data["tools"][name]["hash"])

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.data)


def tool_metadata(t: dict[str, Any]) -> dict[str, Any]:
    """The part of a tool definition an LLM can see or that changes its effect."""
    return {"name": t["name"], "description": t["description"], "args": t.get("args", {}),
            "side_effect": t.get("side_effect", "read"), "output_label": t.get("output_label", "external_untrusted")}


def compile_model(model: MASModel) -> IR:
    m = to_dict(model)
    full = model.model_dump(mode="json")
    tools: dict[str, Any] = {}
    for t in full["tools"]:
        meta = tool_metadata(t)
        tools[t["name"]] = {"meta": meta, "hash": sha256_hex(meta)}
    agents = {a["id"]: {"def": a, "hash": sha256_hex(a)} for a in full["agents"]}
    labels = static_labels(model)
    order = topo_order(model)
    slots: dict[str, Any] = {}
    for s in full["slots"]:
        sobj = model.slot(s["id"])
        contract = _strip(s, "id", "reads", "owner", "args_from")
        if s["kind"] == "tool":
            contract["tool_hash"] = tools[s["tool"]]["hash"]
        contract_hash = sha256_hex(contract)
        prereqs = list(sobj.read_slots())
        slots[s["id"]] = {"def": s, "contract_hash": contract_hash, "prereqs": prereqs,
                          "rank": order.index(s["id"]), "static_label": labels[s["id"]].value,
                          "owner": (s.get("owner") if s["kind"] == "agent" else
                                    f"tool:{s['tool']}" if s["kind"] == "tool" else f"tcb:{s['kind']}"),
                          "hash": sha256_hex({"slot": s, "contract_hash": contract_hash})}
    edges = sorted({(p, sid) for sid, sl in slots.items() for p in sl["prereqs"]})
    policy = full["policy"]
    release = full["release"]
    budget = full["budget"]
    plan_hash = sha256_hex({"v": IR_VERSION, "name": m["name"], "version": m.get("version", "1"),
                            "agents": {k: v["hash"] for k, v in agents.items()},
                            "tools": {k: v["hash"] for k, v in tools.items()},
                            "slots": {k: v["hash"] for k, v in slots.items()},
                            "edges": [list(e) for e in edges], "policy": policy, "release": release,
                            "budget": budget})
    data = {"ir_version": IR_VERSION, "name": m["name"], "version": m.get("version", "1"),
            "agents": agents, "tools": tools, "slots": slots, "order": order,
            "edges": [list(e) for e in edges], "policy": policy, "release": release, "budget": budget,
            "plan_hash": plan_hash}
    canonical_bytes(data)  # rejects floats / unordered structures early
    return IR(data=data, model=model)
