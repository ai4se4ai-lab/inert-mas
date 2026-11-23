"""Static checks on a model (all LLM-free).

L1 unreachable slot              a slot not reachable from any input slot
L2 cycle                         the read relation must be acyclic (cycles are unrolled with a budget)
L3 untrusted-to-sink path        a high-integrity sink is reachable from an untrusted source with no
                                 declassifier on the path (static label above the sink's maximum)
L4 slot without owner            unknown agent/tool owner, or an agent that owns nothing
L5 free text into a sink         a tool executor argument or a guard reads an unbounded free-text field,
                                 or reads a field whose role is ``data``
L6 dangling read                 a read or argument that names a missing slot or field
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import HIGH_INTEGRITY, Label, MASModel, Slot, label_join, label_leq


@dataclass(frozen=True)
class LintIssue:
    code: str
    slot: str
    message: str


def _field_of(model: MASModel, ref: str) -> tuple[Slot, str | None]:
    sid, _, field = ref.partition(".")
    return model.slot(sid), (field or None)


def output_fields(model: MASModel, s: Slot) -> set[str]:
    if s.kind == "agent":
        return set(s.fields)
    if s.kind == "tool":
        return {"result"}
    if s.kind == "declassify":
        return {"value", "ok"}
    return set(s.fields) or {"text"}


def topo_order(model: MASModel) -> list[str]:
    """Kahn order with deterministic tie-break on declaration order; raises on a cycle."""
    ids = [s.id for s in model.slots]
    deps = {s.id: [d for d in s.read_slots() if d in ids] for s in model.slots}
    order: list[str] = []
    done: set[str] = set()
    while len(order) < len(ids):
        progress = False
        for sid in ids:
            if sid not in done and all(d in done for d in deps[sid]):
                order.append(sid)
                done.add(sid)
                progress = True
        if not progress:
            raise ValueError("cycle in read relation: " + ",".join(sorted(set(ids) - done)))
    return order


def static_labels(model: MASModel) -> dict[str, Label]:
    """Upper bound of each slot's label (tool outputs at their declared label)."""
    lab: dict[str, Label] = {}
    for sid in topo_order(model):
        s = model.slot(sid)
        ins = [lab[d] for d in s.read_slots() if d in lab]
        if s.kind == "input":
            assert s.label is not None
            lab[sid] = s.label
        elif s.kind == "agent":
            lab[sid] = label_join(model.policy.agent_label, *ins)
        elif s.kind == "tool":
            data_args = {a for a, spec in model.tool(s.tool or "").args.items() if spec.role == "data"} \
                if any(t.name == s.tool for t in model.tools) else set()
            arg_labels = [lab[src.split(".")[0]] for a, src in s.args_from.items()
                          if not src.startswith("=") and src.split(".")[0] in lab and a not in data_args]
            out = model.tool(s.tool or "").output_label if any(t.name == s.tool for t in model.tools) \
                else Label.external_untrusted
            lab[sid] = label_join(out, *arg_labels)
        else:  # declassify
            assert s.declassifier is not None
            lab[sid] = s.declassifier.to_label
    return lab


def lint(model: MASModel) -> list[LintIssue]:
    issues: list[LintIssue] = []
    ids = {s.id for s in model.slots}
    agents = {a.id for a in model.agents}
    tools = {t.name for t in model.tools}
    # L4 / L6
    for s in model.slots:
        if s.kind == "agent" and s.owner not in agents:
            issues.append(LintIssue("L4", s.id, f"owner {s.owner!r} is not a declared agent"))
        if s.kind == "tool" and s.tool not in tools:
            issues.append(LintIssue("L4", s.id, f"tool {s.tool!r} is not declared"))
        refs = list(s.reads) + [v for v in s.args_from.values() if not v.startswith("=")]
        if s.guard:
            refs.append(f"{s.guard.slot}.{s.guard.field}")
        for ref in refs:
            sid, _, field = ref.partition(".")
            if sid not in ids:
                issues.append(LintIssue("L6", s.id, f"read of missing slot {sid!r}"))
            elif field and field not in output_fields(model, model.slot(sid)):
                issues.append(LintIssue("L6", s.id, f"read of missing field {ref!r}"))
        if s.kind == "tool" and s.tool in tools:
            missing = set(model.tool(s.tool or "").args) - set(s.args_from)
            if missing:
                issues.append(LintIssue("L6", s.id, f"tool arguments without source: {sorted(missing)}"))
    owned = {s.owner for s in model.slots if s.kind == "agent"}
    for ag in model.agents:
        if ag.id not in owned:
            issues.append(LintIssue("L4", ag.id, "agent owns no slot"))
    if any(i.code == "L6" for i in issues):
        return issues
    # L2
    try:
        order = topo_order(model)
    except ValueError as e:
        return issues + [LintIssue("L2", "*", str(e))]
    # L1 reachability from inputs
    reach = {s.id for s in model.slots if s.kind == "input"}
    for sid in order:
        s = model.slot(sid)
        if s.kind != "input" and s.read_slots() and all(d in reach for d in s.read_slots()):
            reach.add(sid)
    for s in model.slots:
        if s.id not in reach:
            issues.append(LintIssue("L1", s.id, "slot not reachable from an input"))
    # L3 static taint
    lab = static_labels(model)
    sink_max = model.policy.sink_max
    for s in model.slots:
        if s.kind == "agent":
            for f, spec in s.fields.items():
                if spec.role in HIGH_INTEGRITY and not label_leq(lab[s.id], sink_max[spec.role]):
                    issues.append(LintIssue("L3", s.id, f"field {f} ({spec.role}) can carry {lab[s.id].value} "
                                                        f"> {sink_max[spec.role].value}; add a declassifier"))
        if s.kind == "tool":
            tool = model.tool(s.tool or "")
            for a, src in s.args_from.items():
                if src.startswith("="):
                    continue
                role = tool.args[a].role if a in tool.args else "executor"
                src_id = src.split(".")[0]
                if role in HIGH_INTEGRITY and not label_leq(lab[src_id], sink_max[role]):
                    issues.append(LintIssue("L3", s.id, f"argument {a} reads {src} labelled {lab[src_id].value}"))
    # L5 free text into executor/control sinks
    for s in model.slots:
        checks: list[tuple[str, str]] = []
        if s.kind == "tool" and s.tool in tools:
            tool = model.tool(s.tool or "")
            checks += [(a, src) for a, src in s.args_from.items()
                       if not src.startswith("=") and tool.args.get(a) is not None and tool.args[a].role != "data"]
        if s.guard:
            checks.append(("guard", f"{s.guard.slot}.{s.guard.field}"))
        for what, ref in checks:
            producer, fname = _field_of(model, ref)
            if producer.kind == "agent" and fname:
                spec = producer.fields[fname]
                if spec.role == "data":
                    issues.append(LintIssue("L5", s.id, f"{what} reads data field {ref}"))
                elif what == "guard" and spec.type != "enum":
                    issues.append(LintIssue("L5", s.id, f"guard reads non-enum field {ref}"))
    return issues
