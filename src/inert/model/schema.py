"""M1 metamodel: Pydantic v2 schema of an INERT multi-agent-system model (``*.inert.yaml``).

A model is designer-authored and versioned. Agents are untrusted *proposers*; every value
they produce lands in a typed **slot** whose contract (instruction, field schema, owned
validators) is fixed by the model. Edges are the slot read relation. Each output field has a
**sink role** that the taint policy constrains:

* ``data``        free content; may carry any label (e.g. a report or an e-mail body);
* ``instruction`` text that later steers another agent's task (e.g. a sub-task for a worker);
* ``executor``    a tool argument or code that causes an effect (recipient, path, command);
* ``control``     a routing decision that selects which slot runs next (guards).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Label(StrEnum):
    """Taint lattice (a chain): trusted < user < agent_untrusted < external_untrusted."""

    trusted = "trusted"
    user = "user"
    agent_untrusted = "agent_untrusted"
    external_untrusted = "external_untrusted"


LABEL_ORDER: tuple[Label, ...] = (Label.trusted, Label.user, Label.agent_untrusted, Label.external_untrusted)
SinkRole = Literal["data", "instruction", "executor", "control"]
HIGH_INTEGRITY: tuple[str, ...] = ("instruction", "executor", "control")


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FieldSpec(_Base):
    """A primitive output field. ``string`` fields may be bounded by ``max_length`` / ``pattern``."""

    type: Literal["string", "integer", "boolean", "enum"]
    role: SinkRole = "data"
    values: tuple[str, ...] | None = None
    max_length: int | None = None
    pattern: str | None = None
    minimum: int | None = None
    maximum: int | None = None
    description: str = ""

    @model_validator(mode="after")
    def _enum_values(self) -> FieldSpec:
        if self.type == "enum" and not self.values:
            raise ValueError("enum field needs values")
        if self.type != "enum" and self.values is not None:
            raise ValueError("values only allowed on enum fields")
        return self

    @property
    def bounded(self) -> bool:
        """Schema-bounded: cannot carry arbitrary free text."""
        if self.type in ("integer", "boolean", "enum"):
            return True
        return self.pattern is not None or (self.max_length is not None and self.max_length <= 64)


class Agent(_Base):
    id: str
    role: str
    persona: str = ""


class Tool(_Base):
    name: str
    description: str
    args: dict[str, FieldSpec] = Field(default_factory=dict)
    side_effect: Literal["none", "read", "write", "exec"] = "read"
    output_label: Label = Label.external_untrusted


class Validator(_Base):
    """Owned, deterministic validators (no LLM in the TCB)."""

    kind: Literal["max_length", "not_contains", "regex", "nonempty", "one_of_inputs", "member_of"]
    field: str
    param: Any = None


class Guard(_Base):
    """Run the slot only if ``slot.field == equals`` (the field must be a control enum)."""

    slot: str
    field: str
    equals: str


class Declassifier(_Base):
    """LLM-free, schema-bounded extraction that lowers a label (logged on every use)."""

    kind: Literal["enum", "int_range", "regex", "bool"]
    params: dict[str, Any] = Field(default_factory=dict)
    to_label: Label = Label.agent_untrusted


class Slot(_Base):
    id: str
    kind: Literal["input", "agent", "tool", "declassify"]
    owner: str | None = None              # agent id (agent slots)
    tool: str | None = None               # tool name (tool slots)
    instruction: str = ""
    reads: tuple[str, ...] = ()           # "slot" or "slot.field"
    fields: dict[str, FieldSpec] = Field(default_factory=dict)
    args_from: dict[str, str] = Field(default_factory=dict)   # tool arg -> "slot.field" | "=literal"
    validators: tuple[Validator, ...] = ()
    label: Label | None = None            # input slots only
    guard: Guard | None = None
    declassifier: Declassifier | None = None   # declassify slots: source = reads[0] (slot.field)

    @field_validator("id")
    @classmethod
    def _ident(cls, v: str) -> str:
        if not v or "." in v or " " in v:
            raise ValueError(f"bad slot id {v!r}")
        return v

    @model_validator(mode="after")
    def _kind_fields(self) -> Slot:
        if self.kind == "agent" and not self.owner:
            raise ValueError(f"agent slot {self.id} needs an owner")
        if self.kind == "tool" and not self.tool:
            raise ValueError(f"tool slot {self.id} needs a tool")
        if self.kind == "input" and self.label is None:
            raise ValueError(f"input slot {self.id} needs a label")
        if self.kind == "declassify" and (self.declassifier is None or len(self.reads) != 1 or "." not in self.reads[0]):
            raise ValueError(f"declassify slot {self.id} needs a declassifier and exactly one slot.field read")
        return self

    def read_slots(self) -> tuple[str, ...]:
        out: list[str] = []
        for r in self.reads:
            s = r.split(".", 1)[0]
            if s not in out:
                out.append(s)
        for src in self.args_from.values():
            if not src.startswith("="):
                s = src.split(".", 1)[0]
                if s not in out:
                    out.append(s)
        if self.guard and self.guard.slot not in out:
            out.append(self.guard.slot)
        return tuple(out)


class Policy(_Base):
    sink_max: dict[str, Label] = Field(default_factory=lambda: {
        "data": Label.external_untrusted, "instruction": Label.agent_untrusted,
        "executor": Label.agent_untrusted, "control": Label.agent_untrusted})
    agent_label: Label = Label.agent_untrusted


class JointConstraint(_Base):
    kind: Literal["fields_equal", "not_contains"]
    left: str                     # slot.field
    right: str | None = None      # slot.field (fields_equal)
    param: str | None = None      # substring (not_contains)


class Release(_Base):
    outputs: tuple[str, ...]
    joint_constraints: tuple[JointConstraint, ...] = ()


class Budget(_Base):
    max_attempts: int = 2          # generation budget k per dependency episode
    max_steps: int = 200


class MASModel(_Base):
    name: str
    version: str = "1"
    description: str = ""
    agents: tuple[Agent, ...]
    tools: tuple[Tool, ...] = ()
    slots: tuple[Slot, ...]
    policy: Policy = Field(default_factory=Policy)
    release: Release
    budget: Budget = Field(default_factory=Budget)

    @model_validator(mode="after")
    def _unique(self) -> MASModel:
        for what, ids in (("agent", [a.id for a in self.agents]), ("tool", [t.name for t in self.tools]),
                          ("slot", [s.id for s in self.slots])):
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {what} id")
        return self

    # convenience lookups -------------------------------------------------
    def slot(self, sid: str) -> Slot:
        return next(s for s in self.slots if s.id == sid)

    def tool(self, name: str) -> Tool:
        return next(t for t in self.tools if t.name == name)

    def agent(self, aid: str) -> Agent:
        return next(a for a in self.agents if a.id == aid)


def label_leq(a: Label, b: Label) -> bool:
    return LABEL_ORDER.index(a) <= LABEL_ORDER.index(b)


def label_join(*labels: Label) -> Label:
    if not labels:
        return Label.trusted
    return max(labels, key=LABEL_ORDER.index)
