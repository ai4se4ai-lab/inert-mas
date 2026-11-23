"""Attack tests: (obligation id, injection point, payload, attacker goal, oracle)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .payloads import GOALS, Goal

ATTACKERS = ("A1", "A2", "A3", "A4", "A5", "A6")


@dataclass(frozen=True)
class InjectionPoint:
    kind: str          # resource | agent | transport | collude | tool_meta | rogue_agent | replay | adaptive
    target: str        # resource key, agent id, "agent1+agent2", tool name, slot id
    position: str = "suffix"


@dataclass(frozen=True)
class AttackTest:
    id: str
    obligation: str
    criterion: str
    attacker: str
    point: InjectionPoint
    payload_class: str
    mutator: str
    payload: str
    family: str
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def goal(self) -> Goal:
        return GOALS[self.family]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["goal"] = asdict(self.goal)
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> AttackTest:
        d = {k: v for k, v in d.items() if k != "goal"}
        d["point"] = InjectionPoint(**d["point"])
        return AttackTest(**d)
