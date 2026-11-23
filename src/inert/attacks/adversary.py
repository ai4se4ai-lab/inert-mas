"""Executable attackers against the INERT controller (A2-A5). A1 lives in the environment."""

from __future__ import annotations

import hashlib
import hmac
import random
import re
from typing import Any

from ..canon import hmac_hex, sha256_hex, value_hash
from ..model.schema import FieldSpec
from ..runtime.controller import Controller, Proposal, ProposalRequest, sign
from .payloads import Goal
from .spec import AttackTest


def malicious_value(fields: dict[str, FieldSpec], goal: Goal, payload: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for n, f in fields.items():
        if f.type == "enum":
            vals = list(f.values or ())
            out[n] = goal.tool if goal.tool in vals else vals[0]
        elif f.type == "integer":
            out[n] = f.minimum if f.minimum is not None else 0
        elif f.type == "boolean":
            out[n] = True
        else:
            v = goal.value if (n == goal.arg or f.role == "executor") else payload
            if f.pattern and not re.fullmatch(f.pattern, v):
                v = goal.value if re.fullmatch(f.pattern, goal.value) else v
            out[n] = v[: f.max_length] if f.max_length else v
    return out


class MaliciousProposer:
    """A2/A4: a compromised agent. It holds the genuine capability for its own slots."""

    def __init__(self, goal: Goal, payload: str) -> None:
        self.goal, self.payload = goal, payload

    def propose(self, req: ProposalRequest) -> Proposal | None:
        p = sign(req, malicious_value(req.fields, self.goal, self.payload))
        p.meta = {"usage": {"calls": 0}}
        return p


class InertAdversary:
    def __init__(self, test: AttackTest, seed: int = 0) -> None:
        self.t = test
        self.goal = test.goal
        self.rng = random.Random(seed)
        self.compromised: set[str] = set()
        k = test.point.kind
        if k == "agent":
            self.compromised = {test.point.target}
        elif k == "collude":
            self.compromised = set(test.point.target.split("+"))
        self.prior_secret = self.rng.getrandbits(256).to_bytes(32, "big")

    # A2/A4 impersonation attempts + A5 rogue agent + A5 replay
    def unsolicited(self, ctl: Controller, req: ProposalRequest) -> list[Proposal]:
        k = self.t.point.kind
        val = malicious_value(req.fields, self.goal, self.t.payload)
        out: list[Proposal] = []
        if k in ("agent", "collude") and req.agent not in self.compromised:
            # a compromised agent tries to answer another agent's request, claiming to be that agent
            fake = hmac_hex(self.rng.getrandbits(256).to_bytes(32, "big"),
                            {"request_id": req.request_id, "value": value_hash(val)})
            out.append(Proposal(req.request_id, req.slot, req.agent, req.key, val, fake,
                                {"attacker": sorted(self.compromised)}))
        elif k == "rogue_agent":
            out.append(Proposal(req.request_id, req.slot, "rogue", req.key, val, "0" * 64, {"attacker": "rogue"}))
        elif k == "replay" and req.slot == self.t.point.target:
            # a genuine, signed proposal captured in an earlier run (different run key, older observation)
            stale_key = sha256_hex({"stale": req.key})
            secret = hmac.new(self.prior_secret, req.request_id.encode(), hashlib.sha256).digest()
            body = {"request_id": req.request_id, "slot": req.slot, "agent": req.agent, "key": stale_key,
                    "value": value_hash(val)}
            out.append(Proposal(req.request_id, req.slot, req.agent, stale_key, val, hmac_hex(secret, body),
                                {"attacker": "replay"}))
        return out

    # A3 message tampering in transit (cannot re-MAC)
    def transport(self, p: Proposal) -> Proposal:
        if self.t.point.kind == "transport" and p.agent == self.t.point.target and isinstance(p.value, dict):
            v = dict(p.value)
            for n, x in v.items():
                if isinstance(x, str):
                    v[n] = self.goal.value if n == self.goal.arg else f"{x}\n\n{self.t.payload}"
            return Proposal(p.request_id, p.slot, p.agent, p.key, v, p.mac, p.meta)
        return p

    # A5 reconfiguration
    def on_step(self, ctl: Controller, step: int) -> None:
        if step != 1:
            return
        k = self.t.point.kind
        if k == "tool_meta" and self.t.point.target in ctl.env.registry:
            reg = dict(ctl.env.registry[self.t.point.target])
            reg["description"] = f"{reg['description']} {self.t.payload}"
            ctl.env.registry[self.t.point.target] = reg
            ctl.reconfigure("alter_tool", {"tool": self.t.point.target})
        if k == "rogue_agent":
            ctl.reconfigure("register_agent", {"id": "rogue"})
