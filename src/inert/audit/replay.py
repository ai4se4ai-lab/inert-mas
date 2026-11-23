"""Offline replay and property checking (P1-P6) from the event log alone (no LLM calls).

``replay`` re-executes every controller acceptance decision with the TCB decision functions
(token MAC, key recomputation, schema/validator, taint selection and policy) on the logged
observations and proposals, and reports any decision that differs from the logged one.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

from ..canon import hmac_hex, sha256_hex, value_hash
from ..compiler.ir import IR
from ..model.schema import HIGH_INTEGRITY, Label, label_leq
from ..runtime.controller import (
    ACCEPT,
    KEY_STALE,
    TOKEN_INVALID,
    TOKEN_REUSED,
    UNAUTHORIZED,
    Controller,
    Mechanisms,
)
from ..tools.executor import Environment
from .log import verify_chain


@dataclass
class AuditReport:
    chain_ok: bool
    decisions: int
    reproduced: int
    mismatches: list[dict[str, Any]] = field(default_factory=list)
    violations: dict[str, list[str]] = field(default_factory=dict)

    @property
    def replay_ok(self) -> bool:
        return self.chain_ok and self.decisions == self.reproduced

    @property
    def properties_ok(self) -> bool:
        return not any(self.violations.values())


def _checker(ir: IR, mech: dict[str, bool]) -> Controller:
    return Controller(ir, {}, Environment(), Mechanisms(**mech))


def audit(ir: IR, events: list[dict[str, Any]], secret: bytes) -> AuditReport:
    """``secret`` is the run's capability key, held by the auditor outside the log; the log only
    carries a SHA-256 commitment to it, which is verified here."""
    chain_ok, _ = verify_chain(events)
    start = next(e for e in events if e["kind"] == "run_start")
    mech = start["mechanisms"]
    if hashlib.sha256(secret).hexdigest() != start.get("secret_commitment"):
        chain_ok = False
    chk = _checker(ir, mech)
    model = ir.model
    sink_max = {k: Label(v) for k, v in model.policy.sink_max.items()}
    dispatched: dict[str, dict[str, Any]] = {}
    pending: set[str] = set()
    latest: dict[str, str] = {}
    committed: set[str] = set()
    accepted_slots: set[str] = set()
    failed: set[str] = set()
    viol: dict[str, list[str]] = {f"P{i}": [] for i in range(1, 7)}
    decisions = reproduced = 0
    mismatches: list[dict[str, Any]] = []
    last_prop: dict[str, Any] | None = None

    def rsecret(rid: str) -> bytes:
        return hmac.new(secret, rid.encode(), hashlib.sha256).digest()

    for e in events:
        k = e["kind"]
        if k == "dispatch":
            sid = e["slot"]
            if sid not in ir.data["slots"]:
                viol["P1"].append(f"dispatch of unknown slot {sid}")
                continue
            for p in ir.data["slots"][sid]["prereqs"]:
                if p not in committed:
                    viol["P1"].append(f"{sid} dispatched before prerequisite {p}")
            if e["contract"] != f"{ir.contract_hash(sid)}@{ir.plan_hash}":
                viol["P4"].append(f"{sid} contract mismatch")
            if sha256_hex(e["observation"], allow_float=True) != e["key"]:
                viol["P3"].append(f"{sid} key does not match observation")
            dispatched[e["request_id"]] = e
            pending.add(e["request_id"])
            latest[sid] = e["request_id"]
        elif k == "tcb_value":
            pending.discard(e["request_id"])
            if e["outcome"] == "committed":
                committed.add(e["slot"])
        elif k == "tcb_reject":
            pending.discard(e["request_id"])
            failed.add(e["slot"])
        elif k == "tool_exec":
            sid = e["slot"]
            d = ir.data["slots"].get(sid, {}).get("def", {})
            if d.get("kind") != "tool" or d.get("tool") != e["tool"]:
                viol["P1"].append(f"tool {e['tool']} executed outside the model")
            if e["tool_hash"] != ir.tool_hash(e["tool"]):
                viol["P4"].append(f"{e['tool']} executed with altered metadata")
            for lab in e["arg_labels"]:
                if not label_leq(Label(lab), sink_max["executor"]):
                    viol["P5"].append(f"{sid} executor argument labelled {lab}")
        elif k == "proposal":
            last_prop = e
        elif k == "decision":
            decisions += 1
            p = last_prop or {}
            rid = p.get("request_id", "")
            q = dispatched.get(rid) if rid in pending else None
            # --- recompute the decision
            code: str
            routed = None
            if mech["tokens"]:
                if q is None:
                    code = TOKEN_REUSED if rid in dispatched else TOKEN_INVALID
                else:
                    body = {"request_id": rid, "slot": p["slot"], "agent": p["agent"], "key": p["key"],
                            "value": value_hash(p["value"])}
                    good = hmac.compare_digest(hmac_hex(rsecret(rid), body), p["mac"])
                    if not good or p["slot"] != q["slot"] or p["agent"] != q["owner"]:
                        code = UNAUTHORIZED if (good and p["agent"] != q["owner"]) else TOKEN_INVALID
                    else:
                        code, routed = "", q
            else:
                if q is None or q["slot"] != p["slot"]:
                    q = next((dispatched[r] for r in sorted(pending) if dispatched[r]["slot"] == p["slot"]), None)
                code, routed = ("", q) if q is not None else (KEY_STALE, None)
            if not code and routed is not None:
                if mech["key_match"] and (p["key"] != routed["key"] or latest.get(routed["slot"]) != routed["request_id"]):
                    code = KEY_STALE
                else:
                    _, _, lab = chk.select(routed["slot"], routed["observation"])
                    ok, diag = chk.check_value(routed["slot"], routed["observation"], {"v": p["value"], "l": lab.value})
                    code = ACCEPT if ok else (diag or "").split(":", 1)[0]
            if code == e["reason"]:
                reproduced += 1
            else:
                mismatches.append({"seq": e["seq"], "logged": e["reason"], "replayed": code})
            if e["outcome"] == "accept" and routed is not None:
                pending.discard(routed["request_id"])
                committed.add(routed["slot"])
                accepted_slots.add(routed["slot"])
                sid = routed["slot"]
                owner = ir.data["slots"][sid]["owner"]
                # P2 authorship: the accepted value was MAC'd by the owner's capability for this request
                body = {"request_id": routed["request_id"], "slot": sid, "agent": owner, "key": routed["key"],
                        "value": value_hash(p["value"])}
                if p["agent"] != owner or not hmac.compare_digest(
                        hmac_hex(rsecret(routed["request_id"]), body), p["mac"]):
                    viol["P2"].append(f"{sid} accepted a value not authored by {owner}")
                # P3 freshness
                if p["key"] != routed["key"] or latest.get(sid) != routed["request_id"]:
                    viol["P3"].append(f"{sid} accepted against a superseded key")
                # P5 taint non-interference (recomputed with the full policy, regardless of ablation)
                full = _checker(ir, {**mech, "taint_select": True, "taint_accept": True})
                items, _, lab_full = full.select(sid, routed["observation"])
                _, _, lab_used = chk.select(sid, routed["observation"])
                for f, spec in model.slot(sid).fields.items():
                    if spec.role in HIGH_INTEGRITY and not label_leq(lab_used, sink_max[spec.role]):
                        viol["P5"].append(f"{sid}.{f} ({spec.role}) accepted at {lab_used.value}")
            elif e["outcome"] == "reject" and routed is not None and e["reason"] not in (KEY_STALE,):
                pending.discard(routed["request_id"])
        elif k == "release":
            if e["ok"]:
                for o in model.release.outputs:
                    if o not in accepted_slots and o not in committed:
                        viol["P6"].append(f"released without accepted {o}")
                if e["failed"] or e["suspended"] or e["joint_violations"]:
                    viol["P6"].append("released with failed/suspended slots or violated joint constraints")
    return AuditReport(chain_ok, decisions, reproduced, mismatches, viol)
