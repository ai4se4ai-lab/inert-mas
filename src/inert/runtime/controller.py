"""M3 controller runtime: agents are untrusted proposers; the controller decides.

Built on the vendored guarded-coordination kernel (``kernel.GraphController``: exact
observations, request identities (job, episode, attempt), per-episode budget, upstream gate,
publication barrier). INERT adds:

* **dependency key** = SHA-256 of the kernel observation, which contains the *values and
  taint labels* of all read slots, the slot's contract hash (instruction, schema, validators,
  visible tool-metadata hashes) bound to the plan hash, and the owner;
* **capability tokens**: every request gets a secret derived by HMAC from a per-run key;
  only the authorised proposer receives it and must MAC (request, slot, agent, key, value);
  tokens are single use;
* **taint**: values are stored as envelopes ``{"v": value, "l": label}``; context selection
  withholds values whose label exceeds what the slot's high-integrity sinks allow, and the
  acceptance check rejects any sink whose label exceeds the policy;
* reason-coded, hash-chained logging of every decision for offline replay (``audit``).

Acceptance order (first failure wins, logged with a reason code):
  1 TOKEN  2 KEY  3 SCHEMA/VALIDATOR  4 TAINT
"""

from __future__ import annotations

import hashlib
import hmac
import random
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..audit.log import EventLog
from ..canon import hmac_hex, sha256_hex, value_hash
from ..compiler.ir import IR
from ..model.schema import HIGH_INTEGRITY, Declassifier, FieldSpec, Label, Validator, label_join, label_leq
from ..tools.executor import Environment
from .checks import check_schema, declassify, run_validator
from .kernel import GraphController, Job

SKIP = {"skipped": True}

# reason codes
ACCEPT = "ACCEPT"
TOKEN_INVALID = "TOKEN_INVALID"
TOKEN_REUSED = "TOKEN_REUSED"
UNAUTHORIZED = "UNAUTHORIZED_AGENT"
KEY_STALE = "KEY_STALE"
SCHEMA_INVALID = "SCHEMA_INVALID"
VALIDATOR_REJECT = "VALIDATOR_REJECT"
TAINT_VIOLATION = "TAINT_VIOLATION"
TOOL_METADATA_MISMATCH = "TOOL_METADATA_MISMATCH"
RECONFIG_REJECTED = "RECONFIG_REJECTED"
NO_PROPOSAL = "NO_PROPOSAL"


@dataclass(frozen=True)
class Mechanisms:
    """Ablation switches (I1 = taint off; I2 = everything on; I2-x = one switch off)."""

    tokens: bool = True
    key_match: bool = True
    validator: bool = True
    taint_select: bool = True
    taint_accept: bool = True

    @staticmethod
    def named(name: str) -> Mechanisms:
        return {
            "I2": Mechanisms(), "I1": Mechanisms(taint_select=False, taint_accept=False),
            "I2-tokens": Mechanisms(tokens=False), "I2-key": Mechanisms(key_match=False),
            "I2-validator": Mechanisms(validator=False), "I2-tsel": Mechanisms(taint_select=False),
            "I2-tacc": Mechanisms(taint_accept=False),
        }[name]


@dataclass
class ContextItem:
    ref: str
    label: str
    value: Any


@dataclass
class ProposalRequest:
    request_id: str
    slot: str
    agent: str
    key: str
    instruction: str
    persona: str
    role: str
    fields: dict[str, FieldSpec]
    context: list[ContextItem]
    withheld: list[str]
    feedback: str | None
    secret: bytes = field(repr=False)
    tool_docs: dict[str, str] = field(default_factory=dict)


@dataclass
class Proposal:
    request_id: str
    slot: str
    agent: str
    key: str
    value: Any
    mac: str
    meta: dict[str, Any] = field(default_factory=dict)   # llm usage, raw text (never trusted)


def sign(req: ProposalRequest, value: Any) -> Proposal:
    """Done by the agent *wrapper* holding the capability, not by the LLM."""
    body = {"request_id": req.request_id, "slot": req.slot, "agent": req.agent, "key": req.key,
            "value": value_hash(value)}
    return Proposal(req.request_id, req.slot, req.agent, req.key, value, hmac_hex(req.secret, body))


class Proposer(Protocol):
    def propose(self, req: ProposalRequest) -> Proposal | None: ...


class Adversary(Protocol):
    def unsolicited(self, ctl: Controller, req: ProposalRequest) -> list[Proposal]: ...
    def transport(self, p: Proposal) -> Proposal: ...
    def on_step(self, ctl: Controller, step: int) -> None: ...


@dataclass
class RunResult:
    released: bool
    outputs: dict[str, Any]
    values: dict[str, Any]
    labels: dict[str, str]
    log: EventLog
    failed_slots: list[str]
    reasons: dict[str, int]
    llm_calls: int
    prompt_tokens: int
    completion_tokens: int
    steps: int


def _key(observation: Any) -> str:
    return sha256_hex(observation, allow_float=True)


class Controller:
    def __init__(self, ir: IR, proposers: dict[str, Proposer], env: Environment, mech: Mechanisms | None = None,
                 seed: int = 0, adversary: Adversary | None = None, log: EventLog | None = None,
                 secret: bytes | None = None) -> None:
        self.ir = ir
        self.model = ir.model
        self.proposers = proposers
        self.env = env
        self.mech = mech or Mechanisms()
        self.adversary = adversary
        self.log = log or EventLog()
        self.rng = random.Random(seed)            # non-security randomness only
        # capability key: CSPRNG, independent of the replay seed; never written to the log
        self.run_secret = secret if secret is not None else secrets.token_bytes(32)
        self.used_requests: set[str] = set()
        self.reasons: dict[str, int] = {}
        self.llm_calls = self.prompt_tokens = self.completion_tokens = 0
        self.registered_agents: set[str] = {a.id for a in self.model.agents}
        sink_max = self.model.policy.sink_max
        self.sink_max = {k: Label(v) for k, v in sink_max.items()}
        self.slot_defs = {s.id: s for s in self.model.slots}
        self.kernel = self._build_kernel()

    # ----------------------------------------------------------------- kernel wiring
    def _contract(self, sid: str) -> str:
        return f"{self.ir.contract_hash(sid)}@{self.ir.plan_hash}"

    def _build_kernel(self) -> GraphController:
        jobs = []
        for sid in self.ir.order:
            sl = self.ir.data["slots"][sid]
            reader: Any = self._reader(sid) if sl["def"]["kind"] == "input" else None
            jobs.append(Job(id=sid, rank=sl["rank"], prereqs=tuple(sl["prereqs"]), owner=sl["owner"],
                            contract=self._contract(sid), reads=reader, validator=self._validator(sid)))
        rel = self.model.release
        return GraphController(jobs, inputs={}, budget=self.model.budget.max_attempts,
                               global_predicate=self._joint_ok if rel.joint_constraints else None)

    @staticmethod
    def _reader(sid: str) -> Callable[[dict[str, Any]], Any]:
        def read(inputs: dict[str, Any]) -> Any:
            return inputs.get(sid)
        return read

    def _joint_ok(self, _k: GraphController, values: dict[str, Any]) -> bool:
        ok, _ = self.joint_constraints(values)
        return ok

    def joint_constraints(self, values: dict[str, Any]) -> tuple[bool, list[str]]:
        bad: list[str] = []

        def get(ref: str) -> Any:
            s, _, f = ref.partition(".")
            env = values.get(s) or {}
            v = env.get("v") if isinstance(env, dict) else None
            return v.get(f) if isinstance(v, dict) and f else v

        for jc in self.model.release.joint_constraints:
            if jc.kind == "fields_equal" and jc.right is not None and get(jc.left) != get(jc.right):
                bad.append(f"{jc.left}!={jc.right}")
            if jc.kind == "not_contains" and jc.param and jc.param.lower() in str(get(jc.left)).lower():
                bad.append(f"{jc.left} contains {jc.param}")
        return not bad, bad

    # ----------------------------------------------------------------- selection / labels
    def select(self, sid: str, observation: dict[str, Any]) -> tuple[list[ContextItem], list[str], Label]:
        """Deterministic context selection from the immutable observation (replayable)."""
        s = self.slot_defs[sid]
        preds: dict[str, Any] = observation.get("prerequisites") or {}
        hi_roles = [f.role for f in s.fields.values() if f.role in HIGH_INTEGRITY]
        limit = min((self.sink_max[r] for r in hi_roles), key=lambda lab: list(Label).index(lab)) if hi_roles else None
        items: list[ContextItem] = []
        withheld: list[str] = []
        for ref in s.reads:
            src, _, fld = ref.partition(".")
            envl = preds.get(src)
            if not isinstance(envl, dict) or envl.get("v") == SKIP:
                continue
            lab = Label(envl["l"])
            val = envl["v"]
            if fld and isinstance(val, dict):
                val = val.get(fld)
            if self.mech.taint_select and limit is not None and not label_leq(lab, limit):
                withheld.append(ref)
                continue
            items.append(ContextItem(ref, lab.value, val))
        out = label_join(self.model.policy.agent_label, *[Label(i.label) for i in items])
        return items, withheld, out

    # ----------------------------------------------------------------- validation (step 3+4)
    def _validator(self, sid: str) -> Callable[[Any, Any], Any]:
        def v(observation: Any, envl: Any) -> Any:
            return self.check_value(sid, observation, envl)
        return v

    def check_value(self, sid: str, observation: dict[str, Any], envl: Any) -> tuple[bool, str | None]:
        s = self.slot_defs[sid]
        if s.kind != "agent":
            return True, None
        value = envl.get("v") if isinstance(envl, dict) else None
        if self.mech.validator:
            err = check_schema(dict(s.fields), value)
            if err:
                return False, f"{SCHEMA_INVALID}: {err}"
            items, _, _ = self.select(sid, observation)
            text = " ".join(str(i.value) for i in items)
            ctx = {i.ref: i.value for i in items}
            for val in s.validators:
                err = run_validator(val, value if isinstance(value, dict) else {}, text, ctx)
                if err:
                    return False, f"{VALIDATOR_REJECT}: {err}"
        elif not isinstance(value, dict):
            return False, f"{SCHEMA_INVALID}: not an object"
        if self.mech.taint_accept:
            _, _, lab = self.select(sid, observation)
            if envl.get("l") != lab.value:
                return False, f"{TAINT_VIOLATION}: envelope label mismatch"
            for f, spec in s.fields.items():
                if spec.role in HIGH_INTEGRITY and not label_leq(lab, self.sink_max[spec.role]):
                    return False, f"{TAINT_VIOLATION}: {f} ({spec.role}) carries {lab.value}"
        return True, None

    # ----------------------------------------------------------------- requests
    def request_secret(self, request_id: str) -> bytes:
        return hmac.new(self.run_secret, request_id.encode(), hashlib.sha256).digest()

    def _tool_docs(self, sid: str) -> dict[str, str]:
        docs = {}
        for spec in self.slot_defs[sid].fields.values():
            for v in spec.values or ():
                if v in self.ir.data["tools"]:
                    meta = self.ir.data["tools"][v]["meta"]   # from the IR, never the runtime registry
                    docs[v] = meta["description"]
        return docs

    def make_request(self, q: Any) -> ProposalRequest:
        s = self.slot_defs[q.job]
        items, withheld, _ = self.select(q.job, q.observation)
        agent = self.model.agent(s.owner or "")
        return ProposalRequest(request_id=q.identity, slot=q.job, agent=q.owner, key=_key(q.observation),
                               instruction=s.instruction, persona=agent.persona, role=agent.role,
                               fields=dict(s.fields), context=items, withheld=withheld, feedback=q.feedback,
                               secret=self.request_secret(q.identity), tool_docs=self._tool_docs(q.job))

    def _reason(self, code: str) -> str:
        self.reasons[code] = self.reasons.get(code, 0) + 1
        return code

    # ----------------------------------------------------------------- acceptance (steps 1+2)
    def submit(self, p: Proposal, origin: str = "agent") -> str:
        k = self.kernel
        self.log.append("proposal", request_id=p.request_id, slot=p.slot, agent=p.agent, key=p.key,
                        value=p.value, mac=p.mac, origin=origin)
        q = k.pending.get(p.request_id)
        if self.mech.tokens:
            if q is None:
                code = TOKEN_REUSED if p.request_id in k.history else TOKEN_INVALID
                return self._decide(p, code, None)
            body = {"request_id": p.request_id, "slot": p.slot, "agent": p.agent, "key": p.key,
                    "value": value_hash(p.value)}
            good = hmac.compare_digest(hmac_hex(self.request_secret(p.request_id), body), p.mac)
            if not good or p.slot != q.job or p.agent != q.owner:
                code = UNAUTHORIZED if (good and p.agent != q.owner) else TOKEN_INVALID
                return self._decide(p, code, None)
        else:
            # Ablation: no capability binding; anything addressed to a slot answers its pending request.
            if q is None or q.job != p.slot:
                q = next((r for r in k.pending.values() if r.job == p.slot), None)
            if q is None:
                return self._decide(p, KEY_STALE, None)
        if self.mech.key_match and (p.key != _key(q.observation) or not k._current(q)):
            return self._decide(p, KEY_STALE, q)
        # step 3+4 inside the kernel's optimistic commit (currentness rechecked atomically)
        _, _, lab = self.select(q.job, q.observation)
        envl = {"v": p.value, "l": lab.value}
        outcome, diag = k.resolve(q.identity, envl)
        self.used_requests.add(q.identity)
        if outcome == "committed":
            return self._decide(p, ACCEPT, q, label=lab.value)
        if outcome == "discarded":
            return self._decide(p, KEY_STALE, q)
        code = (diag or SCHEMA_INVALID).split(":", 1)[0]
        return self._decide(p, code, q, detail=diag)

    def _decide(self, p: Proposal, code: str, q: Any, label: str | None = None, detail: str | None = None) -> str:
        self._reason(code)
        self.log.append("decision", request_id=p.request_id, routed_to=q.identity if q is not None else None,
                        slot=p.slot, agent=p.agent, outcome="accept" if code == ACCEPT else "reject",
                        reason=code, detail=detail, label=label,
                        value_hash=value_hash(p.value) if code == ACCEPT else None)
        return code

    # ----------------------------------------------------------------- TCB-produced slots
    def _resolve_tcb(self, q: Any, envl: dict[str, Any], kind: str, **extra: Any) -> None:
        outcome, diag = self.kernel.resolve(q.identity, envl)
        self.log.append("tcb_value", request_id=q.identity, slot=q.job, source=kind, label=envl["l"],
                        value_hash=value_hash(envl["v"]), outcome=outcome, **extra)

    def _guard_false(self, sid: str, observation: dict[str, Any]) -> bool:
        g = self.slot_defs[sid].guard
        if g is None:
            return False
        envl = (observation.get("prerequisites") or {}).get(g.slot)
        if not isinstance(envl, dict) or envl.get("v") == SKIP:
            return True
        v = envl.get("v")
        return not (isinstance(v, dict) and v.get(g.field) == g.equals)

    def _run_tool(self, q: Any) -> None:
        s = self.slot_defs[q.job]
        tool = self.model.tool(s.tool or "")
        preds = q.observation.get("prerequisites") or {}
        args: dict[str, Any] = {}
        labels: list[Label] = []
        for a, src in s.args_from.items():
            if src.startswith("="):
                args[a] = src[1:]
                continue
            ss, _, fld = src.partition(".")
            envl = preds.get(ss) or {}
            val = envl.get("v")
            args[a] = val.get(fld) if isinstance(val, dict) and fld else val
            lab = Label(envl.get("l", Label.external_untrusted.value))
            role = tool.args[a].role if a in tool.args else "executor"
            if role != "data":
                labels.append(lab)
            if role in HIGH_INTEGRITY and self.mech.taint_accept and not label_leq(lab, self.sink_max[role]):
                self._reason(TAINT_VIOLATION)
                self._fail(q, TAINT_VIOLATION, f"argument {a} carries {lab.value}")
                return
        if self.mech.key_match and self.env.registry_hash(tool.name) != self.ir.tool_hash(tool.name):
            self._reason(TOOL_METADATA_MISMATCH)
            self._fail(q, TOOL_METADATA_MISMATCH, tool.name)
            return
        if any(v is None for v in args.values()):
            self._fail(q, SCHEMA_INVALID, "missing argument")
            return
        out, out_label = self.env.call(q.job, tool.name, args, tool.side_effect)
        lab = label_join(out_label, Label(tool.output_label), *labels) if tool.side_effect in ("none", "read") \
            else label_join(out_label, *labels)
        self.log.append("tool_exec", request_id=q.identity, slot=q.job, tool=tool.name, args=args,
                        tool_hash=self.env.registry_hash(tool.name), arg_labels=[x.value for x in labels])
        self._resolve_tcb(q, {"v": {"result": out}, "l": lab.value}, "tool")

    def _fail(self, q: Any, code: str, detail: str) -> None:
        self.log.append("tcb_reject", request_id=q.identity, slot=q.job, reason=code, detail=detail)
        self.kernel.resolve(q.identity, None, timeout=True)
        r = self.kernel.records[q.job]
        r.failed = True   # TCB rejections are deterministic: retrying cannot help

    def _run_declass(self, q: Any) -> None:
        s = self.slot_defs[q.job]
        d: Declassifier = s.declassifier  # type: ignore[assignment]
        src, _, fld = s.reads[0].partition(".")
        envl = (q.observation.get("prerequisites") or {}).get(src) or {}
        val = envl.get("v")
        text = val.get(fld) if isinstance(val, dict) else val
        ok, out = declassify(d, text)
        lab = d.to_label if ok else Label(envl.get("l", Label.external_untrusted.value))
        self.log.append("declassify", slot=q.job, dkind=d.kind, ok=ok, value=out, label=lab.value)
        self._resolve_tcb(q, {"v": {"value": out, "ok": ok}, "l": lab.value}, "declassify")

    # ----------------------------------------------------------------- reconfiguration (A5)
    def reconfigure(self, kind: str, payload: dict[str, Any]) -> str:
        """Runtime reconfiguration requests from untrusted parties are never applied: the plan
        is fixed by the compiled IR. Agent registration grants no slot (no tokens)."""
        if kind == "register_agent":
            self.log.append("reconfig", rkind=kind, payload=payload, outcome="registered-without-authority")
            return "registered-without-authority"
        self._reason(RECONFIG_REJECTED)
        self.log.append("reconfig", rkind=kind, payload=payload, outcome=RECONFIG_REJECTED)
        return RECONFIG_REJECTED

    # ----------------------------------------------------------------- main loop
    def run(self, inputs: dict[str, Any]) -> RunResult:
        k = self.kernel
        inp = {}
        for s in self.model.slots:
            if s.kind == "input":
                inp[s.id] = inputs.get(s.id)
        k.edit(inputs=inp)
        self.log.append("run_start", plan_hash=self.ir.plan_hash,
                        secret_commitment=hashlib.sha256(self.run_secret).hexdigest(),
                        mechanisms=self.mech.__dict__, inputs=inp)
        steps = 0
        for steps in range(1, self.model.budget.max_steps + 1):
            self.env.step = steps
            if self.adversary is not None:
                self.adversary.on_step(self, steps)
            elig = k.eligible()
            if not elig:
                break
            for jid in elig:
                q = k.dispatch(jid)
                if q is None:
                    continue
                s = self.slot_defs[jid]
                self.log.append("dispatch", request_id=q.identity, slot=jid, owner=q.owner,
                                key=_key(q.observation), contract=self._contract(jid), observation=q.observation,
                                prereq_labels={p: (v or {}).get("l") for p, v in
                                               (q.observation.get("prerequisites") or {}).items()})
                if s.kind == "input":
                    self._resolve_tcb(q, {"v": {"text": q.observation["source"]} if not isinstance(
                        q.observation["source"], dict) else q.observation["source"], "l": (s.label or Label.user).value},
                        "input")
                elif self._guard_false(jid, q.observation):
                    self._resolve_tcb(q, {"v": SKIP, "l": Label.trusted.value}, "skip")
                elif s.kind == "declassify":
                    self._run_declass(q)
                elif s.kind == "tool":
                    self._run_tool(q)
                else:
                    self._agent_step(q)
        values = k.values()
        failed = sorted(j for j in k.active if not k.usable(j) and k.records[j].failed)
        released = k.publishable()
        rel_ok, bad = self.joint_constraints(values)
        released = released and rel_ok and all(k.usable(o) for o in self.model.release.outputs)
        outputs = {o: (values.get(o) or {}).get("v") for o in self.model.release.outputs} if released else {}
        self.log.append("release", ok=released, outputs={o: value_hash(v) for o, v in outputs.items()},
                        failed=failed, suspended=sorted(k.suspended), joint_violations=bad)
        return RunResult(released, outputs, {j: (v or {}).get("v") for j, v in values.items()},
                         {j: str((v or {}).get("l")) for j, v in values.items()}, self.log, failed, dict(self.reasons),
                         self.llm_calls, self.prompt_tokens, self.completion_tokens, steps)

    def _agent_step(self, q: Any) -> None:
        req = self.make_request(q)
        self.log.append("request", request_id=q.identity, slot=q.job, agent=q.owner,
                        context=[{"ref": i.ref, "label": i.label, "hash": value_hash(i.value)} for i in req.context],
                        withheld=req.withheld)
        if self.adversary is not None:
            for p in self.adversary.unsolicited(self, req):
                if q.identity not in self.kernel.pending:
                    break
                self.submit(p, origin="unsolicited")
        if q.identity not in self.kernel.pending:
            return
        proposer = self.proposers.get(q.owner)
        got = proposer.propose(req) if proposer is not None else None
        if got is not None:
            p = got
            usage = p.meta.get("usage") or {}
            self.llm_calls += int(usage.get("calls", 0))
            self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self.completion_tokens += int(usage.get("completion_tokens") or 0)
        if got is None:
            self._reason(NO_PROPOSAL)
            self.log.append("tcb_reject", request_id=q.identity, slot=q.job, reason=NO_PROPOSAL, detail="")
            self.kernel.resolve(q.identity, None, timeout=True)
            return
        if self.adversary is not None:
            p = self.adversary.transport(p)
        self.submit(p)
        if q.identity in self.kernel.pending:
            # the proposal never reached a valid decision (e.g. a forged or tampered token): time out
            self.log.append("tcb_reject", request_id=q.identity, slot=q.job, reason="TIMEOUT", detail="")
            self.kernel.resolve(q.identity, None, timeout=True)


def validator_names(vs: tuple[Validator, ...]) -> list[str]:
    return [v.kind for v in vs]
