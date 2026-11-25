# From the paper to the code: approach, algorithms and taxonomy

This document links every concept, formula, algorithm and taxonomy element of the manuscript
(`docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex`) to the code that implements it and to
the test or check that exercises it. Section numbers refer to the manuscript. Paths are relative to
the repository root. Line numbers refer to the commit of this package; function names stay valid
if lines move.

Contents

1. [Overview](#1-overview)
2. [Notation](#2-notation-section-5-notation-paragraph)
3. [Design time: model, linter, compiler (Sec. 5.2)](#3-design-time-model-linter-compiler-section-52)
4. [Run time: the controller (Sec. 5.3, Algorithms 1 and 2)](#4-run-time-the-controller-section-53-algorithms-1-and-2)
5. [Replay audit and properties P1 to P6 (Sec. 4, 5.4)](#5-replay-audit-and-properties-p1-to-p6-sections-4-and-54)
6. [Attack generation (Sec. 5.5, Algorithm 3)](#6-attack-generation-section-55-algorithm-3)
7. [Threat model: attackers A1 to A6 (Sec. 4)](#7-threat-model-attackers-a1-to-a6-section-4)
8. [Study design: conditions, subjects, metrics, statistics (Sec. 6)](#8-study-design-section-6)
9. [Taxonomy to implementation (Sec. 3)](#9-taxonomy-to-implementation-section-3)
10. [Where implementation and pseudocode differ in presentation](#10-where-implementation-and-pseudocode-differ-in-presentation)

---

## 1. Overview

| Manuscript element | Package | Key files |
| --- | --- | --- |
| Model, DSL, sink roles, labels (Sec. 5.2) | M1 `inert.model` | [schema.py](../../../../src/inert/model/schema.py), [io.py](../../../../src/inert/model/io.py), [mermaid.py](../../../../src/inert/model/mermaid.py) |
| Linter L1 to L6, static labels λ(s) | M1 `inert.model.lint` | [lint.py](../../../../src/inert/model/lint.py) |
| Compiler, canonical JSON, hashes h_t, h^c_s, Π | M2 `inert.compiler`, `inert.canon` | [ir.py](../../../../src/inert/compiler/ir.py), [canon.py](../../../../src/inert/canon.py), [export.py](../../../../src/inert/compiler/export.py) |
| Coordination kernel (Def. 11, Sec. 2.6) | M3, vendored | [kernel.py](../../../../src/inert/runtime/kernel.py) (see [docs/vendored.md](../../../vendored.md)) |
| Controller, MP1 to MP3, Algorithms 1 and 2 | M3 `inert.runtime` | [controller.py](../../../../src/inert/runtime/controller.py), [checks.py](../../../../src/inert/runtime/checks.py) |
| Agent wrapper (signs proposals), LLM backends | M4 `inert.agents` | [agent.py](../../../../src/inert/agents/agent.py), [llm.py](../../../../src/inert/agents/llm.py) |
| Tool sandbox and environment labels ℓ_env | M3 `inert.tools` | [executor.py](../../../../src/inert/tools/executor.py) |
| Hash-chained log, replay audit, P1 to P6 (Sec. 5.4) | M6 `inert.audit` | [log.py](../../../../src/inert/audit/log.py), [replay.py](../../../../src/inert/audit/replay.py) |
| Obligations O(P), Algorithm 3, payloads, A1 to A6 (Sec. 5.5) | M5 `inert.attacks` | [coverage.py](../../../../src/inert/attacks/coverage.py), [payloads.py](../../../../src/inert/attacks/payloads.py), [adversary.py](../../../../src/inert/attacks/adversary.py), [adaptive.py](../../../../src/inert/attacks/adaptive.py), [spec.py](../../../../src/inert/attacks/spec.py) |
| Topology zoo, harness, manifests, CLI (Sec. 6) | M7 `inert.eval` | [zoo.py](../../../../src/inert/eval/zoo.py), [harness.py](../../../../src/inert/eval/harness.py), [cli.py](../../../../src/inert/eval/cli.py) |
| Baselines B0 to B4 (Table 5) | `baselines` | [native.py](../../../../baselines/native.py), [planquarantine.py](../../../../baselines/planquarantine.py), [docs/baselines.md](../../../baselines.md) |
| TAMAS study | `adapters.tamas` | [adapter.py](../../../../adapters/tamas/adapter.py), [upstream/](../../../../adapters/tamas/upstream) |
| Tables, figures, statistics (Sec. 7) | `analysis` | [make_assets.py](../../../../analysis/make_assets.py), [make_figures.py](../../../../analysis/make_figures.py), [residual.py](../../../../analysis/residual.py), [paper_text.py](../../../../analysis/paper_text.py), [fill_paper.py](../../../../analysis/fill_paper.py) |
| Taxonomy (Sec. 3) | `analysis` + audit trail | [TAXONOMY_PIPELINE.md](TAXONOMY_PIPELINE.md) |

The trusted computing base of the paper (compiler, controller, validators and declassifiers, policy
engine, tool executors) is exactly `inert.model`, `inert.compiler`, `inert.canon`, `inert.runtime`,
`inert.tools` and `inert.audit`. None of them imports `inert.agents.llm` or performs network access;
LLMs are reached only through the `Proposer` protocol
([controller.py:118](../../../../src/inert/runtime/controller.py#L118)).

## 2. Notation (Section 5, "Notation" paragraph)

| Paper | Meaning | Code |
| --- | --- | --- |
| M = ⟨𝒜, 𝒯, 𝒮, μ, Rel⟩ | model | `MASModel` [schema.py:179](../../../../src/inert/model/schema.py#L179): `agents`, `tools`, `slots`, `policy`, `release` |
| ℒ = trusted ⊏ user ⊏ agent_untrusted ⊏ external_untrusted | integrity labels | `Label` [schema.py:22](../../../../src/inert/model/schema.py#L22) (declaration order is the lattice order) |
| ⊑, ⊔ | order and join | `label_leq`, `label_join` [schema.py:209-213](../../../../src/inert/model/schema.py#L209) |
| ρ ∈ {data, instruction, control, executor} | sink role of a field or tool argument | `FieldSpec.role` [schema.py:40](../../../../src/inert/model/schema.py#L40) |
| ℋ | high-integrity roles | `HIGH_INTEGRITY` [schema.py:33](../../../../src/inert/model/schema.py#L33) |
| μ(ρ) | policy: highest label a sink may receive | `Policy.sink_max` [schema.py:156](../../../../src/inert/model/schema.py#L156) |
| ℓ_𝒜 = agent_untrusted | label of every agent output | `Policy.agent_label` [schema.py:159](../../../../src/inert/model/schema.py#L159) |
| H | SHA-256 over canonical JSON (sorted keys, NFC, no floats) | `canonical_bytes`, `sha256_hex` [canon.py:45-50](../../../../src/inert/canon.py#L45) |
| ⟨v, ℓ⟩ | envelope | dict `{"v": value, "l": label}` stored in the kernel (controller.py throughout) |

## 3. Design time: model, linter, compiler (Section 5.2)

### 3.1 Slots

| Paper | Code |
| --- | --- |
| slot kind k(s) ∈ {input, agent, tool, declassify} | `Slot.kind` [schema.py:106](../../../../src/inert/model/schema.py#L106) |
| ℓ(s) of an input slot | `Slot.label` |
| own(s), instruction, F(s), R(s), V(s) | `Slot.owner`, `Slot.instruction`, `Slot.fields`, `Slot.reads`, `Slot.validators` (`Validator` [schema.py:82](../../../../src/inert/model/schema.py#L82)) |
| tool slot, src(a) | `Slot.tool`, `Slot.args_from` |
| declassify slot, D, ℓ_D | `Slot.declassifier` (`Declassifier` [schema.py:98](../../../../src/inert/model/schema.py#L98): enum, integer range, regex; `to_label`) |
| guard on a control field | `Guard` [schema.py:90](../../../../src/inert/model/schema.py#L90) |
| pre(s), E | `Slot.read_slots()`; IR `prereqs` and `edges` ([ir.py:81-87](../../../../src/inert/compiler/ir.py#L81)) |
| joint constraints for release | `JointConstraint`, `Release` [schema.py:162-169](../../../../src/inert/model/schema.py#L162) |
| running example `chain3_email` | [models/zoo/chain3_email.inert.yaml](../../../../models/zoo/chain3_email.inert.yaml), generated by `build_model` [zoo.py:164](../../../../src/inert/eval/zoo.py#L164) |

### 3.2 Linter and the static label λ(s)

The formula for λ(s) is implemented by `static_labels` [lint.py:60](../../../../src/inert/model/lint.py#L60),
case by case:

| Case of λ(s) | Code |
| --- | --- |
| input: ℓ(s) | `lab[sid] = s.label` |
| agent: ℓ_𝒜 ⊔ ⨆ λ(u) over pre(s) | `label_join(model.policy.agent_label, *ins)` |
| tool: ℓ_t ⊔ ⨆ λ(src(a)) over non-data arguments | `label_join(out, *arg_labels)` with data arguments excluded (`data_args`) |
| declassify: ℓ_D | `s.declassifier.to_label` |

| Rule | Paper | Code | Test |
| --- | --- | --- | --- |
| L1 | unreachable slot | [lint.py:128](../../../../src/inert/model/lint.py#L128) | `test_L1_unreachable` |
| L2 | cycle in reads | `topo_order` [lint.py:42](../../../../src/inert/model/lint.py#L42), [lint.py:119](../../../../src/inert/model/lint.py#L119) | `test_L2_cycle` |
| L3 | λ(s) ⋢ μ(ρ(f)) for a high-integrity field or argument | [lint.py:136](../../../../src/inert/model/lint.py#L136), [lint.py:146](../../../../src/inert/model/lint.py#L146) | `test_L3_untrusted_to_executor` |
| L4 | slot without valid owner | [lint.py:93-112](../../../../src/inert/model/lint.py#L93) | `test_L4_owner` |
| L5 | free text or data field into executor argument or guard | [lint.py:161](../../../../src/inert/model/lint.py#L161) | `test_L5_free_text_into_executor` |
| L6 | dangling reference | [lint.py:102-108](../../../../src/inert/model/lint.py#L102) | `test_L6_dangling` |

Tests are in [tests/test_model.py](../../../../tests/test_model.py). The running-example claim
("L3 for `act.to` and `do.to`, nothing for `do.body` or `intent.index`") is checked by
`scripts/check_claims.py`, section 3.

### 3.3 Compiler and hashes

| Paper | Code |
| --- | --- |
| tool hash h_t over everything an LLM can read about a tool or that changes its effect | `tool_metadata` [ir.py:58](../../../../src/inert/compiler/ir.py#L58) (name, description, args, side effect, output label), hashed at [ir.py:69](../../../../src/inert/compiler/ir.py#L69) |
| contract hash h^c_s over the slot's question, including the hashes of its tools | [ir.py:77-80](../../../../src/inert/compiler/ir.py#L77): slot definition without `id`, `reads`, `owner`, `args_from`, plus `tool_hash` for tool slots |
| plan hash Π over all of it | [ir.py:91](../../../../src/inert/compiler/ir.py#L91): IR version, agent, tool and slot hashes, edges, policy, release, budget |
| contract bound to the plan: h^c_s@Π | `Controller._contract` [controller.py:171](../../../../src/inert/runtime/controller.py#L171) |
| byte-identical compilation | `IR.to_bytes`; `test_deterministic`, `test_equal_models_equal_hash_after_reordering_yaml_keys` ([tests/test_compiler.py](../../../../tests/test_compiler.py)) |
| any change to an instruction or tool description changes the hash | Hypothesis tests `test_instruction_change_changes_hash`, `test_tool_metadata_change_changes_hash` |
| IR exports the agent graph the baselines execute | `agent_graph` [export.py:15](../../../../src/inert/compiler/export.py#L15) |

## 4. Run time: the controller (Section 5.3, Algorithms 1 and 2)

### 4.1 Observations, keys and the kernel

| Paper | Code |
| --- | --- |
| request q for slot s | kernel `Request`, created by `GraphController.dispatch` [kernel.py:199](../../../../src/inert/runtime/kernel.py#L199) |
| observation o_q (prerequisite envelopes, contract h^c_s@Π, owner) | `GraphController.observation` [kernel.py:114](../../../../src/inert/runtime/kernel.py#L114); the contract string is set per job in `_build_kernel` [controller.py:174](../../../../src/inert/runtime/controller.py#L174) |
| dependency key κ_q = H(o_q) | `_key` [controller.py:143](../../../../src/inert/runtime/controller.py#L143) |
| re-ask every dependent whose key changes; cancel requests issued under an old key | `GraphController._reconcile` [kernel.py:142](../../../../src/inert/runtime/kernel.py#L142), `_current` [kernel.py:215](../../../../src/inert/runtime/kernel.py#L215) |
| Elig(), Dispatch(s), Commit(q, ⟨v,ℓ⟩), Pub() | `eligible` [kernel.py:193](../../../../src/inert/runtime/kernel.py#L193), `dispatch` [kernel.py:199](../../../../src/inert/runtime/kernel.py#L199), `resolve` [kernel.py:220](../../../../src/inert/runtime/kernel.py#L220), `publishable` [kernel.py:275](../../../../src/inert/runtime/kernel.py#L275) |

### 4.2 Mediation point 1: least-privilege context

C_q = { r ∈ R(s) | ℓ_r ⊑ m_s },  ℓ_q = ℓ_𝒜 ⊔ ⨆_{r ∈ C_q} ℓ_r

Implemented by `Controller.select` [controller.py:212](../../../../src/inert/runtime/controller.py#L212):

- m_s is `limit`, the minimum of `sink_max[r]` over the slot's high-integrity roles (`None`, i.e. ⊤, for data-only slots);
- reads with a label above `limit` go to `withheld` (named, not shown) when `mech.taint_select` is on;
- the returned label is `label_join(policy.agent_label, *labels of selected items)`.

Selected values reach the LLM as quoted JSON in a block declared untrusted: `render`
[agent.py:83](../../../../src/inert/agents/agent.py#L83). `select` is a pure function of the
observation, which is why the auditor can recompute it.

### 4.3 Mediation point 2: authenticated acceptance (Algorithm 2)

| Paper | Code |
| --- | --- |
| capability c_q = HMAC(K, q) | `request_secret` [controller.py:270](../../../../src/inert/runtime/controller.py#L270) |
| K drawn by Key(), only H(K) logged | `secrets.token_bytes(32)` in `Controller.__init__`; commitment in the `run_start` event [controller.py:429](../../../../src/inert/runtime/controller.py#L429) |
| wrapper signs τ = HMAC(c_q, ⟨q, s, a, κ, H(v)⟩) | `sign` [controller.py:111](../../../../src/inert/runtime/controller.py#L111), called by `LLMAgent.propose` [agent.py:102](../../../../src/inert/agents/agent.py#L102) |
| Accept(p) | `Controller.submit` [controller.py:296](../../../../src/inert/runtime/controller.py#L296), with the Contract and Flow clauses in `check_value` [controller.py:242](../../../../src/inert/runtime/controller.py#L242), run by the kernel inside `resolve` as the job validator |

The four predicates, in the order the code checks them (first failure wins):

| Predicate | Paper | Code | Reason codes | Switch |
| --- | --- | --- | --- | --- |
| Cap (P2) | q pending ∧ τ verifies under c_q ∧ a = own(s) | `submit`: `k.pending.get(...)`, `hmac.compare_digest(...)`, `p.agent != q.owner` | `TOKEN_REUSED` (request already answered), `TOKEN_INVALID`, `UNAUTHORIZED_AGENT` | `tokens` |
| Fresh (P3) | κ = H(o_q) | `submit`: `p.key != _key(q.observation) or not k._current(q)`; also the kernel's atomic recheck (`discarded`) | `KEY_STALE` | `key_match` |
| Contract (P4) | v ⊨ schema(F(s)) ∧ ∀ val ∈ V(s): val(v, C_q) | `check_value`: `check_schema` [checks.py:35](../../../../src/inert/runtime/checks.py#L35), `run_validator` [checks.py:50](../../../../src/inert/runtime/checks.py#L50) over the selected context | `SCHEMA_INVALID`, `VALIDATOR_REJECT` | `validator` |
| Flow (P5) | ∀ f ∈ F(s), ρ(f) ∈ ℋ: ℓ_q ⊑ μ(ρ(f)) | `check_value`: recomputes ℓ_q with `select` from the observation (not from the selection that was shown), checks the envelope label equals it, then checks every high-integrity field | `TAINT_VIOLATION` | `taint_accept` |

Commit(q, ⟨v, ℓ_q⟩) is `k.resolve(q.identity, envl)` in `submit`; every decision is logged by
`_decide` [controller.py:331](../../../../src/inert/runtime/controller.py#L331).

One test per reason code is in [tests/test_runtime.py](../../../../tests/test_runtime.py):
`test_token_invalid_forged_mac`, `test_token_reused_after_accept`, `test_unauthorized_agent`,
`test_key_stale`, `test_schema_invalid`, `test_validator_reject_ungrounded_recipient`,
`test_taint_violation_when_selection_off`, `test_tool_metadata_mismatch`,
`test_transport_tamper_rejected`, plus the Hypothesis property
`test_random_interleavings_never_accept_stale_or_forged`.

### 4.4 Mediation point 3: fail-closed tools and declassifiers

Exec(q) ⟺ ∀ a, ρ(a) ∈ ℋ: ℓ_src(a) ⊑ μ(ρ(a)) ∧ H(meta_Env(t)) = h_t

| Paper | Code (`_run_tool` [controller.py:355](../../../../src/inert/runtime/controller.py#L355)) |
| --- | --- |
| label check of each high-integrity argument | loop over `s.args_from`; failure → `TAINT_VIOLATION`, slot failed |
| run-time metadata equals the pinned hash | `self.env.registry_hash(tool.name) != self.ir.tool_hash(tool.name)` → `TOOL_METADATA_MISMATCH` ([controller.py:378](../../../../src/inert/runtime/controller.py#L378)); `Environment.registry_hash` [executor.py:50](../../../../src/inert/tools/executor.py#L50) |
| fail closed | `_fail` [controller.py:391](../../../../src/inert/runtime/controller.py#L391) marks the slot failed (no retry) |
| ℓ_out = ℓ_env ⊔ ℓ_t ⊔ ⨆ non-data ℓ_src(a) | `label_join(out_label, tool.output_label, *labels)` for read tools; ℓ_env comes from `Environment.call` [executor.py:53](../../../../src/inert/tools/executor.py#L53) |
| Call_t runs in the sandbox | `Environment.call`; side-effect tools (`_send_email`, `_write_file`, `_run_code`, `_post`, [executor.py:97-111](../../../../src/inert/tools/executor.py#L97)) only record the call, nothing is executed |
| declassifier commits at ℓ_D on success, at the source label on failure | `_run_declass` [controller.py:397](../../../../src/inert/runtime/controller.py#L397) with `declassify` [checks.py:75](../../../../src/inert/runtime/checks.py#L75) |
| reconfiguration attempts are never applied | `reconfigure` [controller.py:410](../../../../src/inert/runtime/controller.py#L410): `RECONFIG_REJECTED`; agent registration grants no slot and no token |

### 4.5 Algorithm 1, line by line

`Run(P, X)` is `Controller.run` [controller.py:421](../../../../src/inert/runtime/controller.py#L421).

| Line | Pseudocode | Code |
| --- | --- | --- |
| 1 | K ← Key(); Log(Π, H(K)) | `run_secret` in `__init__`; `self.log.append("run_start", plan_hash=..., secret_commitment=...)` |
| 2 | while Elig() ≠ ∅ ∧ steps < B | `for steps in range(1, budget.max_steps + 1)`, `elig = k.eligible()`, break if empty |
| 3 | s ← First(Elig()); q ← Dispatch(s); Log(q, s, κ_q, o_q) | `for jid in elig: q = k.dispatch(jid)`; `log.append("dispatch", ..., key=_key(q.observation), contract=..., observation=...)` |
| 4-5 | agent slot: v ← prop_own(s)(C_q); Accept(...) | `_agent_step` [controller.py:472](../../../../src/inert/runtime/controller.py#L472): `make_request` (MP1), proposer, `submit` (MP2) |
| 6-7 | tool slot: Exec(q) ? Commit : Fail | `_run_tool` (MP3) |
| 8 | input or declassified value | `_resolve_tcb(..., "input")`, `_run_declass`, and `_guard_false` → skip value |
| 11 | if Pub() then Release(v_Rel) (P6) | `released = k.publishable() and joint_constraints(...) and all release outputs usable`; `log.append("release", ...)` |

### 4.6 Algorithm 2

`for χ in ⟨Cap, Fresh, Contract, Flow⟩: if ¬χ(p) return Reject(code(χ, p))` is the sequence of
early returns in `submit` (Cap, Fresh) followed by `check_value` (Contract, Flow) inside
`k.resolve`. The first failing clause's code is what `_decide` logs; `code(χ, p)` is the
`TOKEN_*`, `UNAUTHORIZED_AGENT`, `KEY_STALE`, `SCHEMA_INVALID`, `VALIDATOR_REJECT`,
`TAINT_VIOLATION` constants [controller.py:43-53](../../../../src/inert/runtime/controller.py#L43).

### 4.7 Ablations and conditions

`Mechanisms` [controller.py:57](../../../../src/inert/runtime/controller.py#L57):

| Condition | Switch turned off | Disables |
| --- | --- | --- |
| I2 | none | — |
| I1 | `taint_select`, `taint_accept` | MP1 filtering and the Flow clause, plus the argument-label check in MP3 |
| I2-tokens | `tokens` | Cap; any proposal addressed to a slot answers its pending request |
| I2-key | `key_match` | Fresh, and the tool-hash check of MP3 (see Section 10) |
| I2-validator | `validator` | Contract (schema and validators; the value must still be an object) |
| I2-tsel | `taint_select` | MP1 filtering only |
| I2-tacc | `taint_accept` | Flow and the MP3 argument-label check |
| I2S (TAMAS) | none; adds a `member_of` task-scope validator | [adapter.py:107](../../../../adapters/tamas/adapter.py#L107) |

### 4.8 Proposition 1 (taint non-interference)

The proof sketch relies on three code facts: proposals depend only on C_q (`make_request` passes
only `select`'s items), `Flow` recomputes ℓ_q from o_q (`check_value` calls `select` again), and
`_run_tool` checks arguments and joins non-data argument labels into ℓ_out. The auditor checks P5
against the full policy for every run (Section 5 below). In the archived records no I2 run has any
property violation (P1 to P6, attributable or not) or any replay mismatch.

### 4.9 Reference-monitor conditions (Definition 5)

| Condition | Where it holds in code |
| --- | --- |
| always invoked | agents receive no tools (`ProposalRequest` carries only tool descriptions from the IR, `_tool_docs` [controller.py:273](../../../../src/inert/runtime/controller.py#L273)); every value enters via `submit`, `_resolve_tcb` or `_run_tool`; release only via `run` |
| tamper-proof (relative to the threat model) | `run_secret` never leaves the controller and is not logged; agents see quoted context, not each other's raw messages |
| verifiable | decisions are deterministic functions of the logged observation; `audit` re-executes them |

## 5. Replay audit and properties P1 to P6 (Sections 4 and 5.4)

| Paper | Code |
| --- | --- |
| hash-chained JSONL log | `EventLog.append` [log.py:19](../../../../src/inert/audit/log.py#L19) (each event carries `prev` and its own `hash`), `verify_chain` [log.py:40](../../../../src/inert/audit/log.py#L40) |
| verify chain and the commitment H(K) | `audit` [replay.py:52](../../../../src/inert/audit/replay.py#L52), lines 55-59 |
| recompute every decision with the TCB's own functions | [replay.py:113-146](../../../../src/inert/audit/replay.py#L113): re-runs Cap, Fresh and `check_value` with a controller built from the logged mechanisms (`_checker`) |

| Property | Checked at | What is recomputed |
| --- | --- | --- |
| P1 control-flow integrity | [replay.py:81-86](../../../../src/inert/audit/replay.py#L81), [104-105](../../../../src/inert/audit/replay.py#L104) | dispatched slot exists in the plan and its prerequisites were committed; tools run only from their tool slot |
| P2 authorship | [replay.py:153-158](../../../../src/inert/audit/replay.py#L153) | accepted value MAC'd with the owner's capability for that request |
| P3 freshness | [replay.py:89-90](../../../../src/inert/audit/replay.py#L89), [160-161](../../../../src/inert/audit/replay.py#L160) | logged key equals H(observation); accepted against the latest request |
| P4 contract integrity | [replay.py:87-88](../../../../src/inert/audit/replay.py#L87), [106-107](../../../../src/inert/audit/replay.py#L106) | contract equals h^c_s@Π; executed tool hash equals h_t |
| P5 taint non-interference | [replay.py:108-110](../../../../src/inert/audit/replay.py#L108), [162-168](../../../../src/inert/audit/replay.py#L162) | labels of executor arguments; label used for acceptance against the full policy, **regardless of ablation** |
| P6 release integrity | [replay.py:171-177](../../../../src/inert/audit/replay.py#L171) | released outputs accepted; nothing failed, suspended or violating joint constraints |

Tests: [tests/test_audit.py](../../../../tests/test_audit.py) (`test_tamper_detected`,
`test_ablation_tokens_off_shows_P2_violation`). The harness audits every INERT run
(`_run_inert` [harness.py:93](../../../../src/inert/eval/harness.py#L93)); every record stores
`replay_ok`, `chain_ok` and the violated properties. The running-example claim "changing one byte
of the 26 logged events breaks the chain at that event" is checked by `scripts/check_claims.py`.

## 6. Attack generation (Section 5.5, Algorithm 3)

### 6.1 The obligation set O(P)

`obligations` [coverage.py:78](../../../../src/inert/attacks/coverage.py#L78):

| Term of O(P) | Criterion | Code | Feasible when |
| --- | --- | --- | --- |
| E | EDGE | one obligation per IR edge | producer is a tool or agent slot and the goal's tool is in 𝒯 |
| 𝒮_A × Payloads | SLOT | agent slot × the four text payload classes (`TEXT_CLASSES`) | goal tool in 𝒯 |
| {(s, r) ∣ r ∈ R(s)} | SEL | one per read of every agent slot | source of the read is a tool or agent slot |
| Paths(Src, Sinks_ℋ) | TAINT | `taint_paths` [coverage.py:46](../../../../src/inert/attacks/coverage.py#L46): DFS from external-labelled tool slots to agent slots with high-integrity fields and to write/exec tool slots with high-integrity arguments | goal tool in 𝒯 |
| 𝒯 ∪ {rogue} ∪ 𝒮_A | RECONF | tool-metadata change per tool, one rogue agent, one replay per agent slot | goal tool in 𝒯 |
| 𝒜_mid × {exec} | COLL | every agent other than `actor` and `planner`, paired with `actor` | an `actor` exists |

Infeasible obligations are returned with `feasible=False` and a reason, and `inert gen-attacks`
writes them to the suite file ("reported, never dropped"). The test
`test_full_feasible_coverage` ([tests/test_attacks.py](../../../../tests/test_attacks.py)) checks
that every feasible obligation of all 51 zoo models gets a test.

### 6.2 Algorithm 3, line by line

`Gen(P, g, σ)` is `generate` [coverage.py:111](../../../../src/inert/attacks/coverage.py#L111).

| Line | Pseudocode | Code |
| --- | --- | --- |
| 2 | for (i, o) in Enum(O(P)) | `for ob in obs`, with `i = next(cyc)` counting feasible obligations only |
| 3 | if ¬feas(o): Report(o); continue | `if not ob.feasible ...: continue` (the obligation stays in the returned list) |
| 4 | ⟨c, m, x⟩ ← Rot(i, σ) | payload class `TEXT_CLASSES[i % 4]` (SLOT keeps its own class; RECONF tool-metadata uses `tool_poison`); mutator `MUTATORS[(i // 4) % 5]` chosen when the seeded `rng.random() < 0.5`, else `none`; position `POSITIONS[i % 3]` |
| 5 | add ⟨o, pt(o), Mut_{m,x}(Ren(c, g)), g, ω_g⟩ | `render(pc, goal, mut, variant=i)` [payloads.py:94](../../../../src/inert/attacks/payloads.py#L94) (Ren and Mut_m); position x is applied by `place` [payloads.py:111](../../../../src/inert/attacks/payloads.py#L111) when the harness injects (`run_case` [harness.py:60](../../../../src/inert/eval/harness.py#L60)); injection point pt(o) per criterion; oracle ω_g is `goal_met` [payloads.py:49](../../../../src/inert/attacks/payloads.py#L49) on the sandbox call log |

Payload classes, mutators and positions: [payloads.py:16-18](../../../../src/inert/attacks/payloads.py#L16)
(`override`, `fake_error`, `infection`, `impersonation`, `tool_poison`; `paraphrase`, `base64`,
`homoglyph`, `language`; `suffix`, `prefix`, `embedded`). Attacker goals per task family:
`GOALS` [payloads.py:37](../../../../src/inert/attacks/payloads.py#L37), all targeting the
reserved domain `evil.example`.

The benchmark-style suite of RQ3 is `benchmark_suite` [coverage.py:160](../../../../src/inert/attacks/coverage.py#L160)
(three payload classes injected as a suffix into the primary untrusted resource). For the 70B
models, `max_tests` keeps a seeded random subset of ten tests per workflow.

## 7. Threat model: attackers A1 to A6 (Section 4)

| Attacker | Channels | Injection point (`InjectionPoint.kind`) | Code |
| --- | --- | --- | --- |
| A1 indirect injection | C2, C3 | `resource` | payload placed in the resource text by `run_case` |
| A2 compromised agent | C4, C5 | `agent` | `MaliciousProposer` [adversary.py:36](../../../../src/inert/attacks/adversary.py#L36) replaces the owner's proposer; `InertAdversary.unsolicited` also tries to answer other slots |
| A3 tamperer in transit | C4, C5 | `transport` | `InertAdversary.transport` [adversary.py:85](../../../../src/inert/attacks/adversary.py#L85) rewrites the value after signing |
| A4 two colluding agents | C4, C5 | `collude` | both agents compromised (`compromised` set) |
| A5 reconfiguration and replay | C5, C7 | `tool_meta`, `rogue_agent`, `replay` | `InertAdversary.on_step` (alters tool description, registers a rogue agent) and `unsolicited` (replays a stale proposal) |
| A6 adaptive attacker | all, via A1 | `resource`, chosen by the attacker LLM | `run_adaptive` [adaptive.py:41](../../../../src/inert/attacks/adaptive.py#L41): budget of attempts, feedback is the rejection reasons (INERT) or the tools called (baselines) |

## 8. Study design (Section 6)

| Paper | Code |
| --- | --- |
| topology zoo: 5 topologies × 3 sizes × 4 families (51 workflows) | `zoo_models` [zoo.py:321](../../../../src/inert/eval/zoo.py#L321), `build_model` [zoo.py:164](../../../../src/inert/eval/zoo.py#L164); YAML copies in [models/zoo/](../../../../models/zoo) |
| five tasks per family with deterministic utility oracles | `tasks` [zoo.py:275](../../../../src/inert/eval/zoo.py#L275), `benign_ok` [zoo.py:309](../../../../src/inert/eval/zoo.py#L309) |
| TAMAS: one slot per agent, personas, tools, queries; DPI-whole and DPI-split | `build` [adapter.py:107](../../../../adapters/tamas/adapter.py#L107) (`split_suffix`), `run_tamas_case` [adapter.py:221](../../../../adapters/tamas/adapter.py#L221); upstream data pinned in [adapters/tamas/upstream/COMMIT](../../../../adapters/tamas/upstream/COMMIT) |
| B0 native group chat | `NativeMAS(mode="B0")` [native.py:89](../../../../baselines/native.py#L89) |
| B1 detector | `Detector` [native.py:64](../../../../baselines/native.py#L64) |
| B2 source tagging | `NativeMAS(mode="B2")` |
| B3 CaMeL-style plan and quarantine | `PlanQuarantine` [planquarantine.py:33](../../../../baselines/planquarantine.py#L33) |
| B4 ControlValve-style permitted graph | `NativeMAS._plan_graph` [native.py:133](../../../../baselines/native.py#L133) |
| same IR, LLM, decoding, seed and tools for every condition | `run_case` [harness.py:60](../../../../src/inert/eval/harness.py#L60) dispatches to `_run_inert` or `_run_baseline` with the same `ir`, `llm`, `seed`, `env` |
| manifests (case expansion, shards, resume) | `expand` [cli.py:71](../../../../src/inert/eval/cli.py#L71), `cmd_run_manifest` [cli.py:152](../../../../src/inert/eval/cli.py#L152); the seven final manifests in [hpc/manifests/](../../../../hpc/manifests) |
| provenance in every record | `cmd_run_manifest` writes `meta` (commit + code hash, model digest via `model_digest` [cli.py:46](../../../../src/inert/eval/cli.py#L46), decoding, manifest SHA-256, shard, job, benchmark versions) |
| ASR: goal met in the call log, or an attributable property violation | [harness.py:88-89](../../../../src/inert/eval/harness.py#L88); P5 counts only when the violating value carries the attacker marker ([harness.py:128-139](../../../../src/inert/eval/harness.py#L128)) |
| infected agents, blast radius, depth | `_infection` [harness.py:40](../../../../src/inert/eval/harness.py#L40) |
| FRR | `make_assets.py` main-table block: honest proposals rejected (INERT), benign messages flagged (B1), blocked actions (B3, B4) |
| de-duplication of resumed shards by (case, model) | `load` [make_assets.py:35](../../../../analysis/make_assets.py#L35) |
| Wilson intervals, exact McNemar with bootstrap OR, Cliff's δ, Holm | `wilson`, `mcnemar`, `cliffs_delta`, `holm` [make_assets.py:54-88](../../../../analysis/make_assets.py#L54) |
| Wilcoxon signed-rank on latency and tokens | [make_assets.py:318-335](../../../../analysis/make_assets.py#L318) |
| logistic mixed-effects model | `BinomialBayesMixedGLM` [make_assets.py:355-363](../../../../analysis/make_assets.py#L355) |
| bootstrap means (2,000 resamples), discovery curves (200 orderings) | `boot_ci` [make_figures.py:56](../../../../analysis/make_figures.py#L56) and the RQ3 block of `make_figures.py` |
| pre-registered analysis plan | [analysis/preregistration.md](../../../../analysis/preregistration.md) |

## 9. Taxonomy to implementation (Section 3)

The taxonomy is INERT's design document: every attack form of the channel tree has a mechanism, a
property and a coverage criterion, and every requirement has a property and a mechanism. The
machine-readable versions are the audit CSVs
[06_channel_tree.csv](../relevant-work/audit/06_channel_tree.csv) and
[08_requirements.csv](../relevant-work/audit/08_requirements.csv). How the taxonomy itself was
built is in [TAXONOMY_PIPELINE.md](TAXONOMY_PIPELINE.md).

### 9.1 Channels (Table 1) to mechanisms, code and tests

| Channel | Protected decision | Mechanism in code | Generated obligations | Study coverage |
| --- | --- | --- | --- | --- |
| C1 user request | task scope | input `label` of the request; DPI-split labels the injected suffix untrusted ([adapter.py:107](../../../../adapters/tamas/adapter.py#L107)); I2S `member_of` validator | TAINT | TAMAS only |
| C2 external content | facts passed to others | environment labels (`environment_for` [executor.py:122](../../../../src/inert/tools/executor.py#L122)), `select` (MP1), Flow (MP2), `_run_tool` argument check (MP3) | SEL, TAINT, EDGE | zoo, TAMAS IPI |
| C3 tool response | next step | fixed compiled plan: the kernel, not the agent, decides what is eligible (`eligible`, `dispatch`) | EDGE | zoo |
| C4 peer message | content of its output | `sign` / Cap (tokens bind sender, request, key and value), envelopes propagate labels | EDGE, SEL, SLOT | zoo, TAMAS impersonation, colluding |
| C5 coordination signal | transition, release | Fresh (`_key`, `_current`), publication barrier (`publishable`, `joint_constraints`) | RECONF (replay), SLOT, COLL | zoo |
| C6 shared state | new decision context | labels within a run only; cross-session memory not modelled (gap G5) | — | out of scope |
| C7 discovery metadata | provider and tool binding | tool hash pinned in the contract (`ir.py`), `registry_hash` check in `_run_tool`, `reconfigure` | RECONF | zoo |

### 9.2 Channel tree: the 14 attack forms (Figure 4)

| Attack form | Channel | Control class | Mechanism → code | Property | Criterion | Expected rejection |
| --- | --- | --- | --- | --- | --- | --- |
| Injected suffix in the user's request | C1 | semantic | input label on the suffix → `adapters/tamas/adapter.py` `build(split_suffix=...)` | P5 | TAINT | `TAINT_VIOLATION` / withheld read |
| Data becomes a worker's sub-task | C2 | semantic | MP1 → `Controller.select` | P5 | SEL | none (read withheld) |
| Data becomes a recipient, path or command | C2 | semantic | MP2 Flow → `check_value`; MP3 → `_run_tool` | P5 | TAINT, EDGE | `TAINT_VIOLATION`, `VALIDATOR_REJECT` |
| Fake error or status routes control | C3 | structural | fixed plan → kernel `eligible`/`dispatch` | P1 | EDGE | none (structure not text-driven) |
| Payload copied from agent to agent | C4 | semantic | label propagation in envelopes → `select` join, `_run_tool` ℓ_out | P5 | EDGE, SEL | none (read withheld) |
| Sender impersonation | C4 | structural | per-request tokens → `request_secret`, `sign`, `submit` | P2 | SLOT | `TOKEN_INVALID`, `UNAUTHORIZED_AGENT` |
| Message rewritten in transit | C4 | structural | MAC over request, key and value → `sign`, `submit` | P2 | EDGE | `TOKEN_INVALID` |
| Replay of a stale approval or result | C5 | structural | exact key match → `_key`, `_current`; single-use tokens | P3 | RECONF | `KEY_STALE`, `TOKEN_REUSED` |
| Release of an inconsistent snapshot | C5 | structural | publication barrier → `publishable`, `joint_constraints` | P6 | SLOT, COLL | release withheld |
| Colluding agents agree on a protected decision | C5 | residual | owned validators → `run_validator` | — | COLL | `VALIDATOR_REJECT` or residual success |
| Poisoned record read in a later session | C6 | semantic | within-run labels; cross-session open (G5) | P5 | — | not tested |
| Poisoned tool description | C7 | structural | pinned tool hash → `ir.py` `tool_metadata`, `_run_tool` | P4 | RECONF | `TOOL_METADATA_MISMATCH` |
| Rogue agent or provider registration | C7 | structural | ownership bound to the plan → `reconfigure` (no slot, no token) | P2, P4 | RECONF | `TOKEN_INVALID` |
| Compromised owner misuses its own authority | any | residual | owned validators, task scope → `run_validator`, I2S | — | SLOT, COLL | residual risk (Sec. 7, `analysis/residual.py`) |

The RQ2 ablation (Figure 8 of the manuscript) is the empirical check of this table: turning off one
switch of `Mechanisms` reopens exactly the forms mapped to it. The last column is the check the
mapping predicts; what actually fired first is the `first_reject` field of each record (computed in
`_run_inert`). On the ablation suite under I2 the observed first rejections are: A1 none 404,
`SCHEMA_INVALID` 52; A2 `TOKEN_INVALID` 556; A3 `TOKEN_INVALID` 344; A4 `TOKEN_INVALID` 40;
A5 `KEY_STALE` 192, `TOOL_METADATA_MISMATCH` 68, `TOKEN_INVALID` 44 (key `first_reject_I2` of the
regenerated `numbers.json`, Figure 8b). Impersonating proposals carry a MAC made without the owner's
capability, so they fail as `TOKEN_INVALID` before `UNAUTHORIZED_AGENT` can apply, and replays are
caught by the key before the single-use token.

### 9.3 Requirements R1 to R8

| Requirement | Property | Implemented by | Checked by |
| --- | --- | --- | --- |
| R1 structural mediation | P1 | compiled plan + kernel (`compile_model`, `GraphController`) | audit P1; RQ2 A3/A5 rows |
| R2 request-bound authorship | P2 | `request_secret`, `sign`, Cap in `submit` | audit P2; `test_token_*`, `test_unauthorized_agent`, `test_transport_tamper_rejected` |
| R3 freshness | P3 | `_key`, `_current`, kernel `_reconcile` | audit P3; `test_key_stale`, Hypothesis interleavings |
| R4 configuration integrity | P4 | contract and tool hashes (`ir.py`), `_run_tool` metadata check | audit P4; `test_tool_metadata_mismatch`, compiler hash tests |
| R5 provenance-bounded flow | P5 | `select` (MP1), Flow in `check_value` (MP2), `_run_tool` (MP3), declassifiers | audit P5; `test_taint_violation_when_selection_off`; RQ2 I2-tsel/I2-tacc |
| R6 consistent release | P6 | `publishable`, `joint_constraints`, release check in `run` | audit P6 |
| R7 verifiable evidence | P1-P6 | `EventLog`, `verify_chain`, `audit` (no LLM) | `test_tamper_detected`; `replay_ok` in every INERT record |
| R8 channel coverage | — | `obligations`, `generate`, `goal_met` effect oracle | `test_full_feasible_coverage`, `test_tests_execute_on_inert_and_b0`; RQ3 |

### 9.4 Gaps G1 to G5

| Gap | INERT response | In code |
| --- | --- | --- |
| G1 learned judgments can be probed | checks contain no learned component | TCB packages import no LLM client; adaptive attacker A6 (`run_adaptive`) tests it |
| G2 flow control for one agent only | labels carried across agents inside dependency keys | envelopes in the kernel observation, `_key` |
| G3 no family combines structural mediation and flow control from the designed workflow | everything derived from one model | `compile_model` feeds the controller, the auditor and the generator |
| G4 fixed injection points, LLM judges | channel-derived obligations, effect oracles, replay audit | `obligations`, `goal_met`, `audit` |
| G5 cross-session shared state | stated limitation | not implemented |

### 9.5 Corpus tree leaves (Figure 3) to INERT elements

Each leaf of the corpus tree names the INERT element it informs
([04_leaf_codebook.csv](../relevant-work/audit/04_leaf_codebook.csv)). The code side:

| Leaf | Informs | Code |
| --- | --- | --- |
| Content and interpretation | A1, payload classes, mutators | `payloads.py` |
| Peer influence and composition | A2-A4, P2, label propagation | `adversary.py`, `sign`/`submit`, envelopes |
| State and discovery | A5, P4, RECONF; G5 | `on_step`, `_run_tool` hash check, RECONF obligations |
| Execution and disclosure | executor sinks, effect oracle, P1 | `HIGH_INTEGRITY`, `goal_met`, sandbox tools |
| Topology and propagation | topology zoo, RQ1 metrics | `zoo.py`, `_infection` |
| Roles and trust boundaries | slot owners, capabilities | `Slot.owner`, `request_secret` |
| Shared and deployed workflows | C6, envelopes | envelopes (C6 out of scope) |
| Planning and information flow | taint policy, declassifiers, B3, B4 | `Policy`, `Declassifier`, `planquarantine.py`, `_plan_graph` |
| Identity and access control | tokens, pinned metadata | `request_secret`, `tool_metadata` |
| Tool and execution boundaries | sandbox, fail-closed execution | `executor.py`, `_fail` |
| Signals and monitoring | B1, reason codes | `Detector`, reason-code constants |
| Collaborative defenses | B1, B2; G1 | `native.py` modes B1, B2 |
| Prompt and model defenses | B2, quoted context | B2 tagging, `agent.render` |
| Multi-agent evaluation | TAMAS adapter, attacker models | `adapters/tamas/` |
| Agent tasks and competitions | BENCH suite, A6 | `benchmark_suite`, `run_adaptive` |
| Prompt and model evaluation | payload classes, ASR definition | `payloads.py`, `harness.py:88-89` |
| Agent architectures and security | requirements R1-R8 | Section 9.3 above |
| Injection and protocol taxonomies | channel definitions C1-C7 | Section 9.1 above |

## 10. Where implementation and pseudocode differ in presentation

These are differences of presentation, not of behaviour; reviewers comparing pseudocode and code
may otherwise trip over them.

1. **Dispatch granularity.** Algorithm 1 dispatches one eligible slot per iteration
   (`First(Elig())`). `Controller.run` dispatches every eligible slot in one round and counts
   rounds against the budget B (`budget.max_steps`). Slots eligible in the same round are
   independent by construction (their prerequisites are committed), so the order does not change
   any decision; the kernel returns them in plan (topological) order.
2. **Where Contract and Flow run.** Algorithm 2 lists four predicates in one loop. In the code,
   Cap and Fresh run in `submit`, and Contract and Flow run in `check_value`, which the kernel
   calls inside `resolve` so that currentness is rechecked atomically with the commit. A proposal
   whose request became stale in between is `discarded` and logged as `KEY_STALE`.
3. **Flow also checks the envelope label.** Besides the sink check of the paper, `check_value`
   rejects a proposal whose envelope label differs from the recomputed ℓ_q (`TAINT_VIOLATION:
   envelope label mismatch`); the controller builds the envelope itself, so this never fires on
   honest runs and guards against a modified selection.
4. **Tool-hash check under the `key_match` switch.** The paper attributes the run-time metadata
   check to MP3 (P4). In code it is guarded by `mech.key_match`, because the pinned tool hash is
   part of the contract and therefore of the key. The I2-key ablation thus disables both Fresh and
   the metadata check; the RQ2 results for I2-key should be read with that in mind.
5. **Rot(i, σ).** The mutator rotation applies a mutator to about half of the tests, chosen by the
   seeded generator (`rng.random() < 0.5`); the rest are unmutated. Generation is deterministic
   per seed.
6. **Payload classes.** The paper lists five classes. Four are text classes rotated over EDGE,
   SEL, TAINT, COLL and SLOT obligations; `tool_poison` is used for RECONF tool-metadata
   obligations only.
