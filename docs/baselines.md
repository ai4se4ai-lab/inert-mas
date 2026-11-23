# Baselines: design choices and differences from INERT

All baselines run the same compiled IR (same agents, roles, instructions, tool bindings and
order), the same LLM, decoding configuration and seed, and the same sandboxed tools.

* **B0 native.** Group chat over the IR's agent export. Every agent sees the shared transcript
  including raw tool outputs (AutoGen group-chat semantics), may call only its own bound tools
  and may hand off to any team member (Swarm-style, at most 3 extra turns). Off-model handoffs
  are counted as P1 violations.
* **B1 detector.** B0 plus a zero-shot injection classifier (same LLM) and a lexical
  pre-filter on every tool output and agent message; flagged content is replaced. Its extra
  LLM calls are charged to B1.
* **B2 tagging.** B0 plus source tags on every message and a system instruction to treat tagged
  content as data (LLM Tagging, Prompt Infection paper).
* **B3 plan + quarantine (CaMeL-style).** A planner LLM sees only the request and tool
  signatures and writes a tool plan with literal or extracted arguments; quarantined LLMs
  extract values and the model's middle agents run as quarantined analysts. A capability
  policy denies write/exec tools whose executor-role arguments derive from untrusted data.
  Differences from CaMeL: JSON plans instead of Python, no interpreter-level control-flow
  capabilities.
* **B4 permitted graph (ControlValve-style).** Before execution a planning LLM that sees only
  the task generates allowed handoffs and per-agent tools; the B0 runtime blocks the rest.
  Difference: ControlValve's per-edge context rules are not reimplemented.
* **INERT (I1/I2).** Owned validators of the zoo models (grounded recipient/path, forbidden
  OS/network calls in code) are part of the designer's contract and are not available to the
  baselines; their effect is isolated by the I2-validator ablation.
