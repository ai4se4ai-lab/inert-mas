# Benchmarks and adapter fidelity

* **Topology zoo** (ours): chain, star, hierarchical, debate, planner-coder-reviewer; 3/5/8
  agents; task families email, reply, web, code; 5 tasks per family.
* **TAMAS** (microsoft/TAMAS @ 545c112a): 5 domains x 6 attack types x 10 instances, plus the
  50 IPI queries used as benign tasks. RoundRobin configuration. See docs/open-questions.md
  items 3-5 for oracle and provenance choices.
* **Re-implemented payload styles**: MAS hijacking (fake error / traceback), Prompt Infection
  (self-replication), Agent-in-the-Middle (transport tampering, A3), MCP tool poisoning (A5).
