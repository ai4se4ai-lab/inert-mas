# Pre-registration (fixed 2026-11-23, before the full grid)

Development and smoke runs (manifests `smoke`, `local_smoke`, `local_baselines`, `dev1`) were used
to debug the harness and the approach; their results are not reported as findings.

## Hypotheses
- **H1 (RQ1)** Under B0, propagation (infected agents, blast radius) grows with topology fan-out and
  size; chain topologies amplify transport tampering.
- **H2 (RQ2)** Structural attacks (A2 impersonation attempts, A3, A5) fall to near zero under I1;
  semantic propagation (A1 into executor/instruction sinks) needs I2. Removing taint at selection
  or taint at acceptance alone does not restore A1 success (the two are redundant); removing
  validators restores success of compromised executor agents (A2/A4 on the actor).
- **H3 (RQ3)** At equal LLM-call cost, model-coverage suites find more successful attacks and more
  distinct violated obligations than benchmark-style suites, on B0 and B4.
- **H4 (RQ4)** INERT's benign utility loss relative to B0 is comparable to B3's, and its false
  rejection rate is lower than B1's flag rate.
- **H5 (RQ5)** Under an adaptive attacker (budget 10), I2 keeps P1-P6 and residual successes
  concentrate at declassifiers and at slots with legitimate authority.

## Analysis (unchanged after this date)
Primary outcome: ASR = goal met (sandbox call log) or attributable P1-P6 violation.
Paired exact McNemar vs B0 and vs B4 with conditional odds ratio and 10,000-sample bootstrap CI;
Wilcoxon signed-rank + Cliff's delta for latency and tokens; logistic mixed model (defense + LLM
fixed, task random intercept, variational Bayes); Holm correction within each RQ; Wilson
intervals for rates. Every condition that was run is reported, including unfavourable ones.
Failed cases are re-run or reported as failed, never dropped.
