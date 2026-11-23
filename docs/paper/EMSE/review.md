# Self-review against the EMSE review criteria

This is an internal review pass, written as a critical reviewer would, with the action taken for each point.
Status: **R** resolved in the manuscript, **D** disclosed as a limitation, **O** open (needs the authors).

## i) Novelty

| Concern a reviewer may raise | Response | Status |
| --- | --- | --- |
| "Taint tracking and capability tokens are known ideas." | The novelty is their combination at the level of a designer-authored, compiled MAS model: labels inside dependency keys, policy at both context selection and acceptance, and one IR shared by the runtime, the test generator and the auditor. Section 1 and Related Work state this explicitly. | R |
| "How is this different from CaMeL and ControlValve?" | CaMeL derives the plan from an LLM per request for one agent. ControlValve derives a control-flow graph with an LLM and does not constrain data flow. INERT takes structure from a versioned model, covers staleness, replay and reconfiguration, tracks taint across agents, and generates tests from the same model. Both are reimplemented as baselines (B3, B4) and compared head to head. | R |
| "Model-based security testing exists." | Yes, and it is cited. Its application to prompt-injection propagation in LLM MAS, with coverage criteria over slots, selectors and taint paths, is new. RQ3 evaluates the benefit. | R |
| Overlap with the prior controller paper (JSS). | The vendored kernel is recapped in one paragraph and cited. All new contributions are listed in Section 1. | R |

## ii) Rigor

| Concern | Response | Status |
| --- | --- | --- |
| Baselines are reimplementations and may be weak. | Two harness bugs that hurt the baselines were found and fixed before the final runs (empty tool arguments, a too-strict planner prompt). B0 and B4 then reach high benign utility. All baselines share the IR, model, tools, decoding and seed. Differences from the originals are listed in docs/baselines.md and in Threats. | R / D |
| The zoo models were written by the authors. | They are written in the direct style (each agent reads its upstream agents and the tool output). The linter flags untrusted-to-sink paths in all of them, so enforcement comes from the runtime and not from a tailored design. | D |
| INERT's zoo models include validators the baselines lack. | Isolated by the I2-validator ablation (Table RQ2). | R |
| Single seed per cell. | Decoding is at temperature 0. A five-seed sub-study at temperature 0.7 quantifies variation (Table seeds). | R |
| Oracles. | Effects in the sandbox call log, not text. Property violations from the LLM-free audit. P5 violations count only when attacker content is present. Baseline P1 violations count only when hijacked control reaches the goal tool's owner. | R |
| TAMAS oracle deviates from the original GPT-4o judge. | Disclosed. Deterministic targets are used where TAMAS defines them, and a heuristic elsewhere. The benign base rate of target-tool calls (~8%) is computed and reported. | D |
| Post-hoc changes. | The TAMAS DPI-split bug fix is a re-run with the whole defense set (open question 12). I2S is reported separately and labelled post hoc. Development and smoke runs are excluded. | R |
| Statistics. | Pre-registered (analysis/preregistration.md): McNemar with bootstrap OR intervals, Wilcoxon with Cliff's delta, a logistic mixed model, Holm correction, Wilson intervals. | R |
| Mixed model separation for I2 and B3 (zero successes). | Report the paired McNemar results and the Wilson upper bound. The mixed-model estimates for those two levels are not interpreted. | R |
| Human coding of residual risk with two raters and Cohen's kappa (plan). | The manuscript reports a rule-based categorization. The 100-case coding sheet (paper/residual_coding.csv) and the kappa script (analysis/residual.py --kappa) are ready, but two human raters must code the sample. | **O** |

## iii) Relevance

| Concern | Response | Status |
| --- | --- | --- |
| Why is this a software-engineering paper? | The approach is model-driven development and model-based testing of a software architecture. The evaluation is a controlled experiment on workflows, with implications for practitioners (how to assign sink roles) and for benchmark designers (publish workflows as models). | R |
| Fit with the special issue on software security testing. | Contribution 3 (coverage-based attack generation) and contribution 5 (replayable oracles) address test creation and automation. The head-to-head study addresses evidence on existing techniques. | R |

## iv) Verifiability and transparency

| Concern | Response | Status |
| --- | --- | --- |
| Can results be reproduced without GPUs? | The mock backend runs the whole pipeline offline. CI runs the tests and a smoke grid. | R |
| Can every number be traced? | `analysis/run_all.sh` regenerates every table, figure and number in the text from the result records. No number in the results sections is typed by hand. | R |
| Provenance of each run. | Every record stores the code version (git commit plus content hash of the deployed tree, whose archive is kept), the model digest, the decoding configuration, the seed, the host and the job. | R |
| Environment changes during the study. | The move from rorqual to fir and the capability-key change are documented (open questions 11 and 13). | R |
| Public archive. | The repository URL is given. A Zenodo DOI must be minted when the package is frozen. | **O** |

## v) Presentation

| Concern | Response | Status |
| --- | --- | --- |
| Semicolons. | None in the prose (checked with grep). | R |
| Each RQ ends with an explicit answer. | Yes ("Answer to RQx"). | R |
| Claims bounded. | Section 1 and Section 3 state what is not claimed. Residual risk is quantified. | R |
| Author list and affiliation. | Placeholder from the account details. The authors must confirm. | **O** |
