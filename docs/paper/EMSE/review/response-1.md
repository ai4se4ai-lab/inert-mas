# Response to deep review 1

Each comment of [deep-review-1.md](deep-review-1.md), what was changed and where. Section, table and
figure numbers refer to the revised manuscript
([main.tex](../Springer-Nature-LaTeX-template/main.tex)). Tables 5 (audited trace), 7 (run accounting),
10 (per model) and 11 (per task family) and Listing 1 are new, so the tables of the first version have
moved: conditions 5→6, overall results 6→8, RQ3 7→9, TAMAS 8→12, related taxonomies 9→13. Every number added to Sections 6 to 8 is computed from the result records by
`analysis/make_assets.py` and `analysis/paper_text.py`, and the new ones are recounted independently
by `docs/paper/EMSE/replication-package/scripts/check_claims.py`.

Status: **done**, **clarified** (the manuscript was right but unclear), **partly** (what remains is
stated), **open** (needs the author's input).

## Framing, background, running example

| # | Comment | Status | Change |
| --- | --- | --- | --- |
| 1 | Lattice polarity in Definitions 7 and 8 | done | Def. 7 now states that the order is by increasing distrust, with ⊥ the most trustworthy label, ⊤ the least, ⊔ the least trustworthy argument, and the reversal relative to Biba. Def. 8 says "lower, that is more trustworthy". |
| 2 | Mediation gap omits MAS monitors | done | Sec. 1 now names G-Safeguard, BlindGuard (learned detectors) and AgentSafe (hierarchy and sender authority) and why the gap stays open. |
| 3 | Scope of 106,382 in the abstract | done | "In a study of 106,382 runs, INERT lowered the attack success rate on the 51-workflow topology zoo …". The abstract and Sec. 1 also give the effect-only rate (56.3% → 0.0%). |
| m | `1*` on the affiliation | done | `\affil[1]` without the asterisk. |
| m | Semicolon after the e-mail | open | Printed by the Springer class (`sn-jnl.cls`) for every e-mail list; left to the journal's typesetting. |
| m | Underscores in Figure 1 tool nodes | clarified | The PDF renders `read_email` and `send_email` with underscores; text extraction drops the typewriter underscore, which is what the review saw. |

## Mapping study, taxonomy, threat model, related work

| # | Comment | Status | Change |
| --- | --- | --- | --- |
| 1 | C6 against full marks for R5 and R8 | done | R5 now covers C1–C4 (C1 only with known provenance), R8 the channel instances of the workflow model (C1–C5, C7); C6 is entirely gap G5. Figure 4 no longer claims "labels within a run" for C6. Table 3's caption states the scope of INERT's marks and that ◐ also marks by-design guarantees for a single agent. Audit CSVs 06, 08, 09 and 10 regenerated. |
| 2 | C1 missing from A1–A6; residual rows without property; P5 under A2/A4 | done | Sec. 4 explains that the user's request is trusted at label *user*, that C1 can be mediated only when provenance is segmented, and that both settings are evaluated on TAMAS. Residual rows in Figure 4 now name P4 (owned validators) and mark the task scope as I2S (post hoc). Sec. 4 states that under the default policy P5 keeps environment content out of high-integrity sinks, whereas compromised agents are bounded by validators (P4) or per-slot policies. |
| 3 | Mapping-study reproducibility | partly | Sec. 3.1 now: says which records were deduplicated; defines E4 (link threshold); states that 164 Scopus records were screened on the title alone; explains that the threshold controls corpus size, not categories, that studies below it were not classified, and that it favours older work. Sec. 9 states that no independent rater validated the screening or classification and that no agreement is reported. **Open:** the name of the academic search engine used for Q1 and Q2 is not recorded in the repository (see `docs/open-questions.md`, item 17). A second human rater cannot be supplied by a script. |
| 4 | Related-work characterizations | done | Table 3: R2 is now ◐ for "MAS monitors, data management", because AgentSafe's ThreatSieve verifies the authority of information to prevent impersonation (checked against its abstract in the API cache). Injection benchmarks were already ◐ on R8. G4 and Sec. 10.4 now say that structural workflow coverage derives its criteria from the workflow's structure rather than from injection channels, instead of "targets functional faults". The abstract of that paper is not in the cache, so its restricted-tool criterion is not described. Figure 3's caption and Sec. 6.3 explain that the multi-agent monitors and AgentSafe were not reimplemented and why. |
| 5 | Kernel reference is an unarchived repository | partly | The kernel's source at commit f56c0e86 is vendored in the repository and replication package; the reference and Sec. 2.6 say so, and Definition 11 states every guarantee INERT relies on. A DOI for the kernel repository has not been minted. |
| m | E4 skipped; ambiguous "Records were deduplicated" | done | See item 3. |
| m | Missing citations in Sec. 10.1; [52] in Table 13 | done | Citations added for surveys, tiered risks and practitioner frameworks; Table 13 now describes [52] as "risk tiers, rule vs. judge boundary". |
| m | `???` in eight references | done | Publisher addresses added (Springer, ACL, ACM, IEEE, Morgan & Claypool, Wiley); the PMLR publisher is dropped because series and volume identify it. The rendered bibliography has no `???`. |
| m | Article numbers in [43], [91] | done | `pages = {1--10}, note = {Article 38}` and `pages = {1--36}, note = {Article 182}`. |
| m | "Technical Report Technical Report" in [88] | done | `number = {\#1}`, arXiv identifier moved to `note`. |
| m | [25], [45], [55] without venue | done | ACL 2025, KDD 2025 (V.2) and AIxDKE (IEEE), taken from the search records. Venues were also added as notes to 25 uncited entries. |
| m | arXiv:2610.07657 | clarified | Correct: it is the identifier in the search record's URL (October 2026). |

## Architecture

| # | Comment | Status | Change |
| --- | --- | --- | --- |
| 1 | Data-role arguments and Proposition 1 | done | Sec. 5.2 states the constraint that an argument that can influence a tool's return value must not have the data role. Checked in all 51 models: data arguments occur only as `body` of `send_email` and `content` of `write_file`, whose results are acknowledgements. |
| 2 | Static vs. runtime labels | done | Sec. 5.2: ℓ_t(s) is the declared output label and must bound the environment's labels; λ over-approximates by joining before selection; λ assumes successful declassification. Sec. 5.3: a failed extraction commits at the source label, and whether extraction succeeds is a one-bit flow that passes through the declassify slot and is bounded by robustness (Def. 8). |
| 3 | Declassify slots, guards and logging in Algorithm 1 | done | Algorithm 1 has its own declassify branch (lines 8–9). Guards are described (skip marker, counted as committed for Pub, guard field bounded by Flow). The text states which log entries the algorithms omit, including the run-time tool hash. |
| 4 | Trust boundary of the agent wrapper | done | Sec. 4 lists the signing wrappers in the TCB, and says that in the implementation they run in the controller's process and only prompt and text cross to the LLM. Figure 5 now shows only C_q and v crossing to the LLMs, MP1 passes C_q and ℓ_q to MP2, and the caption explains the wrapper. Algorithm 1 line 5 reads (v, τ) ← prop(C_q, c_q). |
| 5 | O(P) and the running example | done | The model has 11 edges: Figure 1's caption now names the omitted `a1 → report` read. O(P) is a tagged disjoint union (⊎); Src, Sinks_H, Paths, Payloads (four text classes), exec and A_mid are defined; SEL includes reads of the trusted input, which are the infeasible obligations (4 edges + 4 reads). |
| m | Figure 5 "value" label | done | Now "C_q, ℓ_q". |
| m | src(a) on fields | done | "Reads and sources name a slot or a field of a slot, and a field has the label of its slot." |
| m | ⊤ undefined | done | m_s = ⊤ = external_untrusted. |
| m | TokenInvalid vs. TokenReused | done | Explained in MP2. |
| m | meta_Env vs. ℓ_env | done | meta_env. |
| m | ω vs. ω_g | done | ω_g throughout. |

## Study design, results, discussion, validity

| # | Comment | Status | Change |
| --- | --- | --- | --- |
| 1 | Declassifiers and the reply family | clarified | The review assumed that no zoo workflow has a declassifier. In fact all 27 reply and code workflows have one (sender address; affected function name), which the manuscript did not say. Sec. 6.2 now says so. RQ4 reports utility by family (I2: email 100%, web 100%, reply 81.6%, code 54.2%; B3: 0% on reply and code). RQ5 states that the adaptive attacker faced five code workflows with a declassifier, and that ten attempts do not establish robustness against stronger attackers. |
| 2 | Typed slots confounded with security | done | RQ4 uses I1 as the structural control: typed slots +20.5 points (B0 → I1), taint −9.7 points (I1 → I2), mostly on code; tokens are similar under I1 (3,072 mean), so the savings come from slot-scoped context. The RQ4 answer is reworded accordingly. Sec. 6.3 states that every condition uses JSON-schema constrained decoding (B3 except for its plan). |
| 3 | RQ2 inconsistencies | done | Figure 8b shows the *first* rejection of a run. In A2/A4 tests the adversary first answers other slots' requests (TokenInvalid). The owner's own proposals are rejected later (272 ValidatorReject decisions) or kept from the executor; the text and caption now say this. I2-tokens: A2/A3/A4 successes are audited P2 violations with no goal met, and A5 5.3% = 16/16 rogue-agent tests. I2-key: A5 73.4% = replays 70.5% plus all 68 tool-metadata tests, because the metadata check is tied to the key-match switch (now stated in Sec. 5.3). I1 A4 50% is explained. U_att 56.4% is labelled as the ablation suite against 61.4% on the full grid. The ablation suite has no benign runs, so no benign utility is claimed for I2-tsel. |
| 4 | Residual double-counting; IPI rate an oracle artifact | done | Sec. 8 counts each TAMAS configuration separately: 369 successes with the whole query trusted (219 / 126 / 24) and 257 with the suffix untrusted (86 / 126 / 45). Sec. 7.7 reports n = 300 per cell, and that 23 of the 24 IPI and 17 of the 21 DPI-split successes under I2 call a tool that the benign run of the same instance and model also calls (25 of 300 benign runs do), so I2's IPI rate is at the oracle's floor. DPI-split is described as an idealized setting. The abstract says "about the rate at which benign runs call the targeted tools". |
| 5 | ASR vs. Goal; validator asymmetry; B4 | done | Sec. 6.4 defines the baseline P1 clause. Sec. 7 reports that it fires on 52.5% (B0), 51.6% (B1), 50.5% (B2) and 26.1% (B4) of benign runs and accounts for 52.1% of B1's attacked runs. It gives the effect-only ordering (B3/I2 0.0, I1 7.1, B1 11.8, B4 46.2, B2 47.6, B0 56.3) and explains I1's gap as audited P5 violations. ASR stays the primary outcome because it was pre-registered. Table 8's caption, Sec. 6.3, Table 6 and Sec. 9 disclose that only INERT has validators and the designer's graph, and that B4 must infer the graph and lacks per-edge rules. |
| 6 | Run accounting | done | New Table 7 (generated) and text: 51 = 4 × 3 × 4 + 3; 8,670 = 1,530 benchmark-style + 7,140 generated; the 2,100 superseded DPI-split runs are included in 106,382 and replaced in the analysis; RQ3 notes ten tests per workflow for the 70B-class models. |
| 7 | Mixed model under separation | done | Sec. 6.4 names the estimator (variational Bayes, `BinomialBayesMixedGLM`, default normal priors with sd 2 for fixed effects and sd 1 for the log sd of the random effect), states that all conditions enter the fit, and that B3 and I2 are not identifiable and not interpreted. |
| m | Table 6 B2 citation without brackets | done | `\citep`. |
| m | Hyphens for minus signs, "B4 - 1.25" | done | Generated in math mode ($-1.02$, $-0.45$). |
| m | "126 of these 126" | done | "all 126 of these successes". |
| m | ToolMetadata legend | done | Legend "ToolMetadataMismatch"; MP3 names the reason code. |
| m | "of them" | done | "of benign tasks". |
| m | Mean vs. median tokens | done | "(means; Figure 10 shows medians)". |
| m | Construct-validity sentence | done | Reworded as suggested. |
| m | "The authors declare" | done | "The author declares". |

## Weaknesses not covered above

- **Unexercised declassifiers / adaptive attacker on declassifiers:** see design item 1. The
  adaptive attacker did face declassifiers, but a stronger evaluation of declassifier robustness
  would need new GPU runs and is stated as a limitation in RQ5.
- **Baseline simplifications and missing multi-agent defenses:** disclosed and justified (Sec. 6.3,
  Sec. 9, Sec. 10.3). New baselines would need new GPU runs and were not added.
- **Additional benchmarks (ACIArena):** discussed in G4 and related work; not evaluated.

## Use of the additional space (body up to 44 pages)

The body grew from 39 to 43 pages. The additions are generated from the code or the records, or are
drawn from the classified corpus:

- **Approach:** Listing 1 shows the running example's model. Table 5 gives its audited trace under the
  indirect injection for I1 and I2 (generated by `analysis/example_trace.py` with the deterministic
  mock LLM, so it is reproducible). It shows the withheld read, the committed labels and the audit's
  P5 verdict.
- **Evaluation:** Section 7.5 with Table 10 (attack success and utility per model) and Table 11
  (utility per task family). It reports that I2's 0.0% holds for every model, that utility ranges
  from 52.2% to 100.0% across models, and that the cost of taint lies in the code family, where two
  models complete no task under I2.
- **Related work:** protocol-level taxonomies and surveys; the attack mechanisms of the corpus and the
  channel each targets; multi-agent detectors, guardrails, privilege separation and runtime
  verification; identity governance; multi-agent and model-level benchmarks. Each study is described
  only as far as its title and its codebook leaf support.

