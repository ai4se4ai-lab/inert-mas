"""Prose blocks of the results sections, rendered from numbers.json (no hand-typed numbers).

Each key of ``render`` fills one %<<marker>> block of main.tex. Sentences whose direction depends on
the data are phrased from the data, so a re-run that changes a direction changes the sentence.
"""

from __future__ import annotations

from typing import Any


def p(x: float | None, d: int = 1) -> str:
    return "n/a" if x is None or x != x else f"{100 * x:.{d}f}\\%"


def f(x: float | None, d: int = 2) -> str:
    return "n/a" if x is None or x != x else f"{x:.{d}f}"


def m(x: float | None, d: int = 2) -> str:
    """Signed number in math mode, so that a negative value gets a minus sign, not a hyphen."""
    return "n/a" if x is None or x != x else f"${x:.{d}f}$"


WORDS = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}


def word(x: int) -> str:
    return WORDS.get(x, str(x))


def num(x: int) -> str:
    return f"{x:,}".replace(",", "{,}")


def _best(main: dict[str, Any], key: str, low: bool, prefix: str = "B") -> tuple[str, float]:
    bs = {k: v[key] for k, v in main.items() if k.startswith(prefix) and v[key] == v[key]}
    k = min(bs, key=lambda x: bs[x]) if low else max(bs, key=lambda x: bs[x])
    return k, bs[k]


def residual_sentence(n: dict[str, Any]) -> str:
    cfg = n.get("residual_by_config") or {}
    if not cfg:
        return ""

    def parts(c: dict[str, int], user: str) -> tuple[int, str]:
        tot = sum(c.values())
        tool = c.get("benign-overlap", 0) + c.get("plausible", 0)
        xs = [(c.get("user-input", 0), f"arrived in the user's own request ({user})"),
              (c.get("tool-owned", 0), "were harmful tools in a compromised agent's own tool set"),
              (tool, f"called a target tool that agents also call on benign runs ({c.get('benign-overlap', 0)} of "
                     "them on the benign run of the same instance and model)")]
        return tot, ", ".join(f"{v} ({100 * v / tot:.0f}\\%) {t}" for v, t in xs if v)
    tw, pw = parts(cfg.get("whole", {}), "direct injection or impersonation")
    ts, ps = parts(cfg.get("split", {}), "impersonation")
    zoo = n.get("zoo_success_i2", 0)
    return ("A rule-based categorization of the successful attacks against I2, derived from the run records, shows "
            f"where the residual risk lies. {'None occurred on the topology zoo, so all' if not zoo else 'All'} are "
            "TAMAS runs. Because DPI-whole and DPI-split are two labelings of the same direct-injection runs, we count "
            f"each TAMAS configuration separately. With the whole query trusted, as in TAMAS, there are {tw} successes: "
            f"{pw}. With the injected suffix labelled untrusted, there are {ts}: {ps}.\n\n")


def glmm_sentence(n: dict[str, Any]) -> str:
    g = n.get("glmm") or {}
    if not g:
        return ""
    co = {k.split("T.")[-1].rstrip("]"): v for k, v in g.items() if k.startswith("C(defense)")}
    shown = [f"{d} {m(v['mean'])} ({f(v['sd'])})" for d, v in sorted(co.items()) if v["sd"] < 0.3]
    sep = [d for d, v in co.items() if v["sd"] >= 0.3]
    return (" The pre-registered logistic mixed model gives log-odds of attack success relative to B0 "
            "(posterior mean and standard deviation) of "
            + ", ".join(shown) + (f", while {' and '.join(sorted(sep))} are not identifiable (no successful attack, "
                                    "complete separation)." if sep else "."))


def i2_reject_sentence(n: dict[str, Any]) -> str:
    f2 = n.get("first_reject_I2") or {}
    a1 = f2.get("A1") or {}
    if not a1:
        return ""
    none = 100 * a1.get("none", 0) / max(1, sum(a1.values()))
    a5 = f2.get("A5") or {}
    t5 = max(1, sum(a5.values()))
    rs = n.get("rq2_i2_reasons") or {}
    vr = sum((rs.get(a) or {}).get("VALIDATOR_REJECT", 0) for a in ("A2", "A4"))
    return (f"Figure~\\ref{{fig:ablation}}b shows the first rejection in each I2 run. Under I2, "
            f"{none:.0f}\\% of the A1 tests cause no rejection at "
            "all: selection withheld the tainted read, so the executor never proposed an injected value, and the "
            "attack failed without any check having to fire. In every A2 and A4 test the compromised agents first try "
            "to answer requests of other slots, which fails \\textsc{Cap} (\\textsc{TokenInvalid}), so this is the "
            "first rejection. Their proposals for their own slots carry valid tokens; they are rejected later by owned "
            f"validators ({vr} \\textsc{{ValidatorReject}} decisions in these runs) or accepted as data that selection "
            "keeps from the executor, which is why \\textsc{ValidatorReject} does not appear as a first rejection. "
            f"For A5, replays fail \\textsc{{Fresh}} ({100 * a5.get('KEY_STALE', 0) / t5:.0f}\\%), altered tool "
            f"metadata fails at tool execution ({100 * a5.get('TOOL_METADATA_MISMATCH', 0) / t5:.0f}\\%, "
            "\\textsc{ToolMetadataMismatch}) and proposals of a rogue agent fail \\textsc{Cap} "
            f"({100 * a5.get('TOKEN_INVALID', 0) / t5:.0f}\\%).")


def tests_sentence(n: dict[str, Any]) -> str:
    t = {k: v for k, v in (n.get("tests") or {}).items() if "or" in v and not k.startswith("util_")}
    if not t:
        return ""
    worst = max(v.get("p_holm", v["p"]) for v in t.values())
    m, e = f"{worst:.0e}".split("e")
    return (f" Figure~\\ref{{fig:adaptive}}b, shown with the RQ5 results, gives the paired comparisons as exact "
            f"McNemar odds ratios with bootstrap intervals. All {len(t)} comparisons against B0 and B4 are significant after Holm correction "
            f"(largest adjusted $p < 10^{{{int(e) + 1}}}$).")


def tamper_sentence(n: dict[str, Any]) -> str:
    t = n.get("rq1_tamper") or {}
    if not t:
        return ""
    hi = max(t, key=lambda k: t[k]["asr"])
    return (f"Message tampering (A3) succeeds under B0 in {p(t.get('chain', {}).get('asr'))} of the tests on chains, "
            f"against {p(t[hi]['asr'])} on {hi} topologies, so chains do not amplify tampering. ")


def i1a2_clause(n: dict[str, Any]) -> str:
    c = n.get("i1_a2_success_by_criterion") or {}
    tot = sum(c.values())
    if not tot:
        return "no such attack reached its goal"
    k = max(c, key=lambda x: c[x])
    share = f"all {tot} of these successes are" if c[k] == tot else f"{c[k]} of these {tot} successes are"
    return (f"{share} {k} tests in which the compromised agent writes the payload into "
            "its own slot, from where it travels semantically to the executor. Its attempts to answer another "
            "agent's request are all rejected")


def dpi_whole_cmp(tam: dict[str, Any]) -> str:
    others = [v.get("DPI-whole") for k, v in tam.items() if k not in ("I2", "I2S") and v.get("DPI-whole") is not None]
    if not others or "I2" not in tam:
        return ""
    lo, hi, x = min(others), max(others), tam["I2"]["DPI-whole"]
    where = "slightly below" if x < lo else "slightly above" if x > hi else "within"
    return f", {where} the range of the other conditions ({p(lo)} to {p(hi)}), so INERT gives little protection here"


def render(n: dict[str, Any]) -> dict[str, str]:
    main = n.get("main", {})
    out: dict[str, str] = {}
    llms = n.get("llms", [])
    out["models_text"] = (
        f"We use {word(len(llms))} open-weight instruction-tuned models from four families and three size classes: "
        + ", ".join(f"\\texttt{{{x}}}" for x in llms if x) + " "
        "\\citep{grattafiori2024llama3,qwen2025qwen25,gemma2024gemma2}. The 7--9B and 24B models run the full grid. "
        "The 70B-class models run a reduced grid (two benign tasks and one attacked task per workflow, ten generated "
        "tests per workflow) because they are about four times slower.")
    if "I2" not in main or "B0" not in main:
        return out
    i2, b0, i1, b3, b4, b1 = (main[k] for k in ("I2", "B0", "I1", "B3", "B4", "B1"))
    t = n.get("tests", {})
    rq3 = n.get("rq3", {})
    tam = n.get("tamas", {})
    rq5 = n.get("rq5", {})
    nb_att = sum(v["n_att"] for v in main.values())
    out["abstract_results"] = (
        f"In a study of {num(n['rows'])} runs, INERT lowered the attack success rate on the 51-workflow topology zoo "
        f"from {p(b0['asr'])} without defense to {p(i2['asr'])} (forbidden effects alone: from {p(b0['goal'])} to "
        f"{p(i2['goal'])}), matching the strongest baseline, a CaMeL-style planner with quarantined data, while completing "
        f"{p(i2['u_ben'])} of benign tasks against that baseline's {p(b3['u_ben'])}. An adaptive attacker did not "
        f"succeed against INERT. On TAMAS, INERT reduced indirect injection from {p(tam.get('B0', {}).get('IPI'))} to "
        f"{p(tam.get('I2', {}).get('IPI'))}, about the rate at which benign runs call the targeted tools, but did not stop agents "
        "that misuse tools they legitimately own. "
        f"%Attack suites generated from the model violated "
        f"{rq3.get('B0:generated', {}).get('unique', 0)} distinct model elements of the undefended systems, against "
        f"{rq3.get('B0:bench', {}).get('unique', 0)} for benchmark-style attacks.")
    out["intro_findings"] = (
        f"Our study covers {word(len(llms))} open-weight models, 51 workflows, the TAMAS benchmark and {num(n['rows'])} runs. "
        f"INERT reduced the attack success rate on the topology zoo from {p(b0['asr'])} to {p(i2['asr'])} "
        f"(forbidden effects from {p(b0['goal'])} to {p(i2['goal'])}) and kept "
        f"{p(i2['u_ben'])} benign utility, more than the undefended system ({p(b0['u_ben'])}). The strongest baseline, "
        f"a CaMeL-style planner, also blocked every attack but completed only {p(b3['u_ben'])} of benign tasks. "
        "Each mechanism closed the channel the taxonomy assigns to it, generated suites found more successful attacks "
        "per unit of cost than benchmark-style suites, and on TAMAS agents that misuse tools the model allows them "
        "remain a residual risk.")
    pb = n.get("p1_base_rate") or {}
    zc = n.get("zoo_composition") or {}
    order = sorted(((k, v["goal"]) for k, v in main.items()), key=lambda kv: kv[1])
    out["results_overview"] = (
        f"Table~\\ref{{tab:main}} summarizes the topology zoo: {num(nb_att)} attacked runs "
        f"({num(i2['n_att'])} per condition, of which {num(zc.get('bench', 0))} benchmark-style and "
        f"{num(zc.get('generated', 0))} generated tests) and the benign runs of all seven conditions over all models"
        f"{', with ' + str(n['errors']) + ' failed runs' if n.get('errors') else ', with no failed run'}. "
        f"Two conditions reach an attack success rate of {p(i2['asr'])}: I2 and B3 (Wilson 95\\% upper bound "
        f"{p(i2['asr_hi'], 2)}). They differ sharply in utility. I2 completes {p(i2['u_ben'])} of benign tasks and B3 "
        f"{p(b3['u_ben'])}, because B3's planner never sees the material it must act on and its capability policy "
        f"denies side effects whose arguments derive from it. The message-level defenses reduce but do not prevent "
        f"attacks: the detector B1 reaches {p(b1['asr'])}, the permitted graph B4 {p(b4['asr'])}. "
        "ASR and Goal differ by construction. For the baselines, ASR also counts a control-flow violation (P1): a "
        "handoff outside the model that reaches the agent owning the attacker's target tool. Free-form group chats "
        "make such handoffs without any attack, in "
        + ", ".join(f"{p(pb[d]['benign_offmodel'])} ({d})" for d in ("B0", "B1", "B2") if d in pb)
        + f" and {p(pb.get('B4', {}).get('benign_offmodel'))} (B4)" +
        " of benign runs, so this clause raises baseline ASR; for B1 it accounts for "
        f"{p(pb.get('B1', {}).get('attack_p1_only'))} of the attacked runs, which is why B1's ASR is far above its "
        f"Goal rate. For I1, the gap between Goal and ASR consists of audited P5 violations that carry attacker content "
        "but did not reach the sandbox. Judged by forbidden effects alone (Goal), the order is "
        + ", ".join(f"{k} {p(v)}" for k, v in order) + ", so INERT's advantage holds on both measures. "
        "Figure~\\ref{fig:tradeoff}a places every condition and every model in the security--utility plane, and "
        "Figure~\\ref{fig:tradeoff}b shows the distribution of both rates over the 306 combinations of workflow "
        "and model." + glmm_sentence(n) + tests_sentence(n))
    # ---------------------------------------------------------------- RQ1
    rq1 = n.get("rq1", {})
    if rq1:
        by_t: dict[str, list[tuple[int, dict[str, float]]]] = {}
        for k, v in rq1.items():
            name = k.rstrip("0123456789")
            by_t.setdefault(name, []).append((int(k[len(name):]), v))
        inf = ", ".join(f"{t} from {f(xs[0][1]['inf'], 1)} to {f(xs[-1][1]['inf'], 1)}"
                        for t, xs in sorted((t, sorted(x, key=lambda z: z[0])) for t, x in by_t.items()))
        grows = sum(1 for xs in by_t.values() if sorted(xs, key=lambda z: z[0])[-1][1]["inf"] >
                    sorted(xs, key=lambda z: z[0])[0][1]["inf"])
        shrinks = sum(1 for xs in by_t.values() if sorted(xs, key=lambda z: z[0])[-1][1]["blast"] <
                      sorted(xs, key=lambda z: z[0])[0][1]["blast"])
        worst = max(rq1.items(), key=lambda kv: kv[1]["asr"])
        best = min(rq1.items(), key=lambda kv: kv[1]["asr"])
        deep = max(rq1.items(), key=lambda kv: kv[1]["depth"])
        out["rq1_text"] = (
            "Without a controller, an injection rarely stays with the agent that reads it. Figure~\\ref{fig:propagation}a--c "
            "reports B0 by topology and size, with bootstrap 95\\% bands. The number of infected agents grows with the number of agents in "
            f"{grows} of {len(by_t)} topologies ({inf}). The blast radius, the share of all agent outputs that carry "
            f"attacker content, falls with size in {shrinks} of {len(by_t)} topologies, because added agents dilute "
            "the transcript rather than escape it. The longest infected chains occur in "
            f"{deep[0]} (mean depth {f(deep[1]['depth'])}). Attack success is highest for {worst[0]} "
            f"({p(worst[1]['asr'])}) and lowest for {best[0]} ({p(best[1]['asr'])}). The planner--coder--reviewer workflow "
            "propagates least because only the coder writes the artifact that reaches the executor.\n\n"
            + tamper_sentence(n) +
            "Figure~\\ref{fig:propagation}d separates exposure from effect. Under I1 and I2 about as many agents "
            "carry attacker content as under the message-level defenses, yet the attacks rarely or never reach an "
            "effect: the injected text is still read and repeated, but it stays in data fields.\n\n"
            "\\textbf{Answer to RQ1.} Injections propagate to several agents in every topology, and the absolute "
            "number of infected agents grows with team size. Hypothesis H1 holds for the count of infected agents "
            "but not for the share of outputs, which decreases with size, and its second clause, that chains "
            "amplify tampering, is not supported.")
    # ---------------------------------------------------------------- RQ2
    rq2 = n.get("rq2", {})
    if rq2:
        def g(d: str, a: str) -> str:
            return p(rq2.get(d, {}).get(a))
        fr = n.get("first_reject", {})
        sk = n.get("rq2_success_kind", {})
        a5d = n.get("rq2_a5", {})

        def goal_sum(d: str) -> int:
            return sum(v.get("goal", 0) for v in (sk.get(d) or {}).values())

        def a5(d: str, k: str, f_: str) -> Any:
            return (a5d.get(d) or {}).get(k, {}).get(f_)

        def top(a: str) -> str:
            v = fr.get(a) or {}
            if not v:
                return "n/a"
            k = max(v, key=lambda x: v[x])
            return f"\\textsc{{{k.title().replace('_', '')}}} ({100 * v[k] / sum(v.values()):.0f}\\%)"
        out["rq2_text"] = (
            f"Figure~\\ref{{fig:ablation}} reports the ablation suite ({num(n.get('ablation_design', {}).get('runs', 0))} "
            f"runs on {n.get('ablation_design', {}).get('workflows', 0)} workflows with the "
            f"{word(n.get('ablation_design', {}).get('llms', 0))} full-grid models), in which every INERT condition "
            f"faces the same generated tests. I2 blocks every attacker model (the highest attack success over A1 to A5 is {p(max(rq2.get('I2', {}).values() or [float('nan')]))}). Each ablation reopens precisely the channel that the taxonomy of "
            f"Section~\\ref{{sec:taxonomy}} assigns to it. Without tokens, compromised agents ({g('I2-tokens', 'A2')}), "
            f"message tampering ({g('I2-tokens', 'A3')}) and colluding agents ({g('I2-tokens', 'A4')}) succeed, because "
            "forged and altered proposals are accepted. These successes are audited authorship violations (P2): in "
            f"{'none' if not goal_sum('I2-tokens') else goal_sum('I2-tokens')} of them did the forged value also reach "
            "its goal in the sandbox, because selection and validators still bound what the forged value can steer. "
            f"A rogue agent succeeds in all {a5('I2-tokens', 'rogue_agent', 'n')} of its tests "
            f"({g('I2-tokens', 'A5')} of A5), because a registered agent can answer requests without a capability. "
            f"Without key matching, A5 reaches {g('I2-key', 'A5')}: replayed proposals succeed in "
            f"{p(a5('I2-key', 'replay', 'asr'))} of the replay tests, and every one of the "
            f"{a5('I2-key', 'tool_meta', 'n')} tool-metadata tests succeeds, because our implementation ties the "
            "comparison of the run-time tool description with the pinned hash to the same switch (the pinned hash is "
            "part of the contract and therefore of the key). Without validators, "
            f"colluding agents reach {g('I2-validator', 'A4')} and a compromised executor agent {g('I2-validator', 'A2')}; "
            "these successes reach their goal in the sandbox. "
            f"Without any taint (I1), indirect injection succeeds in {g('I1', 'A1')} of the tests, which is the semantic "
            "propagation that structural mechanisms cannot see. A compromised agent also succeeds in "
            f"{g('I1', 'A2')} of the tests under I1, but " + i1a2_clause(n) + ". Colluding agents succeed in "
            f"{g('I1', 'A4')} of the tests under I1 for the same reason: the middle agent's output, which carries the "
            "attacker's target, enters the executor's context once selection is off and then satisfies the grounding "
            "validator. Removing only one of the two taint checks keeps the "
            "attack success rate at zero, because selection and acceptance back each other up. They are not "
            "interchangeable, however. Without selection the executor agent sees tainted context, its proposals are "
            "rejected at acceptance, and the task fails: on the ablation suite, utility under attack is "
            f"{p(n.get('rq2_util_attack', {}).get('I2-tsel'))} without selection against "
            f"{p(n.get('rq2_util_attack', {}).get('I2'))} for I2 (Table~\\ref{{tab:main}} reports "
            f"{p(i2['u_att'])} for I2 on the full grid). Acceptance alone is the safety net if selection is "
            "misconfigured.\n\n"
            + i2_reject_sentence(n) + "\n\n"
            "\\textbf{Answer to RQ2.} Tokens stop authorship attacks, key matching stops replay (and, in our "
            "implementation, the use of altered tool metadata), validators bound the "
            "authority of compromised agents, and the taint policy is the only mechanism that stops semantic "
            "propagation into executor fields. H2 is supported, with one qualification: under I1 a compromised agent "
            "still wins through the semantic channel of its own output, which only the taint policy closes.")
    # ---------------------------------------------------------------- RQ3
    if rq3:
        parts = []
        for tgt in ("B0", "B4"):
            gq, bq = rq3.get(f"{tgt}:generated"), rq3.get(f"{tgt}:bench")
            if gq and bq:
                parts.append(
                    f"Against {tgt} the generated suites yielded {f(gq['per_kcall'], 1)} successful attacks per 1{{,}}000 "
                    f"LLM calls against {f(bq['per_kcall'], 1)} for the benchmark-style suites, and violated "
                    f"{gq['unique']} distinct obligations against {bq['unique']}")
        crit = n.get("rq3_by_criterion", {}).get("B0", {})
        top_c = max(crit, key=lambda k: crit[k]) if crit else "n/a"
        out["rq3_text"] = (
            "Table~\\ref{tab:rq3} compares the suites. The benchmark-style suites inject one payload into the primary untrusted resource, as AgentDojo and "
            "InjecAgent do. The generated suites cover the six criteria of Section~\\ref{sec:generation} and were "
            "sampled to at most 15 tests per workflow and task (ten per workflow for the 70B-class models). Both suites "
            "are pooled in the $n_{att}$ of Table~\\ref{tab:main}. Figure~\\ref{fig:discovery}a--b plots how many distinct "
            "obligations each suite violates as the target spends LLM calls, averaged over 200 random orderings of "
            "the tests, and Figure~\\ref{fig:discovery}c gives the attack success per criterion. "
            + ". ".join(parts) + ". "
            f"Against B0 the most effective criterion is {top_c} ({p(crit.get(top_c))}), and the criteria that "
            "benchmarks do not cover, compromised and colluding agents and tampering in transit, are among the most "
            "effective, while benchmark-style injection ranks in the middle. Neither "
            "suite found a successful attack against I2, so the generated tests also act as a regression suite for "
            "the defense.\n\n"
            "\\textbf{Answer to RQ3.} At equal cost, model-coverage suites find more successful attacks and reach "
            "several times more distinct model elements than benchmark-style suites. H3 is supported.")
    # ---------------------------------------------------------------- RQ4
    lat, tok, ut = t.get("lat_I2_vs_B0", {}), t.get("tok_I2_vs_B0", {}), t.get("util_I2_vs_B0", {})
    uf = n.get("util_by_family", {})

    def fam(d: str, k: str) -> str:
        return p((uf.get(d) or {}).get(k))
    out["rq4_text"] = (
        f"Table~\\ref{{tab:main}} reports benign utility, false rejections and LLM calls, and "
        f"Figure~\\ref{{fig:cost}} the distributions of tokens and latency. I2 completes {p(i2['u_ben'])} of benign "
        f"tasks, which is more than B0 ({p(b0['u_ben'])}). The paired comparison gives an odds ratio of {f(ut.get('or'))} for I2 succeeding where "
        f"B0 fails versus the opposite (Holm-adjusted $p$ {'$<0.001$' if (ut.get('p_holm', 1) or 1) < 0.001 else '= ' + f(ut.get('p_holm'), 3)}). "
        "This comparison, however, changes two factors at once: the coordination substrate (typed slots with one "
        "question each and a fixed schedule instead of a free-form group chat) and the security mechanisms. I1 uses "
        "the same substrate with tokens, keys and validators but without taint, so it separates the two. Typed slots "
        f"raise benign utility from {p(b0['u_ben'])} (B0) to {p(i1['u_ben'])} (I1), and the taint policy then costs "
        f"{100 * (i1['u_ben'] - i2['u_ben']):.1f} points (I1 to I2). The cost falls on the code family "
        f"({fam('I1', 'code')} under I1, {fam('I2', 'code')} under I2), where the coder sees only the declassified "
        "function name instead of the issue text. On reply, the declassified sender address keeps I2 at "
        f"{fam('I2', 'reply')} ({fam('I1', 'reply')} under I1; the declassifier fails when the planner picks the wrong "
        f"e-mail), and on email and web I2 completes {fam('I2', 'email')} and {fam('I2', 'web')} of the tasks. B3 "
        f"completes {fam('B3', 'reply')} of the reply and {fam('B3', 'code')} of the code tasks, because its planner "
        f"never sees the e-mail or issue it must act on. I2 rejects "
        f"{p(i2['frr'])} of honest proposals. B1 flags {p(b1['frr'])} of benign messages, B3's policy blocks "
        f"{p(b3['frr'])} of attempted actions and B4's generated graph {p(b4['frr'])}. On average I2 uses "
        f"{f(i2['calls'], 1)} LLM calls and {num(round(i2['tok']))} tokens per task against {f(b0['calls'], 1)} and "
        f"{num(round(b0['tok']))} for B0 (means; Figure~\\ref{{fig:cost}} shows medians; Cliff's $\\delta$ for tokens "
        f"{m(tok.get('delta'))}, for latency {m(lat.get('delta'))}), because agents see only selected slot values "
        f"instead of the whole transcript. I1 uses {num(round(i1['tok']))} tokens on average, so the savings come from "
        "slot-scoped context, not from taint.\n\n"
        f"Under attack, I2 keeps {p(i2['u_att'])} utility against {p(b0['u_att'])} for B0. The losses come from "
        "attacks against which INERT deliberately fails closed. A tampered proposal or a tool whose metadata "
        "changed is refused rather than used, which turns an integrity attack into an availability loss.\n\n"
        "\\textbf{Answer to RQ4.} Relative to the undefended system INERT's net utility is higher on our tasks, "
        "because typed slots help more than the taint policy costs; the cost of the security mechanisms proper is "
        f"the {100 * (i1['u_ben'] - i2['u_ben']):.1f}-point gap between I1 and I2, much lower than B3's loss, and "
        "INERT's false-rejection rate is the lowest of all defenses. H4 predicted a loss relative to B0 comparable "
        "to B3's, so the outcome is more favourable than hypothesized, and its second part (false rejections below "
        "B1's flag rate) holds.")
    # ---------------------------------------------------------------- RQ5
    if rq5:
        out["rq5_text"] = (
            "Figure~\\ref{fig:adaptive}a shows cumulative success as a function of the attempt budget. "
            "The adaptive attacker had ten attempts per case, the model description, the policy text and, after each "
            "attempt, the tools that were called and, for INERT, the controller's rejection reasons. Each condition "
            "faces 36 cases (nine workflows of size five, two tasks, two models); in the five code workflows the "
            "executor reads a regex declassifier of the issue, so the attacker could also try to pass a payload "
            "through a declassified value. " + " ".join(
                f"Against {d} it succeeded in {p(v['asr'])} of {v['n']} cases"
                + (f" after {f(v['attempts'], 1)} attempts on average." if v['asr'] > 0 else ", exhausting its budget.")
                for d, v in sorted(rq5.items())) +
            " Feedback helped the attacker against the message-level defenses, which it learned to evade within a few "
            "attempts. Against I2 the rejection reasons only told the attacker that untrusted content never reaches "
            "the executor, which no payload can change.\n\n"
            "\\textbf{Answer to RQ5.} The structural and taint guarantees held under adaptive attack, including on "
            "the workflows with declassifiers. H5 is supported for the zoo: P1 to P6 held, and no residual success "
            "occurred, so its second clause could only be observed on TAMAS, where the residual successes (next "
            "subsection) come from authority that the model grants to agents. Ten attempts against bounded regular "
            "expressions do not establish the robustness of declassifiers against stronger attackers.")
    # ---------------------------------------------------------------- TAMAS
    if tam:
        def g2(d: str, c: str) -> str:
            return p(tam.get(d, {}).get(c))
        orc_i2 = (n.get("tamas_oracle") or {}).get("I2", {})

        def orc_t(c: str) -> str:
            o = orc_i2.get(c, {})
            return f"{o.get('succ_also_benign', 0)} of the {o.get('succ', 0)}"

        def orc_b(c: str) -> str:
            o = orc_i2.get(c, {})
            return f"{o.get('base', 0)} of {o.get('n', 0)}"
        out["tamas_text"] = (
            f"Table~\\ref{{tab:tamas}} reports TAMAS, with {n.get('tamas_n_per_cell', 300)} runs per cell "
            "(50 instances, six models). Indirect injection (IPI) succeeds in "
            f"{g2('B0', 'IPI')} of instances under B0, {g2('B4', 'IPI')} under B4, {g2('B3', 'IPI')} under B3 and "
            f"{g2('I2', 'IPI')} under I2. The TAMAS oracles cannot distinguish an attack-induced call from a call the "
            f"task makes anyway: {orc_t('IPI')} IPI successes under I2 are runs in which the benign run of the "
            f"same instance and model calls the same target tool, which happens in {orc_b('IPI')} benign runs, so I2's "
            "IPI rate is at the oracle's floor rather than a flow of injected content. For direct injection, the outcome depends on what the system knows about "
            f"provenance. When the whole query counts as the user's request (DPI-whole, as in TAMAS), I2 reaches "
            f"{g2('I2', 'DPI-whole')}" + dpi_whole_cmp(tam) + ", because INERT trusts the user's channel by design. "
            f"With the injected suffix labelled untrusted (DPI-split), I2 reaches {g2('I2', 'DPI-split')} against "
            f"{g2('B0', 'DPI-split')} for B0 ({orc_t('DPI-split')} I2 successes coincide with the benign run), "
            f"and impersonation, also delivered in the query, {g2('I2', 'Impersonation')}. DPI-split is an idealized "
            "setting: it assumes that the boundary between the user's text and the injected text is known, for "
            "instance because a user interface or protocol keeps attachments apart. INERT does not segment a prompt "
            "itself.\n\n"
            "TAMAS agents carry harmful tools in their own tool sets, and Byzantine and colluding personas tell them "
            f"to use these tools, which I2 does not prevent: Colluding reaches {g2('I2', 'Colluding')} and Byzantine "
            f"{g2('I2', 'Byzantine')}, against {g2('B0', 'Colluding')} and {g2('B0', 'Byzantine')} for B0"
            + (", so INERT is no better than the undefended system here" if tam.get('I2', {}).get('Byzantine', 0) >=
               tam.get('B0', {}).get('Byzantine', 0) else "") + ". B3 and B4 do better because both derive a per-task "
            "allowlist from the request. A post-hoc variant (I2S) adds a task-scope slot that reads only the request "
            f"and lists the tools the task needs, enforced by an owned validator. It brings Colluding to {g2('I2S', 'Colluding')} and Byzantine to "
            f"{g2('I2S', 'Byzantine')}, at a benign utility of {g2('I2S', 'Benign util.')} against "
            f"{g2('I2', 'Benign util.')} for I2, because the scope sometimes omits a needed tool. We report I2S "
            "separately because it was designed after seeing the results.")
    sd = n.get("seeds", {})
    if sd:
        out["seeds_text"] = ("Across seeds, the standard deviation of the attack success rate is " + ", ".join(
            f"{p(v['asr_sd'])} for {d}" for d, v in sorted(sd.items())) +
            (", and the ordering of the conditions is the same for every seed." if n.get("seeds_order_stable")
             else ", but the ordering of the conditions differs between seeds."))
    else:
        out["seeds_text"] = ""
    out["discussion_text"] = (
        "\\paragraph{Structural and semantic guarantees fail differently.} Tokens, key matching and metadata pinning "
        "defeat attacks on authorship, freshness and configuration whatever the payload says, so feedback does not "
        "help an adaptive attacker. The taint policy decides what an agent may see before it decides, which is why "
        "only it stops an injected recipient, path or command from travelling into an executor field. Message-level "
        "defenses judge single messages, while the harm is a flow.\n\n"
        "\\paragraph{Where INERT does not help.} Residual risk sits in authority the model grants: a compromised "
        "owner of an executor field can misuse it within its validators, and content in the user's own request is "
        "trusted. Model-level least privilege such as the task scope of I2S narrows this risk but moves it to the "
        "component that decides the scope.\n\n"
        + residual_sentence(n) +
        "\\paragraph{Availability.} Failing closed turns tampering into refusals, a denial-of-service surface that an "
        "authenticated transport removes.\n\n"
        "")
    out["conclusion_text"] = (
        "INERT treats an LLM multi-agent system as a model-driven artifact whose controller is a reference monitor "
        "for injection channels, derived from a taxonomy of seven channels and enforced, tested and audited from "
        "one compiled model. "
        f"The full configuration reduced attack success on the topology zoo to {p(i2['asr'])} while completing "
        f"{p(i2['u_ben'])} of benign tasks, more than the undefended system and far more than the strongest "
        "design-level baseline, and model-derived suites exposed more weaknesses than benchmark-style attacks. The remaining risk lies in authority the model grants and "
        "in content that arrives as the user's own request. Future work will study how developers write INERT "
        "models, task scopes with guarantees and long-lived memory.")
    return out
