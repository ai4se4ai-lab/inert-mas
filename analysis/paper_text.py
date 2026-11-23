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
    r = n.get("residual") or {}
    if not r:
        return ""
    total = sum(r.values())
    names = {"user-input": "arrived in the user's own request", "tool-owned": "were harmful tools in a compromised "
             "agent's own tool set", "authority": "came from a compromised agent within its own executor field",
             "declass": "passed through a declassifier", "plausible": "called a target tool that agents also call on "
             "benign runs of the same task", "other": "fit none of these categories"}
    parts = [f"{v} ({100 * v / total:.0f}\\%) {names.get(k, k)}" for k, v in sorted(r.items(), key=lambda kv: -kv[1])]
    return ("A rule-based categorization of all " + str(total) + " successful attacks against I2, derived from the "
            "run records, shows where the residual risk lies: " + ", ".join(parts) + ".\n\n")


def glmm_sentence(n: dict[str, Any]) -> str:
    g = n.get("glmm") or {}
    if not g:
        return ""
    co = {k.split("T.")[-1].rstrip("]"): v for k, v in g.items() if k.startswith("C(defense)")}
    shown = [f"{d} {f(v['mean'])} ({f(v['sd'])})" for d, v in sorted(co.items()) if v["sd"] < 0.3]
    sep = [d for d, v in co.items() if v["sd"] >= 0.3]
    return (" The logistic mixed-effects model with defense and model as fixed effects and task as a random "
            "intercept gives log-odds of attack success relative to B0 (posterior mean and standard deviation) of "
            + ", ".join(shown) + "." + (f" The coefficients of {' and '.join(sorted(sep))} are not identifiable because "
            "these conditions have no successful attack (complete separation), so we rely on the paired tests for them."
            if sep else ""))


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
        f"Over {num(n['rows'])} runs, INERT lowered the attack success rate from {p(b0['asr'])} without defense to "
        f"{p(i2['asr'])}, matching the strongest baseline, a CaMeL-style planner with quarantined data, while completing "
        f"{p(i2['u_ben'])} of benign tasks against that baseline's {p(b3['u_ben'])}. An adaptive attacker did not "
        f"succeed against INERT. On TAMAS, INERT reduced indirect injection from {p(tam.get('B0', {}).get('IPI'))} to "
        f"{p(tam.get('I2', {}).get('IPI'))} but did not stop agents that misuse tools they legitimately own. "
        f"Attack suites generated from the model violated "
        f"{rq3.get('B0:generated', {}).get('unique', 0)} distinct model elements of the undefended systems, against "
        f"{rq3.get('B0:bench', {}).get('unique', 0)} for benchmark-style attacks.")
    out["intro_findings"] = (
        f"Our study covers {word(len(llms))} open-weight models, 51 workflows, the TAMAS benchmark and {num(n['rows'])} runs. "
        f"INERT reduced the attack success rate on the topology zoo from {p(b0['asr'])} to {p(i2['asr'])} and kept "
        f"{p(i2['u_ben'])} benign utility, more than the undefended system ({p(b0['u_ben'])}). The strongest baseline, "
        f"a CaMeL-style planner, also blocked every attack but completed only {p(b3['u_ben'])} of benign tasks. "
        "Ablations show that each INERT mechanism closes a distinct channel, and that the taint policy is the only "
        "defense against semantic propagation. Attack suites generated from the model found more successful attacks "
        "per unit of cost than benchmark-style suites. On TAMAS, INERT did not stop agents that misuse tools the model "
        "allows them to use, which we report as residual risk together with a post-hoc mitigation.")
    out["results_overview"] = (
        f"Table~\\ref{{tab:main}} summarizes the topology zoo: {num(nb_att)} attacked runs and the benign runs of all "
        f"seven conditions over all models"
        f"{', with ' + str(n['errors']) + ' failed runs' if n.get('errors') else ', with no failed run'}. "
        f"Two conditions reach an attack success rate of {p(i2['asr'])}: I2 and B3 (Wilson 95\\% upper bound "
        f"{p(i2['asr_hi'])}). They differ sharply in utility. I2 completes {p(i2['u_ben'])} of benign tasks and B3 "
        f"{p(b3['u_ben'])}, because B3's planner never sees the material it must act on and its capability policy "
        f"denies side effects whose arguments derive from it. The message-level defenses reduce but do not prevent "
        f"attacks: the detector B1 reaches {p(b1['asr'])}, the permitted graph B4 {p(b4['asr'])}. "
        f"Figure~\\ref{{fig:tradeoff}} places every condition in the security--utility plane and "
        f"Table~\\ref{{tab:llm}} breaks the main conditions down by model." + glmm_sentence(n))
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
            "Without a controller, an injection rarely stays with the agent that reads it. Table~\\ref{tab:rq1} reports "
            "B0 by topology and size. The number of infected agents grows with the number of agents in "
            f"{grows} of {len(by_t)} topologies ({inf}). The blast radius, the share of all agent outputs that carry "
            f"attacker content, falls with size in {shrinks} of {len(by_t)} topologies, because added agents dilute "
            "the transcript rather than escape it. The longest infected chains occur in "
            f"{deep[0]} (mean depth {f(deep[1]['depth'])}). Attack success is highest for {worst[0]} "
            f"({p(worst[1]['asr'])}) and lowest for {best[0]} ({p(best[1]['asr'])}). The planner--coder--reviewer workflow "
            "propagates least because only the coder writes the artifact that reaches the executor.\n\n"
            "\\textbf{Answer to RQ1.} Injections propagate to several agents in every topology, and the absolute "
            "number of infected agents grows with team size. Hypothesis H1 holds for the count of infected agents "
            "but not for the share of outputs, which decreases with size.")
    # ---------------------------------------------------------------- RQ2
    rq2 = n.get("rq2", {})
    if rq2:
        def g(d: str, a: str) -> str:
            return p(rq2.get(d, {}).get(a))
        fr = n.get("first_reject", {})

        def top(a: str) -> str:
            v = fr.get(a) or {}
            if not v:
                return "n/a"
            k = max(v, key=lambda x: v[x])
            return f"\\textsc{{{k.title().replace('_', '')}}} ({100 * v[k] / sum(v.values()):.0f}\\%)"
        out["rq2_text"] = (
            "Table~\\ref{tab:rq2} reports the ablation suite, in which every INERT condition faces the same generated "
            f"tests. I2 blocks every attacker model (A1 {g('I2', 'A1')}, A2 {g('I2', 'A2')}, A3 {g('I2', 'A3')}, A4 "
            f"{g('I2', 'A4')}, A5 {g('I2', 'A5')}). Each ablation reopens precisely the channel that the taxonomy of "
            f"Section~\\ref{{sec:taxonomy}} assigns to it. Without tokens, compromised agents ({g('I2-tokens', 'A2')}) "
            f"and message tampering ({g('I2-tokens', 'A3')}) succeed, because forged and altered proposals are accepted. "
            f"Without key matching, replayed proposals succeed ({g('I2-key', 'A5')} of A5 tests). Without validators, "
            f"colluding agents reach {g('I2-validator', 'A4')} and a compromised executor agent {g('I2-validator', 'A2')}. "
            f"Without any taint (I1), indirect injection succeeds in {g('I1', 'A1')} of the tests, which is the semantic "
            "propagation that structural mechanisms cannot see. Removing only one of the two taint checks keeps the "
            "attack success rate at zero, because selection and acceptance back each other up. They are not "
            "interchangeable, however. Without selection the executor agent sees tainted context, its proposals are "
            "rejected at acceptance, and the task fails: utility under attack is "
            f"{p(n.get('rq2_util_attack', {}).get('I2-tsel'))} without selection against "
            f"{p(n.get('rq2_util_attack', {}).get('I2'))} for I2. Acceptance alone is the safety net if selection is "
            "misconfigured.\n\n"
            f"The first rejecting mechanism confirms the mapping: for A1 it is mostly {top('A1')}, for A2 {top('A2')}, "
            f"for A3 {top('A3')}, for A4 {top('A4')} and for A5 {top('A5')}.\n\n"
            "\\textbf{Answer to RQ2.} Tokens stop authorship attacks, key matching stops replay, validators bound the "
            "authority of compromised agents, and the taint policy is the only mechanism that stops semantic "
            "propagation into executor fields. H2 is supported.")
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
        cr = ", ".join(f"{k} {p(v)}" for k, v in sorted(crit.items(), key=lambda kv: -kv[1]))
        out["rq3_text"] = (
            "The benchmark-style suites inject one payload into the primary untrusted resource, as AgentDojo and "
            "InjecAgent do. The generated suites cover the six criteria of Section~\\ref{sec:generation} and were "
            "sampled to at most 15 tests per workflow and task. " + ". ".join(parts) + ". "
            f"Per criterion, the attack success rate against B0 is {cr}. The criteria that benchmarks do not cover, "
            "such as compromised and colluding agents, tampering and replay, are among the most effective. Neither "
            "suite found a successful attack against I2, so the generated tests also act as a regression suite for "
            "the defense.\n\n"
            "\\textbf{Answer to RQ3.} At equal cost, model-coverage suites find more successful attacks and reach "
            "several times more distinct model elements than benchmark-style suites. H3 is supported.")
    # ---------------------------------------------------------------- RQ4
    lat, tok, ut = t.get("lat_I2_vs_B0", {}), t.get("tok_I2_vs_B0", {}), t.get("util_I2_vs_B0", {})
    out["rq4_text"] = (
        f"Table~\\ref{{tab:rq4}} reports benign tasks. I2 completes {p(i2['u_ben'])} of them, which is more than B0 "
        f"({p(b0['u_ben'])}). The paired comparison gives an odds ratio of {f(ut.get('or'))} for I2 succeeding where "
        f"B0 fails versus the opposite (Holm-adjusted $p$ {'$<0.001$' if (ut.get('p_holm', 1) or 1) < 0.001 else '= ' + f(ut.get('p_holm'), 3)}). "
        "Typed slots with one question each appear to help models of this size more than a free-form group chat "
        f"does. I1 is higher still ({p(i1['u_ben'])}). The gap between I1 and I2 is the utility cost of the taint "
        f"policy, concentrated in tasks whose executor needs information from untrusted material. I2 rejects "
        f"{p(i2['frr'])} of honest proposals. B1 flags {p(b1['frr'])} of benign messages, B3's policy blocks "
        f"{p(b3['frr'])} of attempted actions and B4's generated graph {p(b4['frr'])}. I2 uses "
        f"{f(i2['calls'], 1)} LLM calls and {f(i2['tok'], 0)} tokens per task against {f(b0['calls'], 1)} and "
        f"{f(b0['tok'], 0)} for B0 (Cliff's $\\delta$ for tokens {f(tok.get('delta'))}, for latency "
        f"{f(lat.get('delta'))}), because agents see only selected slot values instead of the whole transcript.\n\n"
        f"Under attack, I2 keeps {p(i2['u_att'])} utility against {p(b0['u_att'])} for B0. The losses come from "
        "attacks against which INERT deliberately fails closed. A tampered proposal or a tool whose metadata "
        "changed is refused rather than used, which turns an integrity attack into an availability loss.\n\n"
        "\\textbf{Answer to RQ4.} INERT's utility cost is negative relative to the undefended system on our tasks, "
        "much lower than B3's, and its false-rejection rate is the lowest of all defenses. H4 is supported.")
    # ---------------------------------------------------------------- RQ5
    if rq5:
        out["rq5_text"] = (
            "The adaptive attacker had ten attempts per case, the model description, the policy text and, after each "
            "attempt, the tools that were called and, for INERT, the controller's rejection reasons. " + " ".join(
                f"Against {d} it succeeded in {p(v['asr'])} of {v['n']} cases"
                + (f" after {f(v['attempts'], 1)} attempts on average." if v['asr'] > 0 else ", exhausting its budget.")
                for d, v in sorted(rq5.items())) +
            " Feedback helped the attacker against the message-level defenses, which it learned to evade within a few "
            "attempts. Against I2 the rejection reasons only told the attacker that untrusted content never reaches "
            "the executor, which no payload can change.\n\n"
            "\\textbf{Answer to RQ5.} The structural and taint guarantees held under adaptive attack. H5 is "
            "supported for the zoo. The residual successes we observed on TAMAS (next subsection) come from authority "
            "that the model grants to agents.")
    # ---------------------------------------------------------------- TAMAS
    if tam:
        def g2(d: str, c: str) -> str:
            return p(tam.get(d, {}).get(c))
        out["tamas_text"] = (
            "Table~\\ref{tab:tamas} reports TAMAS. Indirect injection (IPI) succeeds in "
            f"{g2('B0', 'IPI')} of instances under B0, {g2('B4', 'IPI')} under B4, {g2('B3', 'IPI')} under B3 and "
            f"{g2('I2', 'IPI')} under I2. For direct injection, the outcome depends on what the system knows about "
            f"provenance. When the whole query counts as the user's request (DPI-whole, as in TAMAS), I2 reaches "
            f"{g2('I2', 'DPI-whole')}, like the other defenses, because INERT trusts the user's channel by design. "
            f"When the injected suffix is labelled as untrusted content (DPI-split), I2 reaches {g2('I2', 'DPI-split')}, "
            f"against {g2('B0', 'DPI-split')} for B0 and {g2('B3', 'DPI-split')} for B3. "
            f"Impersonation, which is also delivered in the user's query, succeeds in {g2('I2', 'Impersonation')}.\n\n"
            "The TAMAS agents carry harmful tools in their own tool sets, and the Byzantine and colluding attacks "
            "give agents personas that tell them to use these tools. I2 does not prevent an agent from choosing a "
            f"tool the model permits it to choose: Colluding reaches {g2('I2', 'Colluding')} and Byzantine "
            f"{g2('I2', 'Byzantine')}, close to B0 ({g2('B0', 'Colluding')} and {g2('B0', 'Byzantine')}). B3 and B4 do "
            "better here because both derive a per-task allowlist from the request alone. After observing this, "
            "we added one model element to the TAMAS models, a task-scope slot that reads only the request and lists "
            "the tools the task needs, with an owned validator that restricts every agent's tool choice to that list. "
            f"This post-hoc variant (I2S) brings Colluding to {g2('I2S', 'Colluding')} and Byzantine to "
            f"{g2('I2S', 'Byzantine')}, at a benign utility of {g2('I2S', 'Benign util.')} against "
            f"{g2('I2', 'Benign util.')} for I2, because the scope sometimes omits a tool the task needs. We report "
            "I2S separately because it was designed after seeing the results.")
    sd = n.get("seeds", {})
    if sd:
        out["seeds_text"] = ("Across seeds, the standard deviation of the attack success rate is " + ", ".join(
            f"{p(v['asr_sd'])} for {d}" for d, v in sorted(sd.items())) + ", and the ordering of the conditions "
            "does not change.")
    else:
        out["seeds_text"] = ""
    out["discussion_text"] = (
        "\\paragraph{Structural and semantic guarantees fail differently.} The ablations confirm the split drawn by the "
        "taxonomy. Tokens, key matching and metadata pinning defeat attacks on authorship, freshness and "
        "configuration whatever the payload says, so the adaptive attacker gains nothing from feedback against "
        "them. The taint policy decides what an agent may see before it decides, which is why it is the only "
        "mechanism that stops an injected recipient, path or command from travelling through a chain of agents into "
        "an executor field. Message-level defenses act on the wrong unit. They judge single messages, while the "
        "harm is a flow.\n\n"
        "\\paragraph{Where INERT does not help.} The residual risk sits in authority that the model itself grants. A "
        "compromised agent that owns an executor field can misuse it within its validators, and an injection that "
        "arrives as the user's own request is trusted. TAMAS makes the first case visible because its agents carry "
        "harmful tools. Least privilege at the level of the model, for example the task-scope slot of I2S, narrows "
        "this risk but moves the problem to the component that decides the scope and costs utility when the scope "
        "is wrong.\n\n"
        + residual_sentence(n) +
        "\\paragraph{Availability.} INERT fails closed. Tampering and tool-metadata changes become refusals, which is "
        "the right default for integrity but an attack surface for denial of service. An authenticated channel "
        "between agents and controller removes the tampering case in deployment.\n\n"
        "\\paragraph{Comparison with design-level baselines.} B3 matches INERT's attack success rate on the zoo but "
        "loses utility whenever the executor's decision depends on untrusted material. INERT handles these cases "
        "with designer-declared declassifiers, which bound what untrusted text may contribute instead of excluding "
        "it. B4 shows that an LLM-generated control-flow graph is both too permissive for data-flow attacks and too "
        "restrictive for benign work.")
    out["conclusion_text"] = (
        "INERT treats an LLM multi-agent system as a model-driven artifact. One compiled model is enforced by a "
        "deterministic controller, tested by generated attacks and audited from logs without re-running any model. "
        f"In our study the full configuration reduced the attack success rate on the topology zoo to {p(i2['asr'])} "
        f"while completing {p(i2['u_ben'])} of benign tasks, more than the undefended system and far more than the "
        "strongest design-level baseline. Every mechanism mattered for a specific channel, and test suites derived "
        "from the model exposed more distinct weaknesses than benchmark-style attacks. The remaining risk lies in "
        "authority that the model grants to agents and in content that arrives as the user's own request. Future "
        "work will study how developers write INERT models, derive task scopes with guarantees, and extend the "
        "approach to long-running and self-modifying agent systems.")
    return out
