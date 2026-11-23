"""M5: generated suites cover 100% of feasible obligations; tests execute on INERT and B0."""
import pytest

from inert.agents.llm import MockLLM
from inert.attacks.coverage import benchmark_suite, generate
from inert.compiler import compile_model
from inert.eval.harness import run_case
from inert.eval.zoo import build_model, tasks, zoo_models


@pytest.mark.parametrize("t,s,f", zoo_models())
def test_full_feasible_coverage(t, s, f):
    ir = compile_model(build_model(t, s, f))
    res = next(iter(tasks(f, 1)[0].resources))
    tests, obs = generate(ir, f, res)
    feasible = {o.id for o in obs if o.feasible}
    assert feasible and {x.obligation for x in tests} == feasible
    # deterministic suites
    assert [x.to_dict() for x in generate(ir, f, res)[0]] == [x.to_dict() for x in tests]


@pytest.mark.parametrize("t,s,f", [("chain", 3, "email"), ("star", 5, "web"), ("pcr", 3, "code"),
                                   ("hierarchical", 5, "reply"), ("debate", 3, "email")])
def test_tests_execute_on_inert_and_b0(t, s, f):
    ir = compile_model(build_model(t, s, f))
    task = tasks(f, 1)[0]
    res = next(iter(task.resources))
    tests, _ = generate(ir, f, res, max_tests=12)
    for att in tests + benchmark_suite(ir, f, res):
        for d in ("B0", "I2"):
            rec = run_case(ir, task, d, att, MockLLM(), 0)
            assert "asr" in rec
            if d == "I2":
                assert rec["replay_ok"]
