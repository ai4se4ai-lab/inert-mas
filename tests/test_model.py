"""M1: YAML round trip; one passing and one failing fixture per lint rule; zoo models compile."""
import pytest

from inert.eval.zoo import build_model, zoo_models
from inert.model import dump_yaml, lint, load_yaml, loads_yaml
from inert.model.mermaid import import_mermaid
from inert.model.schema import FieldSpec, Label, MASModel

EX = "models/examples/email_summary.inert.yaml"


def test_roundtrip_identity():
    m = load_yaml(EX)
    text = dump_yaml(m)
    assert dump_yaml(loads_yaml(text)) == text
    assert loads_yaml(text) == m


def _mutate(m: MASModel, sid: str, **upd):
    return m.model_copy(update={"slots": tuple(s.model_copy(update=upd) if s.id == sid else s for s in m.slots)})


def codes(m):
    return {i.code for i in lint(m)}


def test_example_lints_clean():
    assert lint(load_yaml(EX)) == []


def test_L1_unreachable():
    m = load_yaml(EX)
    bad = _mutate(m, "report", reads=())
    assert "L1" in codes(bad)


def test_L2_cycle():
    m = load_yaml(EX)
    bad = _mutate(m, "intent", reads=("task", "report.report"))
    assert "L2" in codes(bad)


def test_L3_untrusted_to_executor():
    m = load_yaml(EX)
    bad = _mutate(m, "intent", reads=("task", "fetch.result"))
    bad = bad.model_copy(update={"slots": tuple(s for s in bad.slots)})
    # intent now reads the e-mail it chooses -> cycle; use summarize->recipient instead
    m2 = _mutate(m, "summarize", fields={"summary": FieldSpec(type="string", role="executor")})
    assert "L3" in codes(m2)
    assert "L3" not in codes(m)


def test_L4_owner():
    m = load_yaml(EX)
    with pytest.raises(ValueError):
        _mutate(m, "summarize", owner=None).model_validate(_mutate(m, "summarize", owner=None).model_dump())
    assert "L4" in codes(_mutate(m, "summarize", owner="ghost"))


def test_L5_free_text_into_executor():
    m = load_yaml(EX)
    bad = _mutate(m, "send", args_from={"to": "summarize.summary", "body": "summarize.summary"})
    assert "L5" in codes(bad)


def test_L6_dangling():
    m = load_yaml(EX)
    assert "L6" in codes(_mutate(m, "summarize", reads=("fetch.nope",)))


def test_mermaid_import():
    m = import_mermaid('stateDiagram-v2\nstate "Planner: plan it" as plan\nstate "Coder: code it" as code\n'
                       '[*] --> plan\nplan --> code\ncode --> [*]\n')
    assert [s.id for s in m.slots] == ["task", "plan", "code"]
    assert m.release.outputs == ("code",)
    assert lint(m) == []


@pytest.mark.parametrize("t,s,f", zoo_models())
def test_zoo_models_valid(t, s, f):
    m = build_model(t, s, f)
    assert {i.code for i in lint(m)} <= {"L3"}   # faithful designs: only taint paths, enforced at runtime
    assert m.slot("task").label == Label.user
