"""M2: byte-identical compilation; hash sensitivity (Hypothesis)."""
from hypothesis import given, settings
from hypothesis import strategies as st

from inert.compiler import compile_model
from inert.model import dump_yaml, load_yaml, loads_yaml

EX = "models/examples/email_summary.inert.yaml"


def test_deterministic():
    m = load_yaml(EX)
    assert compile_model(m).to_bytes() == compile_model(m).to_bytes()
    assert compile_model(loads_yaml(dump_yaml(m))).plan_hash == compile_model(m).plan_hash


@settings(max_examples=60, deadline=None)
@given(st.text(min_size=1, max_size=40))
def test_instruction_change_changes_hash(txt):
    m = load_yaml(EX)
    s = m.slot("summarize")
    if txt == s.instruction:
        return
    m2 = m.model_copy(update={"slots": tuple(x.model_copy(update={"instruction": txt}) if x.id == "summarize" else x
                                              for x in m.slots)})
    a, b = compile_model(m), compile_model(m2)
    assert a.plan_hash != b.plan_hash
    assert a.contract_hash("summarize") != b.contract_hash("summarize")
    assert a.contract_hash("intent") == b.contract_hash("intent")


@settings(max_examples=40, deadline=None)
@given(st.text(min_size=1, max_size=30))
def test_tool_metadata_change_changes_hash(desc):
    m = load_yaml(EX)
    t = m.tool("send_email")
    if desc == t.description:
        return
    m2 = m.model_copy(update={"tools": tuple(x.model_copy(update={"description": desc}) if x.name == "send_email" else x
                                              for x in m.tools)})
    a, b = compile_model(m), compile_model(m2)
    assert a.tool_hash("send_email") != b.tool_hash("send_email")
    assert a.contract_hash("send") != b.contract_hash("send")


def test_equal_models_equal_hash_after_reordering_yaml_keys():
    import yaml
    m = load_yaml(EX)
    d = yaml.safe_load(dump_yaml(m))
    d2 = {k: d[k] for k in reversed(list(d))}
    assert compile_model(loads_yaml(yaml.safe_dump(d2))).plan_hash == compile_model(m).plan_hash
