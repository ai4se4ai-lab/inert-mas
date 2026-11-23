"""M6: replay reproduces decisions; tampered logs are detected; ablations surface violations."""
import copy

from inert.audit.log import verify_chain
from inert.audit.replay import audit
from inert.runtime import controller as C
from tests.test_runtime import TASK, Adv, setup


def test_tamper_detected():
    ir, env, ctl = setup()
    ev = ctl.run(TASK).log.events
    assert verify_chain(ev)[0]
    assert audit(ir, ev, ctl.run_secret).replay_ok
    assert not audit(ir, ev, b"\x00" * 32).replay_ok  # wrong key: commitment mismatch
    bad = copy.deepcopy(ev)
    bad[3]["slot"] = "report"
    ok, at = verify_chain(bad)
    assert not ok and at == 3
    assert not audit(ir, bad, ctl.run_secret).replay_ok


def test_ablation_tokens_off_shows_P2_violation():
    forged = lambda ctl, req: [C.Proposal(req.request_id, req.slot, req.agent, req.key,  # noqa: E731
                                          {"index": 0, "recipient": "bob@corp.example"}, "f" * 64)] \
        if req.slot == "intent" else []
    ir, env, ctl = setup(mech=C.Mechanisms(tokens=False), adversary=Adv(unsolicited=forged))
    r = ctl.run(TASK)
    rep = audit(ir, r.log.events, ctl.run_secret)
    assert rep.replay_ok
    assert rep.violations["P2"]
