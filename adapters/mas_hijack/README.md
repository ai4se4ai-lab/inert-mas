# MAS hijacking (Triedman et al., arXiv:2503.12188)
Re-implemented, not vendored: the fake-error/traceback payload class (`src/inert/attacks/payloads.py`,
class `fake_error`) and LLM-chosen handoffs in B0 (`baselines/native.py`) reproduce the control-flow
hijacking channel. Code execution is simulated (`run_code` records code, never runs it).
