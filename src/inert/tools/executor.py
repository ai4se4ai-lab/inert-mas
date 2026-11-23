"""Simulated, sandboxed tool environment with recorded I/O.

No tool touches the network or the host: e-mail, files, web pages and code execution are
simulated over an in-memory world. ``run_code`` never executes anything; it records the
code and reports a canned result, so attack payloads are harmless by construction.
Each resource carries a provenance label, so tool output labels are *dynamic*.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..canon import sha256_hex
from ..compiler.ir import tool_metadata
from ..model.schema import Label, MASModel


@dataclass
class ToolCall:
    step: int
    caller: str
    tool: str
    args: dict[str, Any]
    output: str
    label: str
    side_effect: str


ToolImpl = Callable[["Environment", dict[str, Any]], tuple[str, Label]]


@dataclass
class Environment:
    resources: dict[str, tuple[str, Label]] = field(default_factory=dict)   # key -> (content, label)
    impls: dict[str, ToolImpl] = field(default_factory=dict)
    registry: dict[str, dict[str, Any]] = field(default_factory=dict)       # runtime tool metadata (poisonable)
    poison: dict[str, str] = field(default_factory=dict)                     # tool -> injected output suffix
    calls: list[ToolCall] = field(default_factory=list)
    effects: list[dict[str, Any]] = field(default_factory=list)
    step: int = 0
    dispatchers: set[str] = field(default_factory=set)
    side_effects: dict[str, str] = field(default_factory=dict)

    def copy(self) -> Environment:
        return copy.deepcopy(self)

    def registry_hash(self, tool: str) -> str:
        return sha256_hex(self.registry[tool]) if tool in self.registry else ""

    def call(self, caller: str, tool: str, args: dict[str, Any], side_effect: str = "read") -> tuple[str, Label]:
        impl = self.impls.get(tool, generic_impl)
        out, label = impl(self, {"__tool__": tool, **args})
        if tool in self.dispatchers:
            # a dispatcher tool runs the named tool; record the call under the dispatched name
            tool, args = str(args.get("name", "none")), {"args": args.get("args", "")}
            side_effect = self.side_effects.get(tool, side_effect)
            if tool == "none":
                return out, label
        if tool in self.poison:
            out = f"{out}\n{self.poison[tool]}"
            label = Label.external_untrusted
        self.calls.append(ToolCall(self.step, caller, tool, {k: v for k, v in args.items()}, out, label.value,
                                   side_effect))
        if side_effect in ("write", "exec"):
            self.effects.append({"tool": tool, "args": dict(args), "caller": caller})
        return out, label


def generic_impl(env: Environment, args: dict[str, Any]) -> tuple[str, Label]:
    tool = args.pop("__tool__")
    key = f"tool/{tool}"
    if key in env.resources:
        text, label = env.resources[key]
        try:
            text = text.format(**args)
        except (KeyError, IndexError, ValueError):
            pass
        return text, label
    shown = ", ".join(f"{k}={v}" for k, v in sorted(args.items()))
    return f"{tool}({shown}) completed.", Label.user


# ------------------------------------------------------------------ workspace tools
def _read(prefix: str) -> ToolImpl:
    def f(env: Environment, args: dict[str, Any]) -> tuple[str, Label]:
        args.pop("__tool__", None)
        k = f"{prefix}/{next(iter(args.values()), '')}" if args else prefix
        if k in env.resources:
            return env.resources[k]
        return f"not found: {k}", Label.user
    return f


def _send_email(env: Environment, args: dict[str, Any]) -> tuple[str, Label]:
    return f"email sent to {args.get('to')}", Label.user


def _write_file(env: Environment, args: dict[str, Any]) -> tuple[str, Label]:
    env.resources[f"file/{args.get('path')}"] = (str(args.get("content", "")), Label.agent_untrusted)
    return f"wrote {args.get('path')}", Label.user


def _run_code(env: Environment, args: dict[str, Any]) -> tuple[str, Label]:
    code = str(args.get("code", ""))
    return f"[sandbox] executed {len(code)} chars; tests: 3 passed", Label.user


def _post(env: Environment, args: dict[str, Any]) -> tuple[str, Label]:
    return f"posted to {args.get('channel')}", Label.user


WORKSPACE_IMPLS: dict[str, ToolImpl] = {
    "read_email": _read("email"), "fetch_url": _read("web"), "read_file": _read("file"),
    "read_issue": _read("issue"), "search_docs": _read("docs"),
    "send_email": _send_email, "write_file": _write_file, "run_code": _run_code, "post_message": _post,
}


def environment_for(model: MASModel, resources: dict[str, tuple[str, Label]],
                    impls: dict[str, ToolImpl] | None = None) -> Environment:
    env = Environment(resources=dict(resources), impls=dict(impls or WORKSPACE_IMPLS))
    for t in model.model_dump(mode="json")["tools"]:
        env.registry[t["name"]] = tool_metadata(t)
    return env
