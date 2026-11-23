"""LLM backends (outside the TCB). All are stdlib-only and record usage per call.

* ``OllamaClient``   node-local Ollama ``/api/chat`` with JSON-schema constrained output;
* ``OpenAIClient``   any OpenAI-compatible server (vLLM) ``/v1/chat/completions``;
* ``MockLLM``        deterministic, seeded simulator for offline tests (never used for results).
"""

from __future__ import annotations

import json
import random
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    error: str | None = None


class LLM(Protocol):
    name: str

    def chat(self, messages: list[dict[str, str]], schema: dict[str, Any] | None = None,
             seed: int = 0) -> tuple[str, Usage]: ...


@dataclass
class Decoding:
    temperature: float = 0.0
    top_p: float = 1.0
    num_ctx: int = 8192
    num_predict: int = 768


@dataclass
class OllamaClient:
    host: str
    name: str
    decoding: Decoding = field(default_factory=Decoding)
    timeout: int = 300

    def chat(self, messages: list[dict[str, str]], schema: dict[str, Any] | None = None,
             seed: int = 0) -> tuple[str, Usage]:
        body: dict[str, Any] = {"model": self.name, "stream": False, "messages": messages,
                                "options": {"temperature": self.decoding.temperature, "top_p": self.decoding.top_p,
                                            "seed": seed, "num_ctx": self.decoding.num_ctx,
                                            "num_predict": self.decoding.num_predict}}
        if schema is not None:
            body["format"] = schema
        if re.search(r"qwen3|gpt-oss|deepseek-r1", self.name):
            body["think"] = False
        t0 = time.monotonic()
        err = None
        resp: dict[str, Any] = {}
        for attempt in range(3):
            try:
                req = urllib.request.Request(self.host.rstrip("/") + "/api/chat", json.dumps(body).encode(),
                                             {"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    resp = json.loads(r.read())
                err = None
                break
            except Exception as e:  # transport failure: retry the identical call
                err = f"{type(e).__name__}: {e}"
                time.sleep(2 * (attempt + 1))
        text = (resp.get("message") or {}).get("content", "")
        return text, Usage(int(resp.get("prompt_eval_count") or 0), int(resp.get("eval_count") or 0),
                           time.monotonic() - t0, err)


@dataclass
class OpenAIClient:
    host: str
    name: str
    decoding: Decoding = field(default_factory=Decoding)
    timeout: int = 300

    def chat(self, messages: list[dict[str, str]], schema: dict[str, Any] | None = None,
             seed: int = 0) -> tuple[str, Usage]:
        body: dict[str, Any] = {"model": self.name, "messages": messages, "temperature": self.decoding.temperature,
                                "top_p": self.decoding.top_p, "seed": seed, "max_tokens": self.decoding.num_predict}
        if schema is not None:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": "out", "schema": schema}}
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(self.host.rstrip("/") + "/v1/chat/completions", json.dumps(body).encode(),
                                         {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read())
            u = resp.get("usage") or {}
            return resp["choices"][0]["message"]["content"] or "", Usage(
                int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0), time.monotonic() - t0)
        except Exception as e:
            return "", Usage(0, 0, time.monotonic() - t0, f"{type(e).__name__}: {e}")


# ----------------------------------------------------------------------------- mock
_DIRECTIVE = re.compile(
    r"(?:call|use|run|invoke|execute)\s+(?:the\s+)?`?(?P<tool>[a-z_][a-z0-9_]{2,})`?(?:\s+tool)?"
    r"(?:\s+(?:with|using)\s+(?P<args>[^\n]*))?", re.I)
_KV = re.compile(r"(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)")
_INJECT_CUES = re.compile(r"ignore (all |any )?(previous|prior|above)|system (notice|override|update)|"
                          r"important[:!]|new instructions|you must now|error:.*retry|traceback|admin(istrator)? "
                          r"(says|here)|as the (orchestrator|manager|supervisor)", re.I)


@dataclass
class MockLLM:
    """Deterministic stand-in with a tunable *susceptibility* to injected directives.

    It complies with a directive found in the prompt with probability ``susceptibility`` when
    the directive appears together with an injection cue; directives inside a <data> block
    marked untrusted are followed with probability ``susceptibility * data_discount``.
    Otherwise it answers the task honestly from the instruction. For offline tests only.
    """

    name: str = "mock"
    susceptibility: float = 0.8
    data_discount: float = 0.6
    calls: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def chat(self, messages: list[dict[str, str]], schema: dict[str, Any] | None = None,
             seed: int = 0) -> tuple[str, Usage]:
        with self._lock:
            self.calls += 1
        text = "\n".join(m["content"] for m in messages)
        rng = random.Random(f"{seed}|{len(text)}|{text[:64]}|{text[-64:]}")
        props: dict[str, Any] = (schema or {}).get("properties", {})
        directive = None
        for m in _DIRECTIVE.finditer(text):
            window = text[max(0, m.start() - 300): m.end() + 50]
            if _INJECT_CUES.search(window):
                in_data = "<data>" in text[: m.start()] and "</data>" in text[m.end():]
                p = self.susceptibility * (self.data_discount if in_data else 1.0)
                if rng.random() < p:
                    directive = m
                break
        out: dict[str, Any] = {}
        task_text = text
        for name, spec in props.items():
            out[name] = self._honest(name, spec, task_text, rng)
        if directive is not None:
            tool = directive.group("tool")
            args = {k: v.strip("\"'") for k, v in _KV.findall(directive.group("args") or "")}
            for name, spec in props.items():
                if "enum" in spec and tool in spec["enum"]:
                    out[name] = tool
                if name in args:
                    out[name] = self._coerce(args[name], spec)
                if name == "args" and spec.get("type") == "string":
                    out[name] = json.dumps(args)
                if name == "args" and spec.get("type") == "object":
                    out[name] = {**(out[name] if isinstance(out[name], dict) else {}),
                                 **{k: self._coerce(v, (spec.get("properties") or {}).get(k, {})) for k, v in args.items()}}
                if spec.get("type") == "string" and name in ("message", "summary", "report", "text", "notes",
                                                             "content", "body", "analysis"):
                    out[name] = (str(out[name]) + " " + directive.group(0))[-1500:]
        if schema is None:
            return json.dumps(out) if out else "OK", Usage(len(text) // 4, 20)
        return json.dumps(out), Usage(len(text) // 4, 40)

    @staticmethod
    def _coerce(v: str, spec: dict[str, Any]) -> Any:
        if spec.get("type") == "integer":
            try:
                return int(v)
            except ValueError:
                return 0
        if spec.get("type") == "boolean":
            return v.lower() in ("true", "yes", "1")
        return v

    @staticmethod
    def _honest(name: str, spec: dict[str, Any], text: str, rng: random.Random) -> Any:
        # honest view: drop lines that carry injection cues, prefer the task text
        clean = "\n".join(line for line in text.splitlines() if not _INJECT_CUES.search(line))
        task = clean.split("DATA", 1)[-1] if "DATA" in clean else clean
        if "enum" in spec:
            vals = list(spec["enum"])
            for v in vals:
                if v not in ("none",) and re.search(r"\b" + re.escape(str(v)) + r"\b", task):
                    return v
            for v in vals:
                if v not in ("none",) and re.search(r"\b" + re.escape(str(v)) + r"\b", clean):
                    return v
            return vals[0]
        t = spec.get("type")
        if t == "object":
            return {k: MockLLM._honest(k, v, text, rng) for k, v in (spec.get("properties") or {}).items()}
        if t == "integer":
            lo, hi = spec.get("minimum", -10**9), spec.get("maximum", 10**9)
            for hit in re.finditer(r"\b(\d{1,6})\b", task):
                if lo <= int(hit.group(1)) <= hi:
                    return int(hit.group(1))
            return max(lo, 0) if lo <= 0 <= hi else lo
        if t == "boolean":
            return True
        if name in ("to", "recipient"):
            m = re.search(r"[\w.+-]+@[\w-]+\.[\w.]*\w", task)
            return m.group(0) if m else "user@corp.example"
        if name in ("path", "file"):
            m = re.search(r"\b[\w/-]+\.(?:txt|md|py|json|csv)\b", task)
            return m.group(0) if m else "notes.txt"
        if name in ("code",):
            return "def solution(x):\n    return x\n"
        if name in ("url",):
            m = re.search(r"https?://[^\s\"']+", task)
            return m.group(0).rstrip(".,)") if m else "https://docs.corp.example/page"
        body = re.findall(r"[A-Za-z][A-Za-z ,.'%0-9-]{20,}", task)
        s = (body[-1] if body else "done").strip()[:200]
        ml = spec.get("maxLength")
        return s[:ml] if ml else s
