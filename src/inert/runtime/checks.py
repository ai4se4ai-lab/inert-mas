"""Deterministic schema checks, owned validators and declassifiers (TCB, no LLM)."""

from __future__ import annotations

import re
from typing import Any

from ..model.schema import Declassifier, FieldSpec, Validator


def check_field(spec: FieldSpec, v: Any) -> str | None:
    if spec.type == "string":
        if not isinstance(v, str):
            return "not a string"
        if spec.max_length is not None and len(v) > spec.max_length:
            return f"longer than {spec.max_length}"
        if spec.pattern is not None and not re.fullmatch(spec.pattern, v):
            return "pattern mismatch"
    elif spec.type == "integer":
        if not isinstance(v, int) or isinstance(v, bool):
            return "not an integer"
        if spec.minimum is not None and v < spec.minimum:
            return "below minimum"
        if spec.maximum is not None and v > spec.maximum:
            return "above maximum"
    elif spec.type == "boolean":
        if not isinstance(v, bool):
            return "not a boolean"
    elif spec.type == "enum":
        if v not in (spec.values or ()):
            return "not an allowed value"
    return None


def check_schema(fields: dict[str, FieldSpec], value: Any) -> str | None:
    if not isinstance(value, dict):
        return "proposal is not an object"
    extra = set(value) - set(fields)
    if extra:
        return f"unexpected fields {sorted(extra)}"
    for name, spec in fields.items():
        if name not in value:
            return f"missing field {name}"
        err = check_field(spec, value[name])
        if err:
            return f"{name}: {err}"
    return None


def run_validator(v: Validator, value: dict[str, Any], inputs_text: str,
                  context: dict[str, Any] | None = None) -> str | None:
    x = value.get(v.field)
    s = x if isinstance(x, str) else str(x)
    if v.kind == "max_length" and len(s) > int(v.param):
        return f"{v.field} too long"
    if v.kind == "nonempty" and not s.strip():
        return f"{v.field} empty"
    if v.kind == "not_contains":
        for bad in (v.param if isinstance(v.param, list) else [v.param]):
            if str(bad).lower() in s.lower():
                return f"{v.field} contains forbidden {bad!r}"
    if v.kind == "regex" and not re.fullmatch(str(v.param), s):
        return f"{v.field} fails regex"
    if v.kind == "member_of" and s != "none":
        # value must be one of the identifiers listed in the read ``param`` (e.g. a task scope)
        allowed = set(re.findall(r"[A-Za-z_]\w*", str((context or {}).get(str(v.param), ""))))
        if s not in allowed:
            return f"{v.field} outside the scope declared by {v.param}"
    if v.kind == "one_of_inputs" and s and s.lower() not in inputs_text.lower():
        # value (e.g. a recipient) must literally occur in the trusted inputs it was derived from
        return f"{v.field} not grounded in its inputs"
    return None


def declassify(d: Declassifier, text: Any) -> tuple[bool, Any]:
    """Schema-bounded extraction. Returns (ok, value). Never returns free text."""
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    p = d.params
    if d.kind == "enum":
        values = [str(x) for x in p.get("values", [])]
        low = s.lower()
        hits = [(low.find(val.lower()), val) for val in values
                if re.search(r"(?<![\w-])" + re.escape(val.lower()) + r"(?![\w-])", low)]
        if not hits:
            return False, None
        if p.get("unique", False) and len({h[1] for h in hits}) > 1:
            return False, None
        return True, min(hits)[1]
    if d.kind == "int_range":
        lo, hi = int(p.get("min", 0)), int(p.get("max", 10**9))
        for hit in re.finditer(r"-?\d+", s):
            n = int(hit.group())
            if lo <= n <= hi:
                return True, n
        return False, None
    if d.kind == "regex":
        m = re.search(str(p["pattern"]), s)
        if not m:
            return False, None
        val = m.group(1) if m.groups() else m.group()
        if len(val) > int(p.get("max_length", 64)):
            return False, None
        return True, val
    if d.kind == "bool":
        low = s.lower()
        yes = any(w in low for w in p.get("true_words", ["yes", "true", "pass", "approved"]))
        no = any(w in low for w in p.get("false_words", ["no", "false", "fail", "rejected"]))
        if yes == no:
            return False, None
        return True, yes
    return False, None
