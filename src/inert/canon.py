"""Canonical JSON encoding and SHA-256 hashing (TCB).

Rules: sorted keys, NFC-normalised strings, compact separators, UTF-8. Floats are
rejected when ``allow_float`` is False (used for IR and keys). Never hash ``repr``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from typing import Any


class CanonicalError(ValueError):
    pass


def _norm(obj: Any, allow_float: bool) -> Any:
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        if not allow_float:
            raise CanonicalError("floats are not allowed in canonical IR/keys")
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalError(f"non-string key {k!r}")
            out[unicodedata.normalize("NFC", k)] = _norm(v, allow_float)
        return out
    if isinstance(obj, list | tuple):
        return [_norm(v, allow_float) for v in obj]
    if isinstance(obj, set | frozenset):
        raise CanonicalError("unordered collections cannot be hashed; sort them first")
    raise CanonicalError(f"unsupported type {type(obj).__name__}")


def canonical_bytes(obj: Any, allow_float: bool = False) -> bytes:
    return json.dumps(_norm(obj, allow_float), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(obj: Any, allow_float: bool = False) -> str:
    return hashlib.sha256(canonical_bytes(obj, allow_float)).hexdigest()


def hmac_hex(secret: bytes, obj: Any) -> str:
    return hmac.new(secret, canonical_bytes(obj, allow_float=True), hashlib.sha256).hexdigest()


def value_hash(value: Any) -> str:
    """Hash of an accepted runtime value (floats allowed: LLM outputs may contain them)."""
    return sha256_hex(value, allow_float=True)
