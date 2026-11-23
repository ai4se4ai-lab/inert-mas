"""M6 replay log: JSONL events with a SHA-256 hash chain (tampering is detectable)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..canon import canonical_bytes, sha256_hex

GENESIS = "0" * 64


class EventLog:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.head = GENESIS

    def append(self, kind: str, **data: Any) -> dict[str, Any]:
        ev = {"seq": len(self.events), "kind": kind, **data, "prev": self.head}
        canonical_bytes(ev, allow_float=True)
        ev["hash"] = sha256_hex(ev, allow_float=True)
        self.head = ev["hash"]
        self.events.append(ev)
        return ev

    def of(self, *kinds: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["kind"] in kinds]

    def dump(self, path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for e in self.events:
                fh.write(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n")

    @staticmethod
    def load(path: str | Path) -> list[dict[str, Any]]:
        return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def verify_chain(events: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (ok, first bad seq)."""
    prev = GENESIS
    for i, e in enumerate(events):
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("seq") != i or e.get("prev") != prev or sha256_hex(body, allow_float=True) != e.get("hash"):
            return False, i
        prev = e["hash"]
    return True, None
