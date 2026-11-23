"""YAML <-> model round trip and JSON Schema export of the DSL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .schema import MASModel


def _plain(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_plain(v) for v in obj]
    return obj


def to_dict(model: MASModel) -> dict[str, Any]:
    """Canonical plain dict: defaults dropped so that YAML -> model -> YAML is identity."""
    return _plain(model.model_dump(mode="json", exclude_defaults=True))  # type: ignore[no-any-return]


def loads_yaml(text: str) -> MASModel:
    return MASModel.model_validate(yaml.safe_load(text))


def load_yaml(path: str | Path) -> MASModel:
    return loads_yaml(Path(path).read_text(encoding="utf-8"))


def dump_yaml(model: MASModel) -> str:
    return yaml.safe_dump(to_dict(model), sort_keys=False, allow_unicode=True, width=110)


def json_schema() -> str:
    return json.dumps(MASModel.model_json_schema(), indent=2, sort_keys=True)
