from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List


@dataclass
class ProfileTarget:
    name: str
    param_names: List[str]
    param_count: int
    input_kind: str  # "list", "string", "dict", "int"


def _infer_input_kind(param_names: List[str]) -> str:
    lowered = [p.lower() for p in param_names]
    if any(name in ("items", "arr", "array", "data", "numbers", "values") for name in lowered):
        return "list"
    if any(name in ("text", "s", "string", "line") for name in lowered):
        return "string"
    if any(name in ("mapping", "d", "dict", "mapping") for name in lowered):
        return "dict"
    return "list" if lowered else "int"


def detect_profile_targets(code: str) -> List[ProfileTarget]:
    """Parse user code and return top-level functions to profile."""
    tree = ast.parse(code)
    targets: List[ProfileTarget] = []

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            param_names = [arg.arg for arg in node.args.args]
            targets.append(
                ProfileTarget(
                    name=node.name,
                    param_names=param_names,
                    param_count=len(param_names),
                    input_kind=_infer_input_kind(param_names),
                )
            )

    return targets

