from __future__ import annotations

from typing import List

from .detector import ProfileTarget


def generate_input_expr(target: ProfileTarget, n: int) -> str:
    """
    Return a Python expression string that, when evaluated, yields
    a synthetic input of "size" n appropriate for the target.
    """
    kind = target.input_kind

    if kind == "string":
        return f"'x' * {n}"
    if kind == "dict":
        return f"{{str(i): i for i in range({n})}}"
    if kind == "int":
        return str(n)

    # Default: list of ints
    return f"[i for i in range({n})]"


def default_sizes() -> List[int]:
    return [10, 50, 100, 500, 1000, 5000]

