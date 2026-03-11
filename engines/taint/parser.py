from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass
class SourceConfig:
    names: Set[str]


@dataclass
class SinkConfig:
    functions: Set[str]


DEFAULT_SOURCES = SourceConfig(
    names={"input", "sys.argv", "os.environ"},
)

DEFAULT_SINKS = SinkConfig(
    functions={"eval", "exec", "os.system", "subprocess.run"},
)


def parse_code(code: str) -> ast.AST:
    return ast.parse(code)


def is_source_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == "input":
        return True
    return False


def is_sink_call(node: ast.Call) -> bool:
    # Simple detection based on fully-qualified-ish name in source
    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
        return True
    if isinstance(node.func, ast.Attribute):
        attr = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
        if attr in {"os.system", "subprocess.run"}:
            return True
    return False

