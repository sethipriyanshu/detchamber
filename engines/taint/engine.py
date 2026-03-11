from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional

from .parser import is_sink_call, is_source_call, parse_code


@dataclass
class TaintFinding:
    source_var: str
    sink_func: str
    source_line: int
    sink_line: int


@dataclass
class TaintReport:
    findings: List[TaintFinding]


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.tainted: Dict[str, int] = {}  # var -> first tainted line
        self.findings: List[TaintFinding] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Source: input()
        if is_source_call(node):
            # Assign to a variable if we are in an Assign context
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = node.lineno

        # Sink: eval/exec/os.system/subprocess.run
        if is_sink_call(node):
            sink_name = self._sink_name(node)
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self.findings.append(
                        TaintFinding(
                            source_var=arg.id,
                            sink_func=sink_name,
                            source_line=self.tainted[arg.id],
                            sink_line=node.lineno,
                        )
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Propagate taint through simple assignments: b = a
        value = node.value
        if isinstance(value, ast.Name) and value.id in self.tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = self.tainted[value.id]

        self.generic_visit(node)

    @staticmethod
    def _sink_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            base = getattr(node.func.value, "id", "")
            return "{}.{}".format(base, node.func.attr) if base else node.func.attr
        return "unknown"


def _attach_parents(tree: ast.AST) -> None:
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            setattr(child, "parent", parent)


def run_taint(code: str) -> TaintReport:
    """
    Very simple taint analysis:
    - Sources: input() assigned to a variable
    - Propagation: simple assignments var2 = var1
    - Sinks: eval/exec/os.system/subprocess.run
    """
    tree = parse_code(code)
    _attach_parents(tree)
    visitor = _TaintVisitor()
    visitor.visit(tree)
    return TaintReport(findings=visitor.findings)

