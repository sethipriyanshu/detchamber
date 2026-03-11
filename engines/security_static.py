from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List

from sandbox.security import DEFAULT_POLICY


@dataclass
class StaticThreat:
    operation: str
    severity: str
    message: str
    lineno: int


def static_security_scan(code: str) -> List[StaticThreat]:
    """Lightweight AST-based scan for obviously dangerous calls."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    threats: List[StaticThreat] = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> Any:  # noqa: ANN401
            op_name: str | None = None

            # Bare builtins: open(), eval(), exec()
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in ("open", "eval", "exec"):
                    op_name = name

            # Attribute calls: os.system, subprocess.run, socket.socket, etc.
            elif isinstance(node.func, ast.Attribute):
                base = getattr(node.func.value, "id", "")
                qual = f"{base}.{node.func.attr}" if base else node.func.attr
                if qual in DEFAULT_POLICY:
                    op_name = qual

            if op_name:
                severity, description = DEFAULT_POLICY.get(
                    op_name, ("HIGH", "Statically detected dangerous operation")
                )
                threats.append(
                    StaticThreat(
                        operation=op_name,
                        severity=severity,
                        message=description,
                        lineno=node.lineno,
                    )
                )

            self.generic_visit(node)

    Visitor().visit(tree)
    return threats

