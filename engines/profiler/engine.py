from __future__ import annotations

import ast
from typing import List

from .classifier import ComplexityResult, classify
from .detector import ProfileTarget, detect_profile_targets
from .harness import MeasurementMatrix, measure_function
from .input_gen import default_sizes


def _static_estimate_complexity(code: str) -> List[ComplexityResult]:
    """Fallback static complexity estimate based on loop nesting depth."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    results: List[ComplexityResult] = []

    class LoopDepthVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.max_depth = 0
            self._depth = 0

        def generic_visit(self, node: ast.AST) -> None:
            if isinstance(node, (ast.For, ast.While)):
                self._depth += 1
                self.max_depth = max(self.max_depth, self._depth)
                super().generic_visit(node)
                self._depth -= 1
            else:
                super().generic_visit(node)

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            visitor = LoopDepthVisitor()
            visitor.visit(node)
            depth = visitor.max_depth
            if depth <= 0:
                cls = "O(1)"
            elif depth == 1:
                cls = "O(n)"
            else:
                cls = "O(n^2)"
            results.append(
                ComplexityResult(
                    function_name=node.name,
                    complexity_class=cls,
                    confidence=0.25,
                    matrix={},
                )
            )

    return results


def run_profiler(code: str) -> List[ComplexityResult]:
    """
    High-level entry point for the complexity profiler.

    - Detects candidate functions in the submitted code.
    - For each, measures runtime and memory across input sizes.
    - Classifies the observed behavior into a Big-O class.
    - If measurement fails for all functions, falls back to a static estimate.
    """
    targets: List[ProfileTarget] = detect_profile_targets(code)
    if not targets:
        return []

    sizes = default_sizes()
    results: List[ComplexityResult] = []

    for target in targets:
        matrix: MeasurementMatrix = measure_function(code, target, sizes)
        if len(matrix) < 2:
            continue
        kind, confidence = classify(matrix)
        results.append(
            ComplexityResult(
                function_name=target.name,
                complexity_class=kind,
                confidence=confidence,
                matrix=matrix,
            )
        )

    if results:
        return results

    # Fallback: static estimates when we couldn't measure reliably.
    return _static_estimate_complexity(code)

