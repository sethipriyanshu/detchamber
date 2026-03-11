from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .harness import MeasurementMatrix, MeasurementPoint


COMPLEXITY_CLASSES = [
    "O(1)",
    "O(log n)",
    "O(n)",
    "O(n log n)",
    "O(n^2)",
    "O(n^3)",
]


@dataclass
class ComplexityResult:
    function_name: str
    complexity_class: str
    confidence: float
    matrix: MeasurementMatrix


def _basis_value(kind: str, n: int) -> float:
    if kind == "O(1)":
        return 1.0
    if kind == "O(log n)":
        return math.log(max(n, 2))
    if kind == "O(n)":
        return float(n)
    if kind == "O(n log n)":
        return float(n) * math.log(max(n, 2))
    if kind == "O(n^2)":
        return float(n) ** 2
    if kind == "O(n^3)":
        return float(n) ** 3
    return float(n)


def _fit_for_class(kind: str, points: List[MeasurementPoint]) -> float:
    """
    Fit time ~ a * g(n) for a given complexity kind using least squares,
    then return residual sum of squares. Lower is better.
    """
    g_vals = [_basis_value(kind, p.n) for p in points]
    t_vals = [max(p.time_ms, 1e-6) for p in points]

    num = sum(t * g for t, g in zip(t_vals, g_vals))
    den = sum(g * g for g in g_vals)
    if den == 0:
        return float("inf")

    a = num / den
    residual = sum((t - a * g) ** 2 for t, g in zip(t_vals, g_vals))
    return residual


def classify(matrix: MeasurementMatrix) -> Tuple[str, float]:
    """Return (complexity_class, confidence) for the given measurements."""
    if len(matrix) < 2:
        return "unknown", 0.0

    points = sorted(matrix.values(), key=lambda p: p.n)

    residuals: Dict[str, float] = {}
    for kind in COMPLEXITY_CLASSES:
        residuals[kind] = _fit_for_class(kind, points)

    best_kind = min(residuals, key=residuals.get)
    best_resid = residuals[best_kind]
    worst_resid = max(residuals.values()) or 1.0

    # Heuristic confidence: 1 - (best / worst), clipped to [0,1].
    confidence = max(0.0, min(1.0, 1.0 - best_resid / worst_resid))
    return best_kind, confidence

