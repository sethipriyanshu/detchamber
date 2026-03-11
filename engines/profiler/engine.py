from __future__ import annotations

from typing import List

from .classifier import ComplexityResult, classify
from .detector import ProfileTarget, detect_profile_targets
from .harness import MeasurementMatrix, measure_function
from .input_gen import default_sizes


def run_profiler(code: str) -> List[ComplexityResult]:
    """
    High-level entry point for the complexity profiler.

    - Detects candidate functions in the submitted code.
    - For each, measures runtime and memory across input sizes.
    - Classifies the observed behavior into a Big-O class.
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

    return results

