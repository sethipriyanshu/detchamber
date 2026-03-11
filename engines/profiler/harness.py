from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from sandbox.runtime import ExecutionResult, run_in_sandbox

from .detector import ProfileTarget
from .input_gen import generate_input_expr


@dataclass
class MeasurementPoint:
    n: int
    time_ms: float
    peak_kb: float


MeasurementMatrix = Dict[int, MeasurementPoint]


def _build_profiler_snippet(code: str, func_name: str, arg_expr: str, n: int) -> str:
    """
    Combine user code with a small harness that measures a single call
    to func_name(arg_expr) for size n and prints 'n time_ms peak_kb'.
    """
    return f"""
import tracemalloc
import time

{code}

def __dc_profile_once():
    tracemalloc.start()
    start = time.perf_counter()
    _ = {func_name}({arg_expr})
    end = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print({n}, (end - start) * 1000.0, peak / 1024.0)

__dc_profile_once()
""".lstrip()


def measure_function(
    code: str,
    target: ProfileTarget,
    sizes: List[int],
) -> MeasurementMatrix:
    """
    For a single target function, run it at each input size inside the sandbox
    and collect timing/memory measurements.
    """
    matrix: MeasurementMatrix = {}

    for n in sizes:
        arg_expr = generate_input_expr(target, n)
        snippet = _build_profiler_snippet(code, target.name, arg_expr, n)
        result: ExecutionResult = run_in_sandbox(snippet)
        if result.exit_code != 0 or result.timed_out:
            # Skip this size if execution failed; keep matrix partial.
            continue

        # Expect stdout like: "n time_ms peak_kb\n"
        line = result.stdout.strip().splitlines()[-1]
        parts = line.split()
        if len(parts) != 3:
            continue

        try:
            n_val = int(parts[0])
            time_ms = float(parts[1])
            peak_kb = float(parts[2])
        except ValueError:
            continue

        matrix[n_val] = MeasurementPoint(n=n_val, time_ms=time_ms, peak_kb=peak_kb)

    return matrix

