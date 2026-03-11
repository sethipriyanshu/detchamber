from engines.profiler import run_profiler


def test_profiler_detects_function_and_returns_result() -> None:
    code = """
def linear(items):
    total = 0
    for x in items:
        total += x
    return total
"""
    results = run_profiler(code)
    assert results, "Expected at least one profiler result"
    names = {r.function_name for r in results}
    assert "linear" in names

