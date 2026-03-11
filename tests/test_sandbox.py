from sandbox.runtime import run_in_sandbox


def test_run_in_sandbox_prints_output() -> None:
    code = "print('hello from sandbox')"
    result = run_in_sandbox(code, timeout_s=2)
    assert "hello from sandbox" in result.stdout
    assert result.exit_code == 0
    assert not result.timed_out


def test_run_in_sandbox_timeout() -> None:
    code = "while True:\n    pass"
    result = run_in_sandbox(code, timeout_s=1)
    assert result.timed_out
    assert result.exit_code != 0
