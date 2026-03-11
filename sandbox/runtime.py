from __future__ import annotations

import io
import multiprocessing as mp
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ThreatLogEntry:
    severity: str
    operation: str
    message: str
    lineno: Optional[int] = None
    func_name: Optional[str] = None


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    violations: list[ThreatLogEntry] = field(default_factory=list)
    timed_out: bool = False
    killed_for_memory: bool = False


def _child_exec(
    code: str,
    timeout_s: int,
    policy: Dict[str, Any],
    conn: mp.Connection,
) -> None:
    from .security import DEFAULT_POLICY, install_security_tracer, build_restricted_globals

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    sys_stdout, sys_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = stdout_buf, stderr_buf

    violations: list[ThreatLogEntry] = []
    start = time.perf_counter()
    exit_code = 0

    try:
        # Merge provided policy with DEFAULT_POLICY inside the child process.
        effective_policy: Dict[str, Any] = dict(DEFAULT_POLICY)
        effective_policy.update(policy or {})
        install_security_tracer(violations, effective_policy)
        restricted_globals = build_restricted_globals(violations, effective_policy)
        exec(compile(code, "<chamber>", "exec"), restricted_globals, None)
    except SystemExit as exc:
        exit_code = int(getattr(exc, "code", 1) or 0)
    except Exception as exc:  # noqa: BLE001
        import traceback

        exit_code = 1
        traceback.print_exc(file=stderr_buf)
        stderr_buf.write(f"\n[DetonationChamber] Unhandled exception: {exc}\n")
    finally:
        duration_ms = (time.perf_counter() - start) * 1000.0
        sys.stdout, sys.stderr = sys_stdout, sys_stderr

    conn.send(
        ExecutionResult(
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            exit_code=exit_code,
            duration_ms=duration_ms,
            violations=violations,
        )
    )
    conn.close()


DEFAULT_TIMEOUT_S = 10


def run_in_sandbox(
    code: str,
    timeout_s: Optional[int] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """Execute user code inside an isolated subprocess with basic timeout handling."""
    timeout_s = timeout_s or DEFAULT_TIMEOUT_S

    parent_conn, child_conn = mp.Pipe(duplex=False)
    if policy is None:
        policy = {}

    proc = mp.Process(
        target=_child_exec,
        args=(code, timeout_s, policy, child_conn),
        daemon=True,
    )
    proc.start()
    child_conn.close()

    start = time.perf_counter()
    proc.join(timeout_s)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    timed_out = proc.is_alive()
    if timed_out:
        proc.terminate()
        proc.join()
        return ExecutionResult(
            stdout="",
            stderr="[DetonationChamber] Execution timed out\n",
            exit_code=1,
            duration_ms=elapsed_ms,
            violations=[],
            timed_out=True,
        )

    if parent_conn.poll(1.0):
        try:
            result: Any = parent_conn.recv()
        except EOFError:
            parent_conn.close()
        else:
            parent_conn.close()
            if isinstance(result, ExecutionResult):
                return result

    parent_conn.close()
    return ExecutionResult(
        stdout="",
        stderr="[DetonationChamber] No result from sandbox process\n",
        exit_code=1,
        duration_ms=elapsed_ms,
        violations=[],
    )
