from __future__ import annotations

import builtins
import sys
from typing import Any, Callable, Dict, Iterable, MutableMapping

from .runtime import ThreatLogEntry


DEFAULT_POLICY: Dict[str, Any] = {
    "open": ("HIGH", "File system access"),
    "socket": ("CRITICAL", "Network socket access"),
    "subprocess": ("CRITICAL", "Subprocess execution"),
    "os.system": ("CRITICAL", "Shell execution"),
    "eval": ("HIGH", "Dynamic eval"),
    # NOTE: we intentionally do NOT block built-in exec(), since the sandbox
    # itself uses exec() to run user code. exec-like behavior in user code
    # will be handled by later engines (e.g., taint analysis).
    "os.environ": ("MEDIUM", "Environment access"),
    "import": ("MEDIUM", "Dynamic import"),
}


def _log_violation(
    violations: list[ThreatLogEntry],
    operation: str,
    message: str,
    severity: str,
) -> None:
    frame = sys._getframe(2)
    violations.append(
        ThreatLogEntry(
            severity=severity,
            operation=operation,
            message=message,
            lineno=frame.f_lineno,
            func_name=frame.f_code.co_name,
        )
    )


def _make_blocking_builtin(
    name: str,
    violations: list[ThreatLogEntry],
    policy: Dict[str, Any],
) -> Callable[..., Any]:
    severity, description = policy.get(name, ("HIGH", "Blocked operation"))

    def wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        _log_violation(
            violations,
            operation=name,
            message=description,
            severity=severity,
        )
        raise PermissionError(f"{name} is blocked in Detonation Chamber sandbox")

    return wrapper


def build_restricted_globals(
    violations: list[ThreatLogEntry],
    policy: Dict[str, Any],
) -> MutableMapping[str, Any]:
    """Return a restricted globals mapping for sandboxed exec."""
    allowed_builtins: Dict[str, Any] = {
        "abs": builtins.abs,
        "all": builtins.all,
        "any": builtins.any,
        "bool": builtins.bool,
        "dict": builtins.dict,
        "float": builtins.float,
        "int": builtins.int,
        "len": builtins.len,
        "list": builtins.list,
        "max": builtins.max,
        "min": builtins.min,
        "print": builtins.print,
        "range": builtins.range,
        "str": builtins.str,
        "tuple": builtins.tuple,
        "enumerate": builtins.enumerate,
        "zip": builtins.zip,
    }

    # Overlay blocked operations with wrappers so calls like open(...) or eval(...)
    # go through our logging layer.
    for name in policy:
        if name in ("open", "eval"):
            allowed_builtins[name] = _make_blocking_builtin(name, violations, policy)

    return {"__builtins__": allowed_builtins}


def install_security_tracer(
    violations: list[ThreatLogEntry],
    policy: Dict[str, Any] = DEFAULT_POLICY,
) -> None:
    """Install a simple sys.settrace-based tracer.

    For v1, most blocking is done via the restricted __builtins__ mapping created
    in build_restricted_globals; this tracer is a hook point for future line-level
    analysis and logging.
    """

    def tracer(frame: Any, event: str, arg: Any) -> Any:  # noqa: ANN401
        # For v1, we keep tracing logic minimal; most blocking happens via patched builtins.
        return tracer

    sys.settrace(tracer)

