"""Runtime security context carried alongside validated AST data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyberguard.execution.result import ExecutionResult, HttpRequestSpec, HttpResponseCapture

from .finding import SecurityFinding


@dataclass(frozen=True)
class SecurityContext:
    """Minimal runtime state available to a security capability."""

    auth_state: dict[str, Any] = field(default_factory=dict)

    target: str | None = None
    test: str | None = None
    original_request: HttpRequestSpec | None = None
    capability: str | None = None
    response: HttpResponseCapture | None = None
    execution_result: ExecutionResult | None = None
    modified_request: HttpRequestSpec | None = None
    payload: Any = None
    findings: tuple[SecurityFinding, ...] = field(default_factory=tuple)
    auth_state: dict[str, Any] = field(default_factory=dict)
