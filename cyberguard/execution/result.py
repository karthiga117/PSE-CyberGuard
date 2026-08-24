"""Result models for the CyberGuard execution engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutionStatus(str, Enum):
    """Structured execution outcome for a CyberGuard run."""

    SUCCESS = "success"
    ASSERTION_FAILURE = "assertion_failure"
    EXECUTION_ERROR = "execution_error"


@dataclass(frozen=True)
class HttpRequestSpec:
    """Runtime HTTP request summary."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None


@dataclass(frozen=True)
class HttpResponseCapture:
    """Runtime HTTP response capture."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    """Structured result produced by the execution engine."""

    status: ExecutionStatus
    target_kind: str
    target_url: str | None
    test_name: str | None
    request: HttpRequestSpec
    response: HttpResponseCapture | None = None
    assertion: str | None = None
    expected: Any = None
    actual: Any = None
    message: str = ""
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS

    @property
    def failed(self) -> bool:
        return self.status in {ExecutionStatus.ASSERTION_FAILURE, ExecutionStatus.EXECUTION_ERROR}
