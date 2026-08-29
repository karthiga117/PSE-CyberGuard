"""Focused tests for the Phase 2 security context and capability boundary."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from cyberguard import ExecutionResult, ExecutionStatus, SecurityCapability, SecurityContext
from cyberguard.execution.result import HttpRequestSpec, HttpResponseCapture
from cyberguard.parser.ast import RequestStatement, SourceLocation
from cyberguard.security import SecurityFinding, SecurityResult


class FakeCapability:
    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        assert isinstance(validated_ast_node, RequestStatement)
        assert context.target == "https://example.com"
        return SecurityResult(
            outcome="passed",
            findings=(
                SecurityFinding(
                    capability="fake-capability",
                    target=context.target or "unknown",
                    test=context.test or "unknown",
                    evidence={
                        "request": (
                            context.original_request.method if context.original_request else None
                        )
                    },
                    outcome="passed",
                ),
            ),
        )


def test_security_context_can_be_created_with_runtime_state() -> None:
    context = SecurityContext(
        target="https://example.com",
        test="login-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/login"),
        capability="request-capability",
    )

    assert context.target == "https://example.com"
    assert context.test == "login-check"
    assert context.original_request.method == "GET"
    assert context.capability == "request-capability"
    assert context.response is None
    assert context.execution_result is None


def test_security_context_can_hold_post_execution_state() -> None:
    execution_result = ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        target_kind="web",
        target_url="https://example.com",
        test_name="login-check",
        request=HttpRequestSpec(method="GET", url="https://example.com/login"),
        response=HttpResponseCapture(
            status_code=200,
            body="ok",
            headers={"content-type": "text/plain"},
        ),
    )
    context = SecurityContext(
        target="https://example.com",
        test="login-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/login"),
        capability="request-capability",
        response=execution_result.response,
        execution_result=execution_result,
    )

    assert context.response is not None
    assert context.response.status_code == 200
    assert context.execution_result is execution_result
    assert context.execution_result.status == ExecutionStatus.SUCCESS


def test_security_capability_contract_accepts_validated_ast_and_context() -> None:
    capability: SecurityCapability = FakeCapability()
    request = RequestStatement(
        method="GET",
        source_location=SourceLocation(line=1, column=1),
        path="/login",
    )
    context = SecurityContext(
        target="https://example.com",
        test="login-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/login"),
        capability="fake-capability",
    )

    result = capability.evaluate(request, context)

    assert result.outcome == "passed"
    assert len(result.findings) == 1
    assert result.findings[0].capability == "fake-capability"
    assert result.findings[0].target == "https://example.com"


def test_security_capability_does_not_execute_http_requests() -> None:
    capability: SecurityCapability = FakeCapability()
    request = RequestStatement(
        method="GET",
        source_location=SourceLocation(line=2, column=2),
    )
    context = SecurityContext(
        target="https://example.com",
        test="noop-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com"),
        capability="noop-capability",
    )

    result = capability.evaluate(request, context)

    assert result.outcome == "passed"
    assert result.findings[0].evidence == {"request": "GET"}
    assert context.execution_result is None


def test_security_context_and_execution_result_are_separate_models() -> None:
    execution_result = ExecutionResult(
        status=ExecutionStatus.EXECUTION_ERROR,
        target_kind="web",
        target_url="https://example.com",
        test_name="timeout-check",
        request=HttpRequestSpec(method="GET", url="https://example.com"),
        error="request timed out",
    )
    security_context = SecurityContext(
        target="https://example.com",
        test="timeout-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com"),
        capability="timeout-check",
        execution_result=execution_result,
    )

    assert security_context.execution_result is execution_result
    assert security_context.execution_result.status == ExecutionStatus.EXECUTION_ERROR
    assert security_context.capability == "timeout-check"
    assert security_context.execution_result is not None
    assert security_context.execution_result.error == "request timed out"


def test_security_context_is_frozen() -> None:
    context = SecurityContext(
        target="https://example.com",
        test="login-check",
    )

    with pytest.raises(FrozenInstanceError):
        context.target = "https://other.example.com"
