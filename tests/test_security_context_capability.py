"""Focused tests for the Phase 2 security context and capability boundary."""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError

import pytest

from cyberguard import (
    BasicAuthenticationCapability,
    ExecutionEngine,
    ExecutionResult,
    ExecutionStatus,
    HttpAssertionCapability,
    SecurityCapability,
    SecurityContext,
)
from cyberguard.execution.result import HttpRequestSpec, HttpResponseCapture
from cyberguard.parser.ast import (
    AuthenticationStatement,
    ComparisonExpression,
    IdentifierValue,
    IntegerLiteral,
    Program,
    RequestStatement,
    SourceLocation,
    TargetBlock,
    TestBlock,
    WithStatement,
)
from cyberguard.security import SecurityFinding, SecurityResult
from cyberguard.status import compare_status


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


def test_http_assertion_capability_status_equals_passes() -> None:
    capability = HttpAssertionCapability()
    comparison = ComparisonExpression(
        left=IdentifierValue(
            name="status",
            source_location=SourceLocation(line=1, column=1),
        ),
        operator="==",
        right=IntegerLiteral(
            value=200,
            source_location=SourceLocation(line=1, column=8),
        ),
        source_location=SourceLocation(line=1, column=1),
    )
    context = SecurityContext(
        target="https://example.com",
        test="status == 200",
        response=HttpResponseCapture(status_code=200, headers={}, body="ok"),
    )

    result = capability.evaluate(comparison, context)

    assert result.outcome == "passed"
    assert result.findings[0].outcome == "passed"
    assert result.findings[0].actual == 200


def test_http_assertion_capability_status_equals_fails() -> None:
    capability = HttpAssertionCapability()
    comparison = ComparisonExpression(
        left=IdentifierValue(
            name="status",
            source_location=SourceLocation(line=1, column=1),
        ),
        operator="==",
        right=IntegerLiteral(
            value=200,
            source_location=SourceLocation(line=1, column=8),
        ),
        source_location=SourceLocation(line=1, column=1),
    )
    context = SecurityContext(
        target="https://example.com",
        test="status == 200",
        response=HttpResponseCapture(status_code=404, headers={}, body="not found"),
    )

    result = capability.evaluate(comparison, context)

    assert result.outcome == "failed"
    assert result.findings[0].severity == "warning"
    assert result.findings[0].actual == 404


@pytest.mark.parametrize(
    ("operator", "expected", "actual", "expected_outcome"),
    [
        ("==", 200, 200, "passed"),
        ("==", 200, 403, "failed"),
        ("!=", 500, 200, "passed"),
        ("!=", 500, 500, "failed"),
    ],
)
def test_http_assertion_capability_status_matrix(
    operator: str,
    expected: int,
    actual: int,
    expected_outcome: str,
) -> None:
    capability = HttpAssertionCapability()
    comparison = ComparisonExpression(
        left=IdentifierValue(
            name="status",
            source_location=SourceLocation(line=1, column=1),
        ),
        operator=operator,
        right=IntegerLiteral(
            value=expected,
            source_location=SourceLocation(line=1, column=8),
        ),
        source_location=SourceLocation(line=1, column=1),
    )

    result = capability.evaluate(
        comparison,
        SecurityContext(
            response=HttpResponseCapture(status_code=actual, headers={}, body="ok")
        ),
    )

    assert result.outcome == expected_outcome
    assert result.findings[0].actual == actual


def test_http_assertion_capability_requires_response() -> None:
    capability = HttpAssertionCapability()
    comparison = ComparisonExpression(
        left=IdentifierValue(
            name="status",
            source_location=SourceLocation(line=1, column=1),
        ),
        operator="==",
        right=IntegerLiteral(
            value=200,
            source_location=SourceLocation(line=1, column=8),
        ),
        source_location=SourceLocation(line=1, column=1),
    )

    result = capability.evaluate(
        comparison,
        SecurityContext(target="https://example.com", test="status == 200"),
    )

    assert result.outcome == "inconclusive"
    assert result.findings == ()


def test_basic_authentication_capability_prepares_authorization_header() -> None:
    capability = BasicAuthenticationCapability()
    statement = AuthenticationStatement(
        method="basic",
        source_location=SourceLocation(line=1, column=1),
    )
    context = SecurityContext(
        target="https://example.com",
        test="secure-admin",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/admin"),
        payload={"username": "alice", "password": "s3cr3t"},
    )

    result = capability.evaluate(statement, context)

    assert result.outcome == "passed"
    assert result.findings[0].rule == "authentication"
    assert result.findings[0].actual == "Basic [REDACTED]"


def test_basic_authentication_capability_requires_credentials() -> None:
    capability = BasicAuthenticationCapability()
    statement = AuthenticationStatement(
        method="basic",
        source_location=SourceLocation(line=1, column=1),
    )
    context = SecurityContext(
        target="https://example.com",
        test="secure-admin",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/admin"),
    )

    result = capability.evaluate(statement, context)

    assert result.outcome == "failed"
    assert result.findings[0].outcome == "failed"


def test_basic_authentication_capability_rejects_wrong_ast_type() -> None:
    capability = BasicAuthenticationCapability()
    context = SecurityContext(
        target="https://example.com",
        test="secure-admin",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/admin"),
        payload={"username": "alice", "password": "s3cr3t"},
    )

    result = capability.evaluate(
        RequestStatement(method="GET", source_location=SourceLocation(1, 1)),
        context,
    )

    assert result.outcome == "inconclusive"
    assert result.findings == ()


def test_basic_authentication_capability_rejects_non_basic_method() -> None:
    capability = BasicAuthenticationCapability()
    statement = AuthenticationStatement(
        method="bearer",
        source_location=SourceLocation(line=1, column=1),
    )
    context = SecurityContext(
        target="https://example.com",
        test="secure-admin",
        original_request=HttpRequestSpec(method="GET", url="https://example.com/admin"),
        payload={"username": "alice", "password": "s3cr3t"},
    )

    result = capability.evaluate(statement, context)

    assert result.outcome == "inconclusive"
    assert result.findings == ()


def test_execution_engine_applies_basic_auth_before_http_request() -> None:
    from cyberguard.execution.http_client import HttpClient

    class RecordingHttpClient(HttpClient):
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def request(self, method, url, headers=None, body=None, timeout=5.0):
            self.calls.append(
                {
                    "method": method,
                    "url": url,
                    "headers": dict(headers or {}),
                    "body": body,
                    "timeout": timeout,
                }
            )
            response = type(
                "Response",
                (),
                {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": '{"ok": true}',
                    "url": url,
                },
            )()
            return response

    base_request = HttpRequestSpec(method="GET", url="https://example.com/admin")
    client = RecordingHttpClient()
    engine = ExecutionEngine(
        program=Program(
            targets=(
                TargetBlock(
                    kind="web",
                    body=(
                        TestBlock(
                            kind="request",
                            body=(
                                RequestStatement(
                                    method="GET",
                                    source_location=SourceLocation(line=1, column=1),
                                    path="/admin",
                                ),
                                AuthenticationStatement(
                                    method="basic",
                                    source_location=SourceLocation(line=2, column=1),
                                ),
                            ),
                            source_location=SourceLocation(line=1, column=1),
                            name="secure-admin",
                        ),
                    ),
                    source_location=SourceLocation(line=1, column=1),
                    url="https://example.com",
                ),
            ),
            source_location=SourceLocation(line=1, column=1),
        ),
        http_client=client,
        default_security_context=SecurityContext(
            payload={"username": "alice", "password": "s3cr3t"},
            original_request=base_request,
        ),
    )

    execution_result = engine.execute()
    assert execution_result.status == ExecutionStatus.SUCCESS
    assert len(client.calls) == 1
    outbound_headers = client.calls[0]["headers"]
    assert "Authorization" in outbound_headers
    assert outbound_headers["Authorization"].startswith("Basic ")
    encoded = outbound_headers["Authorization"].split(" ", 1)[1]
    assert base64.b64decode(encoded).decode("utf-8") == "alice:s3cr3t"
    assert execution_result.request.headers == outbound_headers
    assert base_request.headers == {}


def test_execution_flow_invokes_security_capability_for_status_assertion() -> None:
    from cyberguard.execution.http_client import HttpClient

    class StaticHttpClient(HttpClient):
        def request(self, method, url, headers=None, body=None, timeout=5.0):
            response = type(
                "Response",
                (),
                {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": '{"ok": true}',
                    "url": url,
                },
            )()
            return response

    class RecordingSecurityCapability:
        def __init__(self) -> None:
            self.calls: list[tuple[object, SecurityContext]] = []

        def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
            self.calls.append((validated_ast_node, context))
            assert isinstance(validated_ast_node, ComparisonExpression)
            assert isinstance(context.response, HttpResponseCapture)
            expected = int(validated_ast_node.right.value)
            actual = context.response.status_code
            outcome = (
                "passed"
                if compare_status(actual, expected, validated_ast_node.operator)
                else "failed"
            )
            return SecurityResult(
                outcome=outcome,
                findings=(
                    SecurityFinding(
                        capability="http-assertion",
                        target=context.target or "unknown",
                        test=context.test or "unknown",
                        evidence={
                            "expected": expected,
                            "actual": actual,
                            "operator": validated_ast_node.operator,
                        },
                        outcome=outcome,
                        rule="status",
                        severity="info" if outcome == "passed" else "warning",
                        expected=expected,
                        actual=actual,
                    )
                ),
            )

    comparison = ComparisonExpression(
        left=IdentifierValue(
            name="status",
            source_location=SourceLocation(line=1, column=1),
        ),
        operator="==",
        right=IntegerLiteral(
            value=200,
            source_location=SourceLocation(line=1, column=8),
        ),
        source_location=SourceLocation(line=1, column=1),
    )
    target = TargetBlock(
        kind="web",
        body=(
            TestBlock(
                kind="request",
                body=(
                    RequestStatement(
                        method="GET",
                        source_location=SourceLocation(line=1, column=1),
                    ),
                    WithStatement(
                        expression=comparison,
                        source_location=SourceLocation(line=1, column=1),
                    ),
                ),
                source_location=SourceLocation(line=1, column=1),
                name="request",
            ),
        ),
        source_location=SourceLocation(line=1, column=1),
        url="https://example.com",
    )
    program = Program(targets=(target,), source_location=SourceLocation(line=1, column=1))
    capability = RecordingSecurityCapability()

    execution_result = ExecutionEngine(
        program=program,
        http_client=StaticHttpClient(),
        security_capability=capability,
    ).execute()

    assert execution_result.status == ExecutionStatus.SUCCESS
    assert len(capability.calls) == 1
    evaluated_ast_node, context = capability.calls[0]
    assert evaluated_ast_node is comparison
    assert context.target == "https://example.com"
    assert context.response is not None
    assert context.response.status_code == 200
    assert execution_result.expected == 200
    assert execution_result.actual == 200
