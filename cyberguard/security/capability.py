"""Minimal security capability contract for CyberGuard."""

from __future__ import annotations

import base64
from typing import Protocol

from cyberguard.execution.result import HttpRequestSpec
from cyberguard.parser.ast import (
    AuthenticationStatement,
    ComparisonExpression,
    IdentifierValue,
    IntegerLiteral,
)
from cyberguard.status import compare_status

from .context import SecurityContext
from .finding import SecurityFinding
from .result import SecurityResult


class SecurityCapability(Protocol):
    def evaluate(
        self,
        validated_ast_node: object,
        context: SecurityContext,
    ) -> SecurityResult:
        ...


class HttpAssertionCapability:
    """Security capability wrapper around the existing status assertion behavior."""

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        if not isinstance(validated_ast_node, ComparisonExpression):
            return SecurityResult(outcome="inconclusive", findings=())

        left = getattr(validated_ast_node, "left", None)
        if not isinstance(left, IdentifierValue) or left.name != "status":
            return SecurityResult(outcome="inconclusive", findings=())

        right = getattr(validated_ast_node, "right", None)
        if not isinstance(right, IntegerLiteral):
            return SecurityResult(outcome="inconclusive", findings=())

        response = context.response
        if response is None:
            return SecurityResult(outcome="inconclusive", findings=())

        actual = response.status_code
        expected = int(right.value)
        operator = validated_ast_node.operator
        passed = compare_status(actual, expected, operator)

        outcome = "passed" if passed else "failed"
        finding = SecurityFinding(
            capability="http-assertion",
            target=context.target or "unknown",
            test=context.test or "unknown",
            evidence={
                "expected": expected,
                "actual": actual,
                "operator": operator,
                "status_code": actual,
            },
            outcome=outcome,
            rule="status",
            severity="info" if passed else "warning",
            title="HTTP status assertion",
            description="Validated status comparison against the HTTP response status code.",
            expected=expected,
            actual=actual,
        )
        return SecurityResult(outcome=outcome, findings=(finding,))


def _extract_basic_auth_credentials(payload: object) -> tuple[str | None, str | None]:
    """Return the canonical username/password pair from the runtime payload."""
    if not isinstance(payload, dict):
        return (None, None)

    username = payload.get("username")
    password = payload.get("password")
    if username is None or password is None:
        return (None, None)
    return (str(username), str(password))


def prepare_basic_auth_request(
    request: HttpRequestSpec,
    payload: object,
) -> HttpRequestSpec | None:
    """Return a derived request with a Basic Authorization header when credentials exist."""
    username, password = _extract_basic_auth_credentials(payload)
    if username is None or password is None:
        return None

    credentials = f"{username}:{password}".encode("utf-8")
    token = base64.b64encode(credentials).decode("ascii")
    headers = dict(request.headers)
    headers["Authorization"] = f"Basic {token}"
    return HttpRequestSpec(
        method=request.method,
        url=request.url,
        headers=headers,
        body=request.body,
    )


class BasicAuthenticationCapability:
    """Prepare a Basic Auth Authorization header from the validated AST and context."""

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        if not isinstance(validated_ast_node, AuthenticationStatement):
            return SecurityResult(outcome="inconclusive", findings=())
        if validated_ast_node.method != "basic":
            return SecurityResult(outcome="inconclusive", findings=())

        request = context.original_request
        if request is None:
            return SecurityResult(outcome="inconclusive", findings=())

        username, password = _extract_basic_auth_credentials(context.payload)
        if username is None or password is None:
            finding = SecurityFinding(
                capability="basic-authentication",
                target=context.target or "unknown",
                test=context.test or "unknown",
                evidence={
                    "request": {"method": request.method, "url": request.url},
                    "reason": "missing basic authentication credentials",
                },
                outcome="failed",
                rule="authentication",
                severity="warning",
                title="Basic authentication credentials missing",
                description=(
                    "The Basic Authentication capability requires credentials in "
                    "the SecurityContext payload."
                ),
                expected="username and password",
                actual=None,
            )
            return SecurityResult(outcome="failed", findings=(finding,))

        modified_request = prepare_basic_auth_request(request, context.payload)
        if modified_request is None:
            finding = SecurityFinding(
                capability="basic-authentication",
                target=context.target or "unknown",
                test=context.test or "unknown",
                evidence={
                    "request": {"method": request.method, "url": request.url},
                    "reason": "missing basic authentication credentials",
                },
                outcome="failed",
                rule="authentication",
                severity="warning",
                title="Basic authentication credentials missing",
                description=(
                    "The Basic Authentication capability requires credentials in "
                    "the SecurityContext payload."
                ),
                expected="username and password",
                actual=None,
            )
            return SecurityResult(outcome="failed", findings=(finding,))

        finding = SecurityFinding(
            capability="basic-authentication",
            target=context.target or "unknown",
            test=context.test or "unknown",
            evidence={
                "request": {
                    "method": request.method,
                    "url": request.url,
                    "headers": {"Authorization": "Basic [REDACTED]"},
                },
                "modified_request": {
                    "method": modified_request.method,
                    "url": modified_request.url,
                    "headers": {"Authorization": "Basic [REDACTED]"},
                },
            },
            outcome="passed",
            rule="authentication",
            severity="info",
            title="Basic authentication prepared",
            description=(
                "Basic authentication request preparation succeeded for the "
                "outbound request."
            ),
            expected="Basic [REDACTED]",
            actual="Basic [REDACTED]",
        )
        return SecurityResult(outcome="passed", findings=(finding,))


BasicAuthCapability = BasicAuthenticationCapability
