"""Minimal security capability contract for CyberGuard."""

from __future__ import annotations

from typing import Protocol

from cyberguard.parser.ast import ComparisonExpression, IdentifierValue, IntegerLiteral
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
