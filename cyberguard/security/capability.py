"""Minimal security capability contract for CyberGuard."""

from __future__ import annotations

from typing import Protocol

from cyberguard.parser.ast import ComparisonExpression, IdentifierValue, IntegerLiteral

from .context import SecurityContext
from .finding import SecurityFinding
from .result import SecurityResult


def compare_status(actual: int, expected: int, operator: str) -> bool:
    """Compare an HTTP status code using the project's supported operators."""
    if operator == "==":
        return actual == expected
    if operator == "!=":
        return actual != expected
    return False


class SecurityCapability(Protocol):
    def evaluate(
        self,
        validated_ast_node: object,
        context: SecurityContext,
    ) -> SecurityResult:
        ...

    def execute(
        self,
        validated_ast_node: object,
        context: SecurityContext,
    ) -> SecurityResult:
        ...


class HttpAssertionCapability:
    """Security capability wrapper around the existing status assertion behavior."""

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        return self.execute(validated_ast_node, context)

    def execute(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
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

        if isinstance(response, dict):
            actual = response.get("status_code")
        else:
            actual = getattr(response, "status_code", None)
        if actual is None:
            return SecurityResult(outcome="inconclusive", findings=())

        expected = int(right.value)
        operator = validated_ast_node.operator
        passed = compare_status(int(actual), expected, operator)

        outcome = "passed" if passed else "failed"
        finding = SecurityFinding(
            capability="http-assertion",
            target=context.target or "unknown",
            test=context.test or "unknown",
            evidence={
                "expected": expected,
                "actual": int(actual),
                "operator": operator,
                "status_code": int(actual),
            },
            outcome=outcome,
            rule="status",
            severity="info" if passed else "warning",
            title="HTTP status assertion",
            description="Validated status comparison against the HTTP response status code.",
            expected=expected,
            actual=int(actual),
        )
        return SecurityResult(outcome=outcome, findings=(finding,))
