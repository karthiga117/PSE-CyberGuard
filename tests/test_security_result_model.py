"""Focused tests for the security result models."""

from __future__ import annotations

from cyberguard import ExecutionResult, ExecutionStatus
from cyberguard.execution.result import HttpRequestSpec
from cyberguard.security import SecurityFinding, SecurityResult


def test_security_finding_required_fields_can_be_created() -> None:
    finding = SecurityFinding(
        capability="sql-detection",
        target="https://example.com",
        test="sql-error",
        evidence={"status": 500, "body": "You have an error in your SQL"},
        outcome="failed",
    )

    assert finding.capability == "sql-detection"
    assert finding.target == "https://example.com"
    assert finding.test == "sql-error"
    assert finding.evidence["status"] == 500
    assert finding.outcome == "failed"


def test_security_finding_optional_fields_are_optional() -> None:
    finding = SecurityFinding(
        capability="auth",
        target="api://example",
        test="bearer-token-check",
        evidence="missing Authorization header",
        outcome="inconclusive",
    )

    assert finding.rule is None
    assert finding.severity is None
    assert finding.title is None
    assert finding.description is None
    assert finding.expected is None
    assert finding.actual is None
    assert finding.remediation is None


def test_security_result_supports_zero_one_and_multiple_findings() -> None:
    empty_result = SecurityResult(outcome="passed")
    single_result = SecurityResult(
        outcome="failed",
        findings=[
            SecurityFinding(
                capability="detection",
                target="https://example.com",
                test="sql-error",
                evidence="database error",
                outcome="failed",
            )
        ],
    )
    multiple_result = SecurityResult(
        outcome="failed",
        findings=[
            SecurityFinding(
                capability="detection",
                target="https://example.com",
                test="sql-error",
                evidence="database error",
                outcome="failed",
            ),
            SecurityFinding(
                capability="cloud",
                target="aws:iam",
                test="public_access",
                evidence={"public_access": True},
                outcome="failed",
            ),
        ],
    )

    assert len(empty_result.findings) == 0
    assert len(single_result.findings) == 1
    assert len(multiple_result.findings) == 2
    assert empty_result.outcome == "passed"
    assert single_result.findings[0].capability == "detection"
    assert multiple_result.findings[1].target == "aws:iam"


def test_security_result_preserves_outcome_and_findings() -> None:
    finding = SecurityFinding(
        capability="header-check",
        target="https://example.com",
        test="missing-security-header",
        evidence={"Authorization": "Bearer secret-token"},
        outcome="failed",
    )
    result = SecurityResult(outcome="failed", findings=[finding])

    assert result.outcome == "failed"
    assert len(result.findings) == 1
    assert result.findings[0] == finding
    assert result.findings[0].sanitize().evidence == {"Authorization": "[REDACTED]"}


def test_execution_result_and_security_result_remain_separate() -> None:
    execution_result = ExecutionResult(
        status=ExecutionStatus.EXECUTION_ERROR,
        target_kind="web",
        target_url="https://example.com",
        test_name="request",
        request=HttpRequestSpec(method="GET", url="https://example.com"),
        error="request timed out",
    )
    security_result = SecurityResult(
        outcome="failed",
        findings=[
            SecurityFinding(
                capability="timeout-check",
                target="https://example.com",
                test="request",
                evidence="request timed out",
                outcome="failed",
            )
        ],
    )

    assert execution_result.status == ExecutionStatus.EXECUTION_ERROR
    assert security_result.outcome == "failed"
    assert execution_result.status != security_result.outcome
    assert execution_result.request == HttpRequestSpec(method="GET", url="https://example.com")
    assert security_result.findings[0].capability == "timeout-check"
