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
    empty_result = SecurityResult(outcome="passed", findings=())
    single_finding = SecurityFinding(
        capability="detection",
        target="https://example.com",
        test="sql-error",
        evidence="database error",
        outcome="failed",
    )
    single_result = SecurityResult(outcome="failed", findings=(single_finding,))
    second_finding = SecurityFinding(
        capability="cloud",
        target="aws:iam",
        test="public_access",
        evidence={"public_access": True},
        outcome="failed",
    )
    multiple_result = SecurityResult(outcome="failed", findings=(single_finding, second_finding))

    assert len(empty_result.findings) == 0
    assert len(single_result.findings) == 1
    assert len(multiple_result.findings) == 2
    assert empty_result.outcome == "passed"
    assert single_result.findings[0].capability == "detection"
    assert multiple_result.findings[1].target == "aws:iam"
    assert isinstance(empty_result.findings, tuple)


def test_security_result_add_finding_returns_new_result_without_mutating_original() -> None:
    original = SecurityResult(outcome="passed", findings=())
    added = SecurityFinding(
        capability="detection",
        target="https://example.com",
        test="sql-error",
        evidence="database error",
        outcome="failed",
    )

    updated = original.add_finding(added)

    assert original.findings == ()
    assert updated.findings == (added,)
    assert original is not updated
    assert updated.outcome == "passed"


def test_security_redaction_handles_nested_dicts_and_lists() -> None:
    finding = SecurityFinding(
        capability="header-check",
        target="https://example.com",
        test="missing-security-header",
        evidence={
            "headers": {
                "Authorization": "Bearer super-secret-token",
                "x-trace": "abc123",
            },
            "items": [
                {"token": "abc123"},
                {"message": "SQL authentication error detected"},
            ],
        },
        outcome="failed",
    )

    sanitized = finding.sanitize()

    assert sanitized.evidence["headers"]["Authorization"] == "[REDACTED]"
    assert sanitized.evidence["items"][0]["token"] == "[REDACTED]"
    assert sanitized.evidence["items"][1]["message"] == "SQL authentication error detected"
    assert sanitized.evidence["headers"]["x-trace"] == "abc123"


def test_security_redaction_preserves_non_sensitive_evidence() -> None:
    finding = SecurityFinding(
        capability="detection",
        target="https://example.com",
        test="response-check",
        evidence="SQL authentication error detected",
        outcome="failed",
    )

    sanitized = finding.sanitize()

    assert sanitized.evidence == "SQL authentication error detected"

    header_finding = SecurityFinding(
        capability="auth",
        target="https://example.com",
        test="header",
        evidence="Authorization: Bearer abc123",
        outcome="failed",
    )
    assert header_finding.sanitize().evidence == "[REDACTED]"
    assert SecurityFinding(
        capability="auth",
        target="https://example.com",
        test="header",
        evidence="******",
        outcome="failed",
    ).sanitize().evidence == "[REDACTED]"


def test_execution_result_and_security_result_remain_separate() -> None:
    execution_result = ExecutionResult(
        status=ExecutionStatus.EXECUTION_ERROR,
        target_kind="web",
        target_url="https://example.com",
        test_name="request",
        request=HttpRequestSpec(method="GET", url="https://example.com"),
        error="request timed out",
    )
    security_result = SecurityResult(outcome="failed", findings=())

    assert execution_result.status == ExecutionStatus.EXECUTION_ERROR
    assert execution_result.error == "request timed out"
    assert security_result.outcome == "failed"
    assert security_result.findings == ()
    assert security_result.has_findings is False
    assert execution_result.status != security_result.outcome
