"""Tests for the safe detection capability boundary."""

from __future__ import annotations

from cyberguard import DetectionCapability, ExecutionEngine, SecurityContext, SqlErrorDetectionCapability
from cyberguard.execution.result import HttpRequestSpec, HttpResponseCapture
from cyberguard.parser.ast import DetectionStatement, Program, RequestStatement, SourceLocation, TargetBlock, TestBlock


def test_sql_error_detection_capability_is_non_conclusive_without_defined_rule() -> None:
    capability = SqlErrorDetectionCapability()
    statement = DetectionStatement(kind="sql-error", source_location=SourceLocation(line=1, column=1))
    context = SecurityContext(
        target="https://example.com",
        test="sql-error-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com"),
        response=HttpResponseCapture(status_code=500, headers={}, body="You have an error in your SQL syntax"),
    )

    result = capability.evaluate(statement, context)

    assert result.outcome == "inconclusive"
    assert result.findings == ()
    assert isinstance(DetectionCapability, type)


def test_execution_engine_handles_detection_statement_without_fabricating_findings() -> None:
    request = RequestStatement(method="GET", source_location=SourceLocation(line=1, column=1), path="/")
    detection = DetectionStatement(kind="sql-error", source_location=SourceLocation(line=2, column=1))
    test = TestBlock(kind="request", body=(request, detection), source_location=SourceLocation(line=1, column=1), name="db-check")
    target = TargetBlock(kind="web", body=(test,), source_location=SourceLocation(line=1, column=1), url="https://example.com")
    program = Program(targets=(target,), source_location=SourceLocation(line=1, column=1))

    class _Client:
        def request(self, method, url, headers=None, body=None, timeout=5.0):
            return type(
                "Response",
                (),
                {"status_code": 500, "headers": {"content-type": "text/plain"}, "body": "syntax error", "url": url},
            )()

    engine = ExecutionEngine(program=program, http_client=_Client(), timeout=1.0)
    result = engine.execute(test_name="db-check")

    assert result.status.value == "success"
    assert result.response is not None
    assert result.response.status_code == 500
