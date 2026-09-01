"""Focused regression tests for the detection capability boundary."""

from __future__ import annotations

from cyberguard import ExecutionEngine, SecurityContext, SecurityResult, SqlErrorDetectionCapability
from cyberguard.execution.result import HttpRequestSpec, HttpResponseCapture
from cyberguard.parser.ast import (
    DetectionStatement,
    Program,
    RequestStatement,
    SourceLocation,
    TargetBlock,
    TestBlock,
)


class RecordingDetectionCapability:
    """Record invocation of the production detection boundary without projecting findings."""

    def __init__(self) -> None:
        self.invocations: list[tuple[object, SecurityContext]] = []

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        self.invocations.append((validated_ast_node, context))
        return SecurityResult(outcome="inconclusive", findings=())


def test_sql_error_detection_capability_returns_inconclusive_for_non_detection_ast() -> None:
    capability = SqlErrorDetectionCapability()
    context = SecurityContext(
        target="https://example.com",
        test="sql-error-check",
        original_request=HttpRequestSpec(method="GET", url="https://example.com"),
        response=HttpResponseCapture(
            status_code=500,
            headers={},
            body="You have an error in your SQL syntax",
        ),
    )

    result = capability.evaluate(
        RequestStatement(method="GET", source_location=SourceLocation(line=1, column=1)),
        context,
    )

    assert result.outcome == "inconclusive"
    assert result.findings == ()


def test_execution_engine_invokes_detection_capability_with_response_context(
) -> None:
    request = RequestStatement(
        method="GET",
        source_location=SourceLocation(line=1, column=1),
        path="/",
    )
    detection = DetectionStatement(
        kind="sql-error",
        source_location=SourceLocation(line=2, column=1),
    )
    test = TestBlock(
        kind="request",
        body=(request, detection),
        source_location=SourceLocation(line=1, column=1),
        name="db-check",
    )
    target = TargetBlock(
        kind="web",
        body=(test,),
        source_location=SourceLocation(line=1, column=1),
        url="https://example.com",
    )
    program = Program(targets=(target,), source_location=SourceLocation(line=1, column=1))

    class _Client:
        def request(self, method, url, headers=None, body=None, timeout=5.0):
            return type(
                "Response",
                (),
                {
                    "status_code": 500,
                    "headers": {"content-type": "text/plain"},
                    "body": "syntax error",
                    "url": url,
                },
            )()

    capability = RecordingDetectionCapability()
    engine = ExecutionEngine(
        program=program,
        http_client=_Client(),
        timeout=1.0,
        detection_capability=capability,
    )

    result = engine.execute(test_name="db-check")

    assert result.status.value == "success"
    assert len(capability.invocations) == 1
    invoked_node, context = capability.invocations[0]
    assert isinstance(invoked_node, DetectionStatement)
    assert invoked_node.kind == "sql-error"
    assert context.target == "https://example.com"
    assert context.test == "db-check"
    assert context.original_request is not None
    assert context.original_request.url == "https://example.com/"
    assert context.capability == "sql-error-detection"
    assert context.response is not None
    assert context.response.status_code == 500
    assert context.execution_result is not None
