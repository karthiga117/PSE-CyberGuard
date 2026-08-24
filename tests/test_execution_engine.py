"""Execution engine regression tests for CyberGuard web targets."""

from __future__ import annotations

from dataclasses import replace

from cyberguard import ExecutionEngine, ExecutionStatus
from cyberguard.lexer.lexer import Lexer
from cyberguard.parser import Parser
from cyberguard.semantic import SemanticValidator


class RecordingHttpClient:
    def __init__(
        self,
        *,
        status_code: int = 200,
        response_body: str = '{"ok": true}',
        headers: dict[str, str] | None = None,
        raise_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.response_body = response_body
        self.headers = headers or {"content-type": "application/json"}
        self.raise_error = raise_error
        self.calls: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        url: str,
        headers=None,
        body=None,
        timeout: float = 5.0,
    ):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "timeout": timeout,
            }
        )
        if self.raise_error is not None:
            raise self.raise_error

        response_url = url

        class FakeResponse:
            status_code = self.status_code
            headers = self.headers
            body = self.response_body
            url = response_url

        return FakeResponse()


def parse_valid_source(source: str, *, url: str = "https://example.com"):
    # The current DSL does not define target URL syntax; the execution test
    # supplies the runtime target URL explicitly.
    program = Parser(Lexer(source).tokenize()).parse()
    target = replace(program.targets[0], url=url)
    program = replace(program, targets=(target,))
    SemanticValidator().validate(program)
    return program


def test_execution_engine_request_path_is_combined_with_target_url() -> None:
    source = """\
target: web
    test: request
        request: GET
        with: status == 200
"""
    program = parse_valid_source(source)
    test_block = program.targets[0].body[0]
    request = replace(test_block.body[0], path="/login")
    updated_test = replace(test_block, body=(request, test_block.body[1]))
    program = replace(program, targets=(replace(program.targets[0], body=(updated_test,)),))

    fake_client = RecordingHttpClient(status_code=200)
    engine = ExecutionEngine(program=program, http_client=fake_client)

    result = engine.execute()

    assert result.request.method == "GET"
    assert result.request.url == "https://example.com/login"
    assert fake_client.calls[0]["method"] == "GET"
    assert fake_client.calls[0]["url"] == "https://example.com/login"


def test_execution_engine_end_to_end_from_real_source() -> None:
    source = """\
target: web
    test: request
        request: GET
        with: status == 200
"""
    program = parse_valid_source(source)
    fake_client = RecordingHttpClient(status_code=200)
    engine = ExecutionEngine(program=program, http_client=fake_client)

    result = engine.execute()

    assert result.status == ExecutionStatus.SUCCESS
    assert result.request.method == "GET"
    assert result.request.url == "https://example.com"
    assert result.response is not None
    assert result.response.status_code == 200
    assert result.response.body == '{"ok": true}'


def test_execution_engine_request_construction_uses_target_url_and_method() -> None:
    source = """\
target: web
    test: request
        request: GET
"""
    program = parse_valid_source(source)
    fake_client = RecordingHttpClient(status_code=200)
    engine = ExecutionEngine(program=program, http_client=fake_client)

    result = engine.execute()

    assert result.request.method == "GET"
    assert result.request.url == "https://example.com"
    assert fake_client.calls[0]["method"] == "GET"
    assert fake_client.calls[0]["url"] == "https://example.com"


def test_execution_engine_status_not_equals_passes_and_fails() -> None:
    source_pass = """\
target: web
    test: request
        request: GET
        with: status != 500
"""
    source_fail = """\
target: web
    test: request
        request: GET
        with: status != 200
"""

    pass_program = parse_valid_source(source_pass)
    fail_program = parse_valid_source(source_fail)

    pass_result = ExecutionEngine(
        program=pass_program,
        http_client=RecordingHttpClient(status_code=200),
    ).execute()
    fail_result = ExecutionEngine(
        program=fail_program,
        http_client=RecordingHttpClient(status_code=200),
    ).execute()

    assert pass_result.status == ExecutionStatus.SUCCESS
    assert fail_result.status == ExecutionStatus.ASSERTION_FAILURE
    assert fail_result.expected == 200
    assert fail_result.actual == 200


def test_execution_engine_response_capture_and_runtime_error_result() -> None:
    source = """\
target: web
    test: request
        request: GET
        with: status == 200
"""
    program = parse_valid_source(source)

    response_capture_result = ExecutionEngine(
        program=program,
        http_client=RecordingHttpClient(
            status_code=201,
            response_body='{"status": "created"}',
            headers={"x-id": "abc"},
        ),
    ).execute()

    assert response_capture_result.response is not None
    assert response_capture_result.response.status_code == 201
    assert response_capture_result.response.headers == {"x-id": "abc"}
    assert response_capture_result.response.body == '{"status": "created"}'

    runtime_error_program = parse_valid_source(source)
    runtime_error_result = ExecutionEngine(
        program=runtime_error_program,
        http_client=RecordingHttpClient(raise_error=TimeoutError("request timed out")),
    ).execute()
    assert runtime_error_result.status == ExecutionStatus.EXECUTION_ERROR
    assert "timed out" in runtime_error_result.error


def test_execution_engine_executes_multiple_tests_in_order() -> None:
    source = """\
target: web
    test: request
        request: GET
        with: status == 200
    test: request
        request: POST
        with: status == 201
"""
    program = parse_valid_source(source)
    first_target = replace(program.targets[0], url="https://example.com")
    first_test = replace(first_target.body[0], name="first")
    second_test = replace(first_target.body[1], name="second")
    target_with_names = replace(first_target, body=(first_test, second_test))
    renamed_program = replace(program, targets=(target_with_names,))

    fake_client = RecordingHttpClient(status_code=200)
    engine = ExecutionEngine(program=renamed_program, http_client=fake_client)
    results = engine.execute()

    assert isinstance(results, list)
    assert len(results) == 2
    assert [result.test_name for result in results] == ["first", "second"]
    assert [result.request.method for result in results] == ["GET", "POST"]

    first_call = fake_client.calls[0]
    second_call = fake_client.calls[1]
    assert first_call["method"] == "GET"
    assert second_call["method"] == "POST"
