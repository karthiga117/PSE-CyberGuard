"""Core execution engine for CyberGuard web tests."""

from __future__ import annotations

from urllib.parse import urljoin

from cyberguard.execution.http_client import HttpClient, UrllibHttpClient
from cyberguard.execution.result import (
    ExecutionResult,
    ExecutionStatus,
    HttpRequestSpec,
    HttpResponseCapture,
)
from cyberguard.parser.ast import (
    ComparisonExpression,
    IntegerLiteral,
    Program,
    RequestStatement,
    TargetBlock,
    TestBlock,
    WithStatement,
)


class ExecutionEngine:
    """Execute a valid CyberGuard web AST against an HTTP runtime."""

    def __init__(
        self,
        program: Program | None = None,
        http_client: HttpClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.program = program
        self.http_client = http_client or UrllibHttpClient()
        self.timeout = timeout

    def execute(
        self,
        program: Program | None = None,
        test_name: str | None = None,
    ) -> ExecutionResult | list[ExecutionResult]:
        """Execute one or more web tests from a validated AST."""
        selected_program = self.program if program is None else program
        if selected_program is None:
            raise ValueError("ExecutionEngine requires a Program AST.")
        if not isinstance(selected_program, Program):
            raise TypeError("ExecutionEngine.execute() requires a Program AST node.")

        results: list[ExecutionResult] = []
        for target in selected_program.targets:
            if target.kind != "web":
                continue
            results.extend(self._execute_target(target, test_name=test_name))

        if not results:
            raise ValueError("No web target tests were found in the AST.")
        if len(results) == 1:
            return results[0]
        return results

    def _execute_target(
        self,
        target: TargetBlock,
        test_name: str | None = None,
    ) -> list[ExecutionResult]:
        """Execute all tests in a web target."""
        target_url = getattr(target, "url", None)
        if not target_url:
            raise ValueError("Web target is missing a URL.")

        results: list[ExecutionResult] = []
        for item in target.body:
            if not isinstance(item, TestBlock):
                continue
            if test_name is not None and getattr(item, "name", None) != test_name:
                continue
            results.append(self._execute_test(target_url, item))
        return results

    def _execute_test(self, target_url: str, test: TestBlock) -> ExecutionResult:
        """Execute a single web test block."""
        request = self._find_request(test)
        if request is None:
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                target_kind="web",
                target_url=target_url,
                test_name=getattr(test, "name", None),
                request=HttpRequestSpec(method="GET", url=target_url),
                error="No request statement found in test block.",
                message="Execution failed because the test contains no request.",
            )

        url = self._build_url(target_url, getattr(request, "path", None))
        headers: dict[str, str] = {}
        request_spec = HttpRequestSpec(method=request.method, url=url, headers=headers)

        try:
            response = self.http_client.request(
                method=request.method,
                url=url,
                headers=headers,
                body=None,
                timeout=self.timeout,
            )
        except Exception as exc:  # pragma: no cover - runtime wrapper behavior
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                target_kind="web",
                target_url=target_url,
                test_name=getattr(test, "name", None),
                request=request_spec,
                error=f"{type(exc).__name__}: {exc}",
                message="The HTTP request could not be completed.",
            )

        response_capture = HttpResponseCapture(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body,
            url=response.url,
        )

        assertion = self._find_status_assertion(test)
        if assertion is None:
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                target_kind="web",
                target_url=target_url,
                test_name=getattr(test, "name", None),
                request=request_spec,
                response=response_capture,
                message="Request executed successfully; no assertions were configured.",
            )

        expected = assertion[1]
        actual = response.status_code
        passed = self._compare_status(actual, expected, assertion[0])
        if passed:
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                target_kind="web",
                target_url=target_url,
                test_name=getattr(test, "name", None),
                request=request_spec,
                response=response_capture,
                assertion="status",
                expected=expected,
                actual=actual,
                message=f"Expected status: {expected}; Actual status: {actual}",
            )

        return ExecutionResult(
            status=ExecutionStatus.ASSERTION_FAILURE,
            target_kind="web",
            target_url=target_url,
            test_name=getattr(test, "name", None),
            request=request_spec,
            response=response_capture,
            assertion="status",
            expected=expected,
            actual=actual,
            message=f"Expected status: {expected}; Actual status: {actual}",
        )

    def _find_request(self, test: TestBlock) -> RequestStatement | None:
        """Find the request statement in a test block."""
        for item in test.body:
            if isinstance(item, RequestStatement):
                return item
        return None

    def _find_status_assertion(self, test: TestBlock) -> tuple[str, int] | None:
        """Locate a status comparison assertion in the test body."""
        for item in test.body:
            expr = None
            if isinstance(item, WithStatement):
                expr = item.expression
            elif isinstance(item, ComparisonExpression):
                expr = item

            if expr is None or not isinstance(expr, ComparisonExpression):
                continue
            if getattr(expr.left, "name", "") != "status":
                continue
            if not isinstance(expr.right, IntegerLiteral):
                continue
            return expr.operator, int(expr.right.value)
        return None

    def _compare_status(self, actual: int, expected: int, operator: str) -> bool:
        """Compare status code values using the supported operators."""
        if operator == "==":
            return actual == expected
        if operator == "!=":
            return actual != expected
        return False

    def _build_url(self, base_url: str, path: str | None) -> str:
        """Construct the runtime URL from the target URL and request path."""
        if path is None or path == "":
            return base_url
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
