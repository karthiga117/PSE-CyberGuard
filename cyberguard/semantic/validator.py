"""Semantic validation for CyberGuard AST programs."""

from __future__ import annotations

from typing import Any

from cyberguard.parser.ast import (
    AuthenticationStatement,
    BooleanLiteral,
    ComparisonExpression,
    DetectionStatement,
    ExpectationStatement,
    IdentifierValue,
    InjectionStatement,
    InspectionStatement,
    IntegerLiteral,
    Program,
    RequestStatement,
    ResourceStatement,
    SourceLocation,
    StringLiteral,
    TargetBlock,
    TestBlock,
    WithStatement,
)
from cyberguard.semantic.errors import SemanticError
from cyberguard.semantic.rules import (
    COMMON_CLOUD_PROPERTY_SUGGESTIONS,
    SUPPORTED_AUTH_METHODS,
    SUPPORTED_CLOUD_PROPERTIES,
    SUPPORTED_DETECTION_TYPES,
    SUPPORTED_EXPECTATION_KINDS,
    SUPPORTED_HTTP_METHODS,
    SUPPORTED_INJECTION_TYPES,
    SUPPORTED_INSPECTION_TYPES,
    SUPPORTED_RESOURCE_TYPES,
    get_suggestion,
    is_blank,
    is_valid_url,
    validate_status_code,
)


class SemanticValidator:
    """Validate the semantic meaning of a parsed CyberGuard program."""

    def validate(self, program: Program) -> None:
        """Validate a complete CyberGuard program AST."""
        if not isinstance(program, Program):
            raise TypeError("SemanticValidator.validate() requires a Program AST node.")

        for target in program.targets:
            self._validate_target(target)

        self._validate_unique_names(program)
        self._validate_non_empty_names(program)

        for target in program.targets:
            if target.kind == "web":
                for test in target.body:
                    if isinstance(test, TestBlock):
                        self._validate_test(test)
            elif target.kind == "cloud":
                self._validate_cloud_target_body(target)

    def _validate_target(self, target: TargetBlock) -> None:
        """Validate target-level semantics."""
        if target.kind == "web":
            self._validate_web_target(target)
            for item in target.body:
                if isinstance(item, (ResourceStatement, InspectionStatement)):
                    raise SemanticError(
                        rule_id="V-004",
                        message=(
                            "Cloud-specific resource and inspection statements are not "
                            "allowed in a web target."
                        ),
                        line=item.source_location.line,
                        column=item.source_location.column,
                        suggestion="Move the resource/inspect statements under a cloud target.",
                    )
        elif target.kind == "cloud":
            self._validate_cloud_target(target)
            for item in target.body:
                if isinstance(item, TestBlock):
                    raise SemanticError(
                        rule_id="V-003",
                        message="Web security tests must belong to a web target.",
                        line=item.source_location.line,
                        column=item.source_location.column,
                        suggestion="Move the test block under a target: web section.",
                    )

    def _validate_web_target(self, target: TargetBlock) -> None:
        """Validate web target URL semantics (V-001)."""
        url = getattr(target, "url", None)
        if not is_valid_url(url):
            raise SemanticError(
                rule_id="V-001",
                message="Invalid web target URL.",
                line=target.source_location.line,
                column=target.source_location.column,
                suggestion="Use a complete URL such as https://api.example.com or http://localhost:8080.",
            )

    def _validate_cloud_target(self, target: TargetBlock) -> None:
        """Validate cloud target provider semantics (V-002)."""
        provider = str(getattr(target, "provider", "") or "").strip().lower()
        if provider != "aws":
            raise SemanticError(
                rule_id="V-002",
                message=f"Unsupported cloud provider '{provider or '<missing>'}'.",
                line=target.source_location.line,
                column=target.source_location.column,
                suggestion="Use AWS as the supported provider for CyberGuard v0.1.",
            )

        if not any(isinstance(item, ResourceStatement) for item in target.body):
            raise SemanticError(
                rule_id="V-017",
                message="Cloud targets must declare a resource.",
                line=target.source_location.line,
                column=target.source_location.column,
                suggestion="Add a resource: storage or resource: iam statement.",
            )

        resource_count: dict[str, ResourceStatement] = {}
        for item in target.body:
            if not isinstance(item, ResourceStatement):
                continue
            if item.kind not in SUPPORTED_RESOURCE_TYPES:
                raise SemanticError(
                    rule_id="V-017",
                    message=f"Unsupported cloud resource type '{item.kind}'.",
                    line=item.source_location.line,
                    column=item.source_location.column,
                    suggestion=(
                        "Use one of: storage, iam."
                    ),
                )
            key = item.kind.lower()
            if key in resource_count:
                raise SemanticError(
                    rule_id="V-020",
                    message=f"Duplicate cloud resource declaration '{item.kind}'.",
                    line=item.source_location.line,
                    column=item.source_location.column,
                    suggestion=f"Remove the duplicate '{item.kind}' resource declaration.",
                )
            resource_count[key] = item

        for item in target.body:
            if isinstance(item, InspectionStatement):
                if item.kind not in SUPPORTED_INSPECTION_TYPES:
                    raise SemanticError(
                        rule_id="V-018",
                        message=f"Unsupported cloud inspection target '{item.kind}'.",
                        line=item.source_location.line,
                        column=item.source_location.column,
                        suggestion=(
                            "Use a supported inspection target such as storage, "
                            "iam, header, body, or status."
                        ),
                    )

    def _validate_cloud_target_body(self, target: TargetBlock) -> None:
        """Validate cloud-body ordering and property rules such as V-018, V-019, V-021."""
        inspection_index = None
        for index, item in enumerate(target.body):
            if isinstance(item, InspectionStatement):
                inspection_index = index
                break

        for index, item in enumerate(target.body):
            if isinstance(item, ExpectationStatement):
                self._validate_expectation_statement(item)
            elif isinstance(item, WithStatement):
                self._validate_with_statement(item)
                left_name = getattr(item.expression.left, "name", "")
                if left_name and left_name not in {"status", "header", "body"}:
                    self._validate_cloud_property_name(
                        left_name,
                        item.expression.left.source_location,
                    )
            elif isinstance(item, ComparisonExpression):
                self._validate_comparison_expression(item)
                left_name = getattr(item.left, "name", "")
                if left_name and left_name not in {"status", "header", "body"}:
                    self._validate_cloud_property_name(
                        left_name,
                        item.left.source_location,
                    )

            if isinstance(item, (ExpectationStatement, WithStatement, ComparisonExpression)) and (
                inspection_index is not None and index < inspection_index
            ):
                raise SemanticError(
                    rule_id="V-019",
                    message="Cloud assertions require an inspection before they can be evaluated.",
                    line=item.source_location.line,
                    column=item.source_location.column,
                    suggestion="Place the inspect statement before the cloud assertion.",
                )

    def _validate_unique_names(self, program: Program) -> None:
        """Validate duplicate test/check names (V-005)."""
        seen: dict[str, SourceLocation] = {}
        for target in program.targets:
            for item in target.body:
                if not isinstance(item, (TestBlock, ResourceStatement)):
                    continue
                name = getattr(item, "name", None)
                if name is None:
                    continue
                if name in seen:
                    raise SemanticError(
                        rule_id="V-005",
                        message=f"Duplicate test/check name '{name}'.",
                        line=item.source_location.line,
                        column=item.source_location.column,
                        suggestion="Use a unique name for each test or cloud check.",
                    )
                seen[name] = item.source_location

    def _validate_non_empty_names(self, program: Program) -> None:
        """Validate empty or whitespace-only names (V-006)."""
        for target in program.targets:
            for item in target.body:
                if not isinstance(item, (TestBlock, ResourceStatement)):
                    continue
                name = getattr(item, "name", None)
                if name is None:
                    continue
                if is_blank(str(name)):
                    raise SemanticError(
                        rule_id="V-006",
                        message="Test/check names must not be empty or whitespace only.",
                        line=item.source_location.line,
                        column=item.source_location.column,
                        suggestion="Provide a non-empty name for this test or resource.",
                    )

    def _validate_test(self, test: TestBlock) -> None:
        """Validate a test block and its request-related semantics."""
        requests = [item for item in test.body if isinstance(item, RequestStatement)]
        if len(requests) == 0:
            raise SemanticError(
                rule_id="V-009",
                message="Each test must contain exactly one request.",
                line=test.source_location.line,
                column=test.source_location.column,
                suggestion="Add a single request: GET/POST/PUT/... statement to the test.",
            )
        if len(requests) > 1:
            raise SemanticError(
                rule_id="V-009",
                message="Each test must contain exactly one request.",
                line=requests[1].source_location.line,
                column=requests[1].source_location.column,
                suggestion="Remove duplicate request statements so each test has only one request.",
            )

        request_index = next(
            index for index, item in enumerate(test.body) if isinstance(item, RequestStatement)
        )

        for index, item in enumerate(test.body):
            if isinstance(item, RequestStatement):
                self._validate_request_statement(item)
            elif isinstance(item, AuthenticationStatement):
                self._validate_authentication_statement(item)
            elif isinstance(item, WithStatement):
                self._validate_with_statement(item)
            elif isinstance(item, InjectionStatement):
                self._validate_injection_statement(item)
            elif isinstance(item, DetectionStatement):
                self._validate_detection_statement(item)
            elif isinstance(item, ExpectationStatement):
                if index < request_index:
                    raise SemanticError(
                        rule_id="V-010",
                        message="A request must occur before request-dependent assertions.",
                        line=item.source_location.line,
                        column=item.source_location.column,
                        suggestion="Move the request statement above the expect statement.",
                    )
                self._validate_expectation_statement(item)
            elif isinstance(item, ComparisonExpression):
                self._validate_comparison_expression(item)
            elif isinstance(item, StringLiteral):
                continue

    def _validate_request_statement(self, request: RequestStatement) -> None:
        """Validate request path and method semantics (V-007, V-008)."""
        if request.method not in SUPPORTED_HTTP_METHODS:
            raise SemanticError(
                rule_id="V-008",
                message=f"Invalid HTTP method '{request.method}'.",
                line=request.source_location.line,
                column=request.source_location.column,
                suggestion=(
                    "Use one of: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS."
                ),
            )

        path = getattr(request, "path", None)
        if path is None:
            return
        if not str(path).startswith("/"):
            raise SemanticError(
                rule_id="V-007",
                message=f"Invalid request path '{path}'.",
                line=request.source_location.line,
                column=request.source_location.column,
                suggestion="Paths must begin with '/'. For example: /login or /api/users.",
            )

    def _validate_authentication_statement(self, statement: AuthenticationStatement) -> None:
        """Validate authentication type semantics (V-011)."""
        if statement.method not in SUPPORTED_AUTH_METHODS:
            raise SemanticError(
                rule_id="V-011",
                message=f"Unsupported authentication type '{statement.method}'.",
                line=statement.source_location.line,
                column=statement.source_location.column,
                suggestion="Use one of: basic, bearer, api-key, cookie.",
            )

    def _validate_with_statement(self, statement: WithStatement) -> None:
        """Validate with-expression semantics for assertions and comparisons."""
        self._validate_comparison_expression(statement.expression)

    def _validate_comparison_expression(self, expression: ComparisonExpression) -> None:
        """Validate expression kinds used by assertions."""
        left_name = getattr(expression.left, "name", "")
        right = expression.right

        if left_name == "status":
            if not isinstance(right, IntegerLiteral):
                raise SemanticError(
                    rule_id="V-014",
                    message="Status code assertions must compare against an integer value.",
                    line=expression.source_location.line,
                    column=expression.source_location.column,
                    suggestion="Compare status to an integer such as 200 or 401.",
                )
            if not validate_status_code(right.value):
                raise SemanticError(
                    rule_id="V-014",
                    message=f"Invalid HTTP status code '{right.value}'.",
                    line=expression.source_location.line,
                    column=expression.source_location.column,
                    suggestion="Use an integer from 100 through 599.",
                )

        if left_name in {"header", "body"}:
            if isinstance(right, StringLiteral) and is_blank(right.value):
                raise SemanticError(
                    rule_id="V-015" if left_name == "header" else "V-016",
                    message=(
                        "Header assertion value cannot be empty."
                        if left_name == "header"
                        else "Body assertion value cannot be empty."
                    ),
                    line=expression.source_location.line,
                    column=expression.source_location.column,
                    suggestion="Provide the required header or body value.",
                )

        if left_name == "header":
            if not isinstance(right, (StringLiteral, IdentifierValue)):
                raise SemanticError(
                    rule_id="V-015",
                    message="Header assertions must compare a header name to a string value.",
                    line=expression.source_location.line,
                    column=expression.source_location.column,
                    suggestion="Use a structure such as header == \"Authorization\".",
                )

        if left_name in {
            "public_access",
            "encryption",
            "mfa_enabled",
            "root_access_disabled",
        }:
            if not isinstance(
                right,
                (BooleanLiteral, IntegerLiteral, StringLiteral, IdentifierValue),
            ):
                raise SemanticError(
                    rule_id="V-018",
                    message=(
                        f"Cloud property '{left_name}' must use a valid boolean or "
                        "scalar value."
                    ),
                    line=expression.source_location.line,
                    column=expression.source_location.column,
                    suggestion="Compare the property to a supported boolean or scalar value.",
                )
            if left_name not in SUPPORTED_CLOUD_PROPERTIES:
                suggestion = COMMON_CLOUD_PROPERTY_SUGGESTIONS.get(left_name)
                raise SemanticError(
                    rule_id="V-021",
                    message=f"Unknown cloud property '{left_name}'.",
                    line=expression.source_location.line,
                    column=expression.source_location.column,
                    suggestion=(
                        f"Did you mean '{suggestion}'?"
                        if suggestion
                        else "Use a supported CyberGuard cloud property."
                    ),
                )

    def _validate_expectation_statement(self, statement: ExpectationStatement) -> None:
        """Validate expectation-kind semantics (V-016, V-018)."""
        if statement.kind not in SUPPORTED_EXPECTATION_KINDS:
            raise SemanticError(
                rule_id="V-018",
                message=f"Unsupported expectation kind '{statement.kind}'.",
                line=statement.source_location.line,
                column=statement.source_location.column,
                suggestion=(
                    "Use one of: missing, exists, contains, not-contains, "
                    "not-exists, enabled, disabled."
                ),
            )

    def _validate_detection_statement(self, statement: DetectionStatement) -> None:
        """Validate detection type semantics (V-013)."""
        if statement.kind not in SUPPORTED_DETECTION_TYPES:
            raise SemanticError(
                rule_id="V-013",
                message=f"Unsupported detection type '{statement.kind}'.",
                line=statement.source_location.line,
                column=statement.source_location.column,
                suggestion="Use the supported detection type: sql-error.",
            )

    def _validate_injection_statement(self, statement: Any) -> None:
        """Validate injection type semantics (V-012)."""
        if statement.kind not in SUPPORTED_INJECTION_TYPES:
            raise SemanticError(
                rule_id="V-012",
                message=f"Unsupported injection type '{statement.kind}'.",
                line=statement.source_location.line,
                column=statement.source_location.column,
                suggestion="Use the supported injection type: sql.",
            )

    def _validate_cloud_property_name(self, name: str, location: SourceLocation) -> None:
        """Validate cloud property names against the supported CyberGuard property set (V-021)."""
        if is_blank(name):
            raise SemanticError(
                rule_id="V-021",
                message="Cloud property name cannot be empty.",
                line=location.line,
                column=location.column,
                suggestion="Use a supported cloud property name.",
            )
        if name not in SUPPORTED_CLOUD_PROPERTIES:
            suggestion = COMMON_CLOUD_PROPERTY_SUGGESTIONS.get(name) or get_suggestion(
                name,
                SUPPORTED_CLOUD_PROPERTIES,
            )
            raise SemanticError(
                rule_id="V-021",
                message=f"Unknown cloud property '{name}'.",
                line=location.line,
                column=location.column,
                suggestion=(
                    f"Did you mean '{suggestion}'?"
                    if suggestion
                    else "Use a supported cloud property name."
                ),
            )
