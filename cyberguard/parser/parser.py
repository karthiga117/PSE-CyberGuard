"""Recursive-descent parser for the CyberGuard DSL v0.1."""

from __future__ import annotations

from cyberguard.lexer.tokens import Token, TokenType

from .ast import (
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
from .errors import ParserError


class Parser:
    """Recursive-descent parser for CyberGuard DSL v0.1."""

    def __init__(self, tokens: list[Token]) -> None:
        """Initialize the parser with a token stream."""
        self.tokens = tokens
        self.position = 0

    def parse(self) -> Program:
        """Parse a complete program."""
        # Skip leading blank lines
        self._skip_newlines()

        targets = []
        start_loc = self._current_location()

        while not self._match(TokenType.EOF):
            targets.append(self._parse_target_block())
            self._skip_newlines()

        if not targets:
            raise ParserError(
                "Expected at least one target block",
                start_loc.line,
                start_loc.column,
            )

        return Program(
            targets=tuple(targets),
            source_location=start_loc,
        )

    def _parse_target_block(self) -> TargetBlock:
        """Parse a target block."""
        start_loc = self._current_location()

        self._expect_keyword("target")
        self._expect_operator(":")

        # Parse target kind
        kind_token = self._current()
        if kind_token.type != TokenType.KEYWORD:
            raise ParserError(
                f"Expected target kind (web or cloud), got {kind_token.value}",
                kind_token.line,
                kind_token.column,
            )

        kind = kind_token.value
        if kind not in ("web", "cloud"):
            raise ParserError(
                f"Invalid target kind '{kind}'. Expected 'web' or 'cloud'",
                kind_token.line,
                kind_token.column,
            )

        self._advance()
        self._expect_newline()
        self._expect_indent()

        # Parse target body
        body = []
        if kind == "web":
            body = self._parse_web_target_body()
        elif kind == "cloud":
            body = self._parse_cloud_target_body()

        self._expect_dedent()

        return TargetBlock(
            kind=kind,
            body=tuple(body),
            source_location=start_loc,
        )

    def _parse_web_target_body(self) -> list:
        """Parse web target body (one or more test blocks)."""
        body = []

        while not self._check(TokenType.DEDENT) and not self._check(TokenType.EOF):
            self._skip_newlines()

            if self._check(TokenType.DEDENT) or self._check(TokenType.EOF):
                break

            if self._check_keyword("test"):
                body.append(self._parse_test_block())
            elif self._check_keyword("resource") or self._check_keyword("inspect"):
                raise ParserError(
                    f"Statement '{self._current().value}' is not allowed in web target",
                    self._current().line,
                    self._current().column,
                )
            else:
                raise ParserError(
                    f"Unexpected statement in web target: {self._current().value}",
                    self._current().line,
                    self._current().column,
                )

        if not body:
            raise ParserError(
                "Web target must contain at least one test block",
                self.tokens[self.position - 1].line,
                self.tokens[self.position - 1].column,
            )

        return body

    def _parse_cloud_target_body(self) -> list:
        """Parse cloud target body (exactly one resource, optionally one inspect)."""
        body = []

        # Expect exactly one resource statement
        if not self._check_keyword("resource"):
            raise ParserError(
                "Cloud target must start with a resource statement",
                self._current().line,
                self._current().column,
            )

        body.append(self._parse_resource_statement())
        self._skip_newlines()

        # Optionally parse one inspection statement
        if self._check_keyword("inspect"):
            body.append(self._parse_inspection_statement())
            self._skip_newlines()

        # Reject any other statements
        if not self._check(TokenType.DEDENT):
            raise ParserError(
                f"Unexpected statement in cloud target: {self._current().value}",
                self._current().line,
                self._current().column,
            )

        return body

    def _parse_test_block(self) -> TestBlock:
        """Parse a test block."""
        start_loc = self._current_location()

        self._expect_keyword("test")
        self._expect_operator(":")

        # Parse test kind
        kind_token = self._current()
        if kind_token.type != TokenType.KEYWORD or kind_token.value != "request":
            raise ParserError(
                f"Invalid test kind '{kind_token.value}'. Expected 'request'",
                kind_token.line,
                kind_token.column,
            )

        self._advance()
        self._expect_newline()
        self._expect_indent()

        # Parse test body
        body = self._parse_test_body()

        self._expect_dedent()

        return TestBlock(
            kind="request",
            body=tuple(body),
            source_location=start_loc,
        )

    def _parse_test_body(self) -> list:
        """Parse test body statements."""
        body = []

        # Parse exactly one request statement
        if not self._check_keyword("request"):
            raise ParserError(
                "Expected request statement",
                self._current().line,
                self._current().column,
            )
        body.append(self._parse_request_statement())
        self._skip_newlines()

        # Parse optional statements in order
        # Each optional statement can appear at most once

        if self._check_keyword("authenticate"):
            body.append(self._parse_authentication_statement())
            self._skip_newlines()

        if self._check_keyword("with"):
            body.append(self._parse_with_statement())
            self._skip_newlines()

        if self._check_keyword("inject"):
            body.append(self._parse_injection_statement())
            self._skip_newlines()

        if self._check_keyword("detect"):
            body.append(self._parse_detection_statement())
            self._skip_newlines()

        if self._check_keyword("expect"):
            body.append(self._parse_expectation_statement())
            self._skip_newlines()

        # Reject any invalid statements
        if not self._check(TokenType.DEDENT) and not self._check(TokenType.EOF):
            raise ParserError(
                f"Unexpected statement in test body: {self._current().value}",
                self._current().line,
                self._current().column,
            )

        return body

    def _parse_request_statement(self) -> RequestStatement:
        """Parse a request statement."""
        start_loc = self._current_location()

        self._expect_keyword("request")
        self._expect_operator(":")

        method_token = self._current()
        method = method_token.value

        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            raise ParserError(
                f"Invalid HTTP method '{method}'",
                method_token.line,
                method_token.column,
            )

        self._advance()

        return RequestStatement(method=method, source_location=start_loc)

    def _parse_authentication_statement(self) -> AuthenticationStatement:
        """Parse an authentication statement."""
        start_loc = self._current_location()

        self._expect_keyword("authenticate")
        self._expect_operator(":")

        method_token = self._current()
        method = method_token.value

        if method not in ("basic", "bearer", "api-key", "cookie"):
            raise ParserError(
                f"Invalid authentication method '{method}'",
                method_token.line,
                method_token.column,
            )

        self._advance()

        return AuthenticationStatement(method=method, source_location=start_loc)

    def _parse_with_statement(self) -> WithStatement:
        """Parse a with statement."""
        start_loc = self._current_location()

        self._expect_keyword("with")
        self._expect_operator(":")

        expression = self._parse_comparison_expression()

        return WithStatement(expression=expression, source_location=start_loc)

    def _parse_comparison_expression(self) -> ComparisonExpression:
        """Parse a comparison expression."""
        start_loc = self._current_location()

        # Parse left side (identifier or keyword-backed property names such as status/header/body)
        token = self._current()
        if token.type == TokenType.IDENTIFIER or (
            token.type == TokenType.KEYWORD and token.value in {"status", "header", "body"}
        ):
            left_name = token.value
            self._advance()
        else:
            raise ParserError(
                f"Expected identifier in comparison expression, got {token.value}",
                token.line,
                token.column,
            )

        # Parse operator
        if self._current().type != TokenType.OPERATOR or self._current().value not in (
            "==",
            "!=",
        ):
            raise ParserError(
                f"Expected comparison operator (== or !=), got {self._current().value}",
                self._current().line,
                self._current().column,
            )

        operator = self._current().value
        self._advance()

        # Parse right side (value)
        right = self._parse_value()

        return ComparisonExpression(
            left=IdentifierValue(name=left_name, source_location=start_loc),
            operator=operator,
            right=right,
            source_location=start_loc,
        )

    def _parse_value(
        self,
    ) -> StringLiteral | IntegerLiteral | BooleanLiteral | IdentifierValue:
        """Parse a value (string, integer, boolean, or identifier)."""
        start_loc = self._current_location()
        token = self._current()

        if token.type == TokenType.STRING:
            value = token.value
            self._advance()
            return StringLiteral(value=value, source_location=start_loc)

        elif token.type == TokenType.INTEGER:
            value = int(token.value)
            self._advance()
            return IntegerLiteral(value=value, source_location=start_loc)

        elif token.type == TokenType.KEYWORD and token.value in ("true", "false"):
            value = token.value == "true"
            self._advance()
            return BooleanLiteral(value=value, source_location=start_loc)

        elif token.type == TokenType.IDENTIFIER:
            name = token.value
            self._advance()
            return IdentifierValue(name=name, source_location=start_loc)

        else:
            raise ParserError(
                f"Expected value (string, integer, boolean, or identifier), got {token.value}",
                token.line,
                token.column,
            )

    def _parse_injection_statement(self) -> InjectionStatement:
        """Parse an injection statement."""
        start_loc = self._current_location()

        self._expect_keyword("inject")
        self._expect_operator(":")

        if not self._check_keyword("sql"):
            raise ParserError(
                f"Expected 'sql', got {self._current().value}",
                self._current().line,
                self._current().column,
            )

        self._advance()

        return InjectionStatement(kind="sql", source_location=start_loc)

    def _parse_detection_statement(self) -> DetectionStatement:
        """Parse a detection statement."""
        start_loc = self._current_location()

        self._expect_keyword("detect")
        self._expect_operator(":")

        if not self._check_keyword("sql-error"):
            raise ParserError(
                f"Expected 'sql-error', got {self._current().value}",
                self._current().line,
                self._current().column,
            )

        self._advance()

        return DetectionStatement(kind="sql-error", source_location=start_loc)

    def _parse_expectation_statement(self) -> ExpectationStatement:
        """Parse an expectation statement."""
        start_loc = self._current_location()

        self._expect_keyword("expect")
        self._expect_operator(":")

        kind_token = self._current()
        kind = kind_token.value

        valid_kinds = {
            "missing",
            "exists",
            "contains",
            "not-contains",
            "not-exists",
            "enabled",
            "disabled",
        }

        if kind not in valid_kinds:
            raise ParserError(
                f"Invalid expectation kind '{kind}'",
                kind_token.line,
                kind_token.column,
            )

        self._advance()

        return ExpectationStatement(kind=kind, source_location=start_loc)

    def _parse_resource_statement(self) -> ResourceStatement:
        """Parse a resource statement."""
        start_loc = self._current_location()

        self._expect_keyword("resource")
        self._expect_operator(":")

        kind_token = self._current()
        kind = kind_token.value

        if kind not in ("storage", "iam"):
            raise ParserError(
                f"Invalid resource kind '{kind}'",
                kind_token.line,
                kind_token.column,
            )

        self._advance()

        return ResourceStatement(kind=kind, source_location=start_loc)

    def _parse_inspection_statement(self) -> InspectionStatement:
        """Parse an inspection statement."""
        start_loc = self._current_location()

        self._expect_keyword("inspect")
        self._expect_operator(":")

        kind_token = self._current()
        kind = kind_token.value

        valid_kinds = {"storage", "iam", "header", "body", "status"}

        if kind not in valid_kinds:
            raise ParserError(
                f"Invalid inspection target '{kind}'",
                kind_token.line,
                kind_token.column,
            )

        self._advance()

        return InspectionStatement(kind=kind, source_location=start_loc)

    # Helper methods

    def _current(self) -> Token:
        """Get the current token."""
        if self.position >= len(self.tokens):
            return self.tokens[-1]  # Return EOF
        return self.tokens[self.position]

    def _current_location(self) -> SourceLocation:
        """Get the current source location."""
        token = self._current()
        return SourceLocation(line=token.line, column=token.column)

    def _peek(self, offset: int = 1) -> Token:
        """Peek ahead by offset tokens."""
        pos = self.position + offset
        if pos >= len(self.tokens):
            return self.tokens[-1]  # Return EOF
        return self.tokens[pos]

    def _advance(self) -> None:
        """Move to the next token."""
        if self.position < len(self.tokens) - 1:
            self.position += 1

    def _match(self, token_type: TokenType) -> bool:
        """Check if current token matches type and advance if so."""
        if self._current().type == token_type:
            self._advance()
            return True
        return False

    def _check(self, token_type: TokenType) -> bool:
        """Check if current token is of given type."""
        return self._current().type == token_type

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a keyword with given value."""
        return (
            self._current().type == TokenType.KEYWORD
            and self._current().value == keyword
        )

    def _expect_keyword(self, keyword: str) -> None:
        """Expect current token to be a keyword and advance."""
        token = self._current()
        if token.type != TokenType.KEYWORD or token.value != keyword:
            raise ParserError(
                f"Expected keyword '{keyword}', got {token.value}",
                token.line,
                token.column,
            )
        self._advance()

    def _expect_operator(self, operator: str) -> None:
        """Expect current token to be an operator and advance."""
        token = self._current()
        if token.type != TokenType.OPERATOR or token.value != operator:
            raise ParserError(
                f"Expected operator '{operator}', got {token.value}",
                token.line,
                token.column,
            )
        self._advance()

    def _expect_newline(self) -> None:
        """Expect current token to be a newline and advance."""
        token = self._current()
        if token.type != TokenType.NEWLINE:
            raise ParserError(
                f"Expected NEWLINE, got {token.type.value}",
                token.line,
                token.column,
            )
        self._advance()

    def _expect_indent(self) -> None:
        """Expect current token to be an indent and advance."""
        token = self._current()
        if token.type != TokenType.INDENT:
            raise ParserError(
                f"Expected INDENT, got {token.type.value}",
                token.line,
                token.column,
            )
        self._advance()

    def _expect_dedent(self) -> None:
        """Expect current token to be a dedent and advance."""
        token = self._current()
        if token.type != TokenType.DEDENT:
            raise ParserError(
                f"Expected DEDENT, got {token.type.value}",
                token.line,
                token.column,
            )
        self._advance()

    def _skip_newlines(self) -> None:
        """Skip any newline tokens."""
        while self._check(TokenType.NEWLINE):
            self._advance()
