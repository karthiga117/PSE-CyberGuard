"""Comprehensive tests for the CyberGuard Parser."""

import pytest

from cyberguard.lexer.lexer import Lexer
from cyberguard.parser import (
    AuthenticationStatement,
    BooleanLiteral,
    ComparisonExpression,
    DetectionStatement,
    ExpectationStatement,
    IdentifierValue,
    InjectionStatement,
    InspectionStatement,
    IntegerLiteral,
    Parser,
    ParserError,
    Program,
    RequestStatement,
    ResourceStatement,
    StringLiteral,
    TestBlock,
    WithStatement,
)


def parse(source: str) -> Program:
    """Helper to lex and parse source code."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    return parser.parse()


class TestValidPrograms:
    """Test parsing of valid CyberGuard programs."""

    def test_minimal_web_target(self) -> None:
        """Test minimal web target with one test."""
        source = """\
target: web
    test: request
        request: GET
"""
        prog = parse(source)

        assert isinstance(prog, Program)
        assert len(prog.targets) == 1

        target = prog.targets[0]
        assert target.kind == "web"
        assert len(target.body) == 1

        test = target.body[0]
        assert isinstance(test, TestBlock)
        assert test.kind == "request"
        assert len(test.body) == 1
        assert isinstance(test.body[0], RequestStatement)
        assert test.body[0].method == "GET"

    def test_web_target_with_all_statements(self) -> None:
        """Test web target with all optional test statements."""
        source = """\
target: web
    test: request
        request: GET
        authenticate: basic
        with: username == "admin"
        inject: sql
        detect: sql-error
        expect: exists
"""
        prog = parse(source)

        assert len(prog.targets) == 1
        target = prog.targets[0]
        assert target.kind == "web"

        test = target.body[0]
        assert isinstance(test, TestBlock)
        assert len(test.body) == 6

        assert isinstance(test.body[0], RequestStatement)
        assert test.body[0].method == "GET"

        assert isinstance(test.body[1], AuthenticationStatement)
        assert test.body[1].method == "basic"

        assert isinstance(test.body[2], WithStatement)
        assert isinstance(test.body[2].expression, ComparisonExpression)

        assert isinstance(test.body[3], InjectionStatement)
        assert test.body[3].kind == "sql"

        assert isinstance(test.body[4], DetectionStatement)
        assert test.body[4].kind == "sql-error"

        assert isinstance(test.body[5], ExpectationStatement)
        assert test.body[5].kind == "exists"

    def test_web_target_with_authentication(self) -> None:
        """Test web target with authentication."""
        source = """\
target: web
    test: request
        request: POST
        authenticate: bearer
"""
        prog = parse(source)

        test = prog.targets[0].body[0]
        assert len(test.body) == 2
        assert isinstance(test.body[1], AuthenticationStatement)
        assert test.body[1].method == "bearer"

    def test_web_target_with_with_statement(self) -> None:
        """Test web target with with-expression."""
        source = """\
target: web
    test: request
        request: GET
        with: x == "value"
"""
        prog = parse(source)

        test = prog.targets[0].body[0]
        assert len(test.body) == 2
        assert isinstance(test.body[1], WithStatement)

        expr = test.body[1].expression
        assert isinstance(expr, ComparisonExpression)
        assert isinstance(expr.left, IdentifierValue)
        assert expr.left.name == "x"
        assert expr.operator == "=="
        assert isinstance(expr.right, StringLiteral)
        assert expr.right.value == "value"

    def test_web_target_with_injection(self) -> None:
        """Test web target with injection."""
        source = """\
target: web
    test: request
        request: GET
        inject: sql
"""
        prog = parse(source)

        test = prog.targets[0].body[0]
        assert len(test.body) == 2
        assert isinstance(test.body[1], InjectionStatement)
        assert test.body[1].kind == "sql"

    def test_web_target_with_detection(self) -> None:
        """Test web target with detection."""
        source = """\
target: web
    test: request
        request: GET
        detect: sql-error
"""
        prog = parse(source)

        test = prog.targets[0].body[0]
        assert len(test.body) == 2
        assert isinstance(test.body[1], DetectionStatement)
        assert test.body[1].kind == "sql-error"

    def test_web_target_with_expectation(self) -> None:
        """Test web target with expectation."""
        source = """\
target: web
    test: request
        request: GET
        expect: missing
"""
        prog = parse(source)

        test = prog.targets[0].body[0]
        assert len(test.body) == 2
        assert isinstance(test.body[1], ExpectationStatement)
        assert test.body[1].kind == "missing"

    def test_minimal_cloud_target(self) -> None:
        """Test minimal cloud target."""
        source = """\
target: cloud
    resource: storage
"""
        prog = parse(source)

        assert len(prog.targets) == 1
        target = prog.targets[0]
        assert target.kind == "cloud"
        assert len(target.body) == 1
        assert isinstance(target.body[0], ResourceStatement)
        assert target.body[0].kind == "storage"

    def test_cloud_target_with_inspection(self) -> None:
        """Test cloud target with inspection."""
        source = """\
target: cloud
    resource: storage
    inspect: storage
"""
        prog = parse(source)

        target = prog.targets[0]
        assert len(target.body) == 2
        assert isinstance(target.body[0], ResourceStatement)
        assert isinstance(target.body[1], InspectionStatement)
        assert target.body[1].kind == "storage"

    def test_multiple_targets(self) -> None:
        """Test program with multiple targets."""
        source = """\
target: web
    test: request
        request: GET
target: cloud
    resource: iam
"""
        prog = parse(source)

        assert len(prog.targets) == 2
        assert prog.targets[0].kind == "web"
        assert prog.targets[1].kind == "cloud"

    def test_leading_blank_lines(self) -> None:
        """Test program with leading blank lines."""
        source = """\

target: web
    test: request
        request: GET
"""
        prog = parse(source)

        assert len(prog.targets) == 1

    def test_trailing_blank_lines(self) -> None:
        """Test program with trailing blank lines."""
        source = """\
target: web
    test: request
        request: GET

"""
        prog = parse(source)

        assert len(prog.targets) == 1

    def test_blank_lines_between_targets(self) -> None:
        """Test program with blank lines between targets."""
        source = """\
target: web
    test: request
        request: GET

target: cloud
    resource: storage
"""
        prog = parse(source)

        assert len(prog.targets) == 2

    def test_with_integer_value(self) -> None:
        """Test with-expression with integer value."""
        source = """\
target: web
    test: request
        request: GET
        with: port == 443
"""
        prog = parse(source)

        expr = prog.targets[0].body[0].body[1].expression
        assert isinstance(expr.right, IntegerLiteral)
        assert expr.right.value == 443

    def test_with_boolean_true(self) -> None:
        """Test with-expression with boolean true."""
        source = """\
target: web
    test: request
        request: GET
        with: isEnabled == true
"""
        prog = parse(source)

        expr = prog.targets[0].body[0].body[1].expression
        assert isinstance(expr.right, BooleanLiteral)
        assert expr.right.value is True

    def test_with_boolean_false(self) -> None:
        """Test with-expression with boolean false."""
        source = """\
target: web
    test: request
        request: GET
        with: active == false
"""
        prog = parse(source)

        expr = prog.targets[0].body[0].body[1].expression
        assert isinstance(expr.right, BooleanLiteral)
        assert expr.right.value is False

    def test_with_identifier_value(self) -> None:
        """Test with-expression with identifier as value."""
        source = """\
target: web
    test: request
        request: GET
        with: env == production
"""
        prog = parse(source)

        expr = prog.targets[0].body[0].body[1].expression
        assert isinstance(expr.right, IdentifierValue)
        assert expr.right.name == "production"

    def test_with_not_equal_operator(self) -> None:
        """Test with-expression with != operator."""
        source = """\
target: web
    test: request
        request: GET
        with: statusCode != "error"
"""
        prog = parse(source)

        expr = prog.targets[0].body[0].body[1].expression
        assert expr.operator == "!="

    def test_multiple_http_methods(self) -> None:
        """Test different HTTP methods."""
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            source = f"""\
target: web
    test: request
        request: {method}
"""
            prog = parse(source)
            assert prog.targets[0].body[0].body[0].method == method

    def test_multiple_auth_methods(self) -> None:
        """Test different authentication methods."""
        for method in ("basic", "bearer", "api-key", "cookie"):
            source = f"""\
target: web
    test: request
        request: GET
        authenticate: {method}
"""
            prog = parse(source)
            assert prog.targets[0].body[0].body[1].method == method

    def test_multiple_expectation_kinds(self) -> None:
        """Test different expectation kinds."""
        for kind in (
            "missing",
            "exists",
            "contains",
            "not-contains",
            "not-exists",
            "enabled",
            "disabled",
        ):
            source = f"""\
target: web
    test: request
        request: GET
        expect: {kind}
"""
            prog = parse(source)
            assert prog.targets[0].body[0].body[1].kind == kind

    def test_cloud_resource_kinds(self) -> None:
        """Test different resource kinds."""
        for kind in ("storage", "iam"):
            source = f"""\
target: cloud
    resource: {kind}
"""
            prog = parse(source)
            assert prog.targets[0].body[0].kind == kind

    def test_cloud_inspect_kinds(self) -> None:
        """Test different inspection kinds."""
        for kind in ("storage", "iam", "header", "body", "status"):
            source = f"""\
target: cloud
    resource: storage
    inspect: {kind}
"""
            prog = parse(source)
            assert prog.targets[0].body[1].kind == kind

    def test_multiple_tests_in_web_target(self) -> None:
        """Test multiple test blocks in same web target."""
        source = (
            "target: web\n"
            "    test: request\n"
            "        request: GET\n"
            "    test: request\n"
            "        request: POST\n"
        )
        prog = parse(source)

        target = prog.targets[0]
        assert len(target.body) == 2
        assert isinstance(target.body[0], TestBlock)
        assert isinstance(target.body[1], TestBlock)

    def test_web_target_blank_line_between_tests(self) -> None:
        """Blank lines between web test blocks are permitted."""
        source = (
            "target: web\n"
            "    test: request\n"
            "        request: GET\n"
            "\n"
            "    test: request\n"
            "        request: POST\n"
        )
        prog = parse(source)

        target = prog.targets[0]
        assert len(target.body) == 2
        assert target.body[0].body[0].method == "GET"
        assert target.body[1].body[0].method == "POST"

    def test_web_target_multiple_blank_lines_between_tests(self) -> None:
        """Multiple blank lines between web test blocks are permitted."""
        source = (
            "target: web\n"
            "    test: request\n"
            "        request: GET\n"
            "\n\n"
            "    test: request\n"
            "        request: POST\n"
        )
        prog = parse(source)

        target = prog.targets[0]
        assert len(target.body) == 2
        assert target.body[0].body[0].method == "GET"
        assert target.body[1].body[0].method == "POST"

    def test_web_target_blank_line_before_first_test(self) -> None:
        """An empty line before the first web test block is permitted."""
        source = (
            "target: web\n"
            "\n"
            "    test: request\n"
            "        request: GET\n"
        )
        prog = parse(source)

        target = prog.targets[0]
        assert len(target.body) == 1
        assert target.body[0].body[0].method == "GET"

    def test_web_target_blank_line_before_dedent(self) -> None:
        """Blank lines before a web target DEDENT are permitted."""
        source = (
            "target: web\n"
            "    test: request\n"
            "        request: GET\n"
            "\n"
        )
        prog = parse(source)

        target = prog.targets[0]
        assert len(target.body) == 1
        assert target.body[0].body[0].method == "GET"

    def test_source_location_preservation(self) -> None:
        """Test that source locations are preserved in AST."""
        source = """\
target: web
    test: request
        request: GET
"""
        prog = parse(source)

        # Verify source location exists and has line/column
        assert prog.source_location is not None
        assert prog.source_location.line > 0
        assert prog.source_location.column >= 0

        target = prog.targets[0]
        assert target.source_location is not None
        assert target.source_location.line > 0


class TestInvalidPrograms:
    """Test parser error handling."""

    def test_missing_target_colon(self) -> None:
        """Test error when target is missing colon."""
        source = """\
target web
    test: request
        request: GET
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert ":" in str(exc_info.value)

    def test_missing_target_kind(self) -> None:
        """Test error when target kind is missing."""
        source = """\
target:
    test: request
        request: GET
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_unsupported_target_kind(self) -> None:
        """Test error for unsupported target kind."""
        source = """\
target: api
    test: request
        request: GET
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "api" in str(exc_info.value) or "target kind" in str(exc_info.value)

    def test_missing_indent_after_target(self) -> None:
        """Test error when INDENT is missing after target."""
        source = """\
target: web
test: request
    request: GET
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "INDENT" in str(exc_info.value) or "indent" in str(exc_info.value)

    def test_missing_dedent_at_file_end(self) -> None:
        """Test error when DEDENT is missing at end of file."""
        source = """\
target: web
    test: request
        request: GET
    extra: invalid
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_missing_test_kind(self) -> None:
        """Test error when test kind is missing."""
        source = """\
target: web
    test:
        request: GET
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_unsupported_test_kind(self) -> None:
        """Test error for unsupported test kind."""
        source = """\
target: web
    test: inspect
        request: GET
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "inspect" in str(exc_info.value) or "test kind" in str(exc_info.value)

    def test_missing_request_statement(self) -> None:
        """Test error when request statement is missing."""
        source = """\
target: web
    test: request
        authenticate: basic
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "request" in str(exc_info.value)

    def test_invalid_http_method(self) -> None:
        """Test error for invalid HTTP method."""
        source = """\
target: web
    test: request
        request: INVALID
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "INVALID" in str(exc_info.value) or "method" in str(exc_info.value)

    def test_invalid_auth_method(self) -> None:
        """Test error for invalid authentication method."""
        source = """\
target: web
    test: request
        request: GET
        authenticate: invalid
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "invalid" in str(exc_info.value) or "authentication" in str(exc_info.value)

    def test_invalid_comparison_operator(self) -> None:
        """Test error for invalid comparison operator."""
        source = """\
target: web
    test: request
        request: GET
        with: x = "value"
"""
        # Single '=' is not supported by the lexer
        from cyberguard.lexer.errors import LexerError
        with pytest.raises(LexerError):
            parse(source)

    def test_missing_with_expression_left(self) -> None:
        """Test error when with-expression left side is missing."""
        source = """\
target: web
    test: request
        request: GET
        with: == "value"
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_missing_with_expression_right(self) -> None:
        """Test error when with-expression right side is missing."""
        source = """\
target: web
    test: request
        request: GET
        with: x ==
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_cloud_target_missing_resource(self) -> None:
        """Test error when cloud target is missing resource statement."""
        source = """\
target: cloud
    inspect: storage
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "resource" in str(exc_info.value)

    def test_invalid_resource_kind(self) -> None:
        """Test error for invalid resource kind."""
        source = """\
target: cloud
    resource: invalid
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "invalid" in str(exc_info.value) or "resource" in str(exc_info.value)

    def test_invalid_inspect_kind(self) -> None:
        """Test error for invalid inspection kind."""
        source = """\
target: cloud
    resource: storage
    inspect: invalid
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "invalid" in str(exc_info.value) or "inspect" in str(exc_info.value)

    def test_test_statement_in_cloud_target(self) -> None:
        """Test error when test statement appears in cloud target."""
        source = """\
target: cloud
    resource: storage
    test: request
        request: GET
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert ("test" in str(exc_info.value) or "cloud" in str(exc_info.value)
                or "allowed" in str(exc_info.value))

    def test_resource_statement_in_web_target(self) -> None:
        """Test error when resource statement appears in web target."""
        source = """\
target: web
    resource: storage
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert ("resource" in str(exc_info.value) or "web" in str(exc_info.value)
                or "allowed" in str(exc_info.value))

    def test_invalid_injection_kind(self) -> None:
        """Test error for invalid injection kind."""
        source = """\
target: web
    test: request
        request: GET
        inject: invalid
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "invalid" in str(exc_info.value) or "sql" in str(exc_info.value)

    def test_invalid_detection_kind(self) -> None:
        """Test error for invalid detection kind."""
        source = """\
target: web
    test: request
        request: GET
        detect: invalid
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "invalid" in str(exc_info.value) or "sql-error" in str(exc_info.value)

    def test_invalid_expectation_kind(self) -> None:
        """Test error for invalid expectation kind."""
        source = """\
target: web
    test: request
        request: GET
        expect: invalid
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "invalid" in str(exc_info.value) or "expectation" in str(exc_info.value)

    def test_statement_out_of_order(self) -> None:
        """Test error when statements are out of order."""
        source = """\
target: web
    test: request
        request: GET
        expect: exists
        authenticate: basic
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_empty_web_target(self) -> None:
        """Test error when web target has no test blocks."""
        source = """\
target: web
"""
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        # Error occurs when expecting INDENT after target header
        assert ("INDENT" in str(exc_info.value) or "test" in str(exc_info.value)
                or "web" in str(exc_info.value))

    def test_duplicate_request_statements(self) -> None:
        """Test error when request statement appears twice."""
        # Note: This depends on lexer emitting unique identifier tokens
        source = """\
target: web
    test: request
        request: GET
        request: POST
"""
        with pytest.raises(ParserError):
            parse(source)

    def test_no_targets(self) -> None:
        """Test error when program has no targets."""
        source = ""

        with pytest.raises(ParserError) as exc_info:
            parse(source)
        assert "target" in str(exc_info.value)

    def test_unexpected_eof(self) -> None:
        """Test error on unexpected EOF."""
        source = """\
target: web
    test: request
"""
        with pytest.raises(ParserError):
            parse(source)


class TestASTStructure:
    """Test AST structure and node properties."""

    def test_program_contains_targets(self) -> None:
        """Test that Program node contains targets tuple."""
        source = """\
target: web
    test: request
        request: GET
target: cloud
    resource: storage
"""
        prog = parse(source)

        assert hasattr(prog, "targets")
        assert isinstance(prog.targets, tuple)
        assert len(prog.targets) == 2

    def test_target_block_structure(self) -> None:
        """Test TargetBlock has expected fields."""
        source = """\
target: web
    test: request
        request: GET
"""
        prog = parse(source)
        target = prog.targets[0]

        assert hasattr(target, "kind")
        assert hasattr(target, "body")
        assert hasattr(target, "source_location")
        assert target.kind == "web"
        assert isinstance(target.body, tuple)

    def test_test_block_structure(self) -> None:
        """Test TestBlock has expected fields."""
        source = """\
target: web
    test: request
        request: GET
"""
        prog = parse(source)
        test = prog.targets[0].body[0]

        assert hasattr(test, "kind")
        assert hasattr(test, "body")
        assert hasattr(test, "source_location")
        assert test.kind == "request"
        assert isinstance(test.body, tuple)

    def test_request_statement_structure(self) -> None:
        """Test RequestStatement has expected fields."""
        source = """\
target: web
    test: request
        request: POST
"""
        prog = parse(source)
        stmt = prog.targets[0].body[0].body[0]

        assert isinstance(stmt, RequestStatement)
        assert hasattr(stmt, "method")
        assert hasattr(stmt, "source_location")
        assert stmt.method == "POST"

    def test_comparison_expression_structure(self) -> None:
        """Test ComparisonExpression has expected fields."""
        source = """\
target: web
    test: request
        request: GET
        with: user == "admin"
"""
        prog = parse(source)
        expr = prog.targets[0].body[0].body[1].expression

        assert isinstance(expr, ComparisonExpression)
        assert hasattr(expr, "left")
        assert hasattr(expr, "operator")
        assert hasattr(expr, "right")
        assert hasattr(expr, "source_location")

    def test_value_nodes_are_correct_type(self) -> None:
        """Test that value nodes have correct types."""
        # String literal
        source2 = """\
target: web
    test: request
        request: GET
        with: x == "test"
"""
        prog2 = parse(source2)
        right = prog2.targets[0].body[0].body[1].expression.right
        assert isinstance(right, StringLiteral)
        assert right.value == "test"

        # Integer literal
        source3 = """\
target: web
    test: request
        request: GET
        with: x == 42
"""
        prog3 = parse(source3)
        right3 = prog3.targets[0].body[0].body[1].expression.right
        assert isinstance(right3, IntegerLiteral)
        assert right3.value == 42

        # Boolean literal
        source4 = """\
target: web
    test: request
        request: GET
        with: x == true
"""
        prog4 = parse(source4)
        right4 = prog4.targets[0].body[0].body[1].expression.right
        assert isinstance(right4, BooleanLiteral)
        assert right4.value is True

        # Identifier value
        source5 = """\
target: web
    test: request
        request: GET
        with: x == name
"""
        prog5 = parse(source5)
        right5 = prog5.targets[0].body[0].body[1].expression.right
        assert isinstance(right5, IdentifierValue)
        assert right5.name == "name"

    def test_immutable_ast_nodes(self) -> None:
        """Test that AST nodes are immutable."""
        source = """\
target: web
    test: request
        request: GET
"""
        prog = parse(source)
        stmt = prog.targets[0].body[0].body[0]

        # Attempt to modify should raise FrozenInstanceError
        with pytest.raises((AttributeError, TypeError)):
            stmt.method = "POST"  # type: ignore
