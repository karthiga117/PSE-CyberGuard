"""Semantic validation tests for CyberGuard v0.1."""

import pytest

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
from cyberguard.semantic import SemanticError, SemanticValidator


def loc(line: int, column: int) -> SourceLocation:
    return SourceLocation(line=line, column=column)


def make_request(method: str = "GET", path: str = "/login") -> RequestStatement:
    return RequestStatement(method=method, source_location=loc(2, 1), path=path)


def make_test(name: str | None = "auth", *items: object) -> TestBlock:
    return TestBlock(kind="request", body=tuple(items), source_location=loc(1, 1), name=name)


def make_web_program(*tests: TestBlock, url: str = "https://example.com") -> Program:
    target = TargetBlock(kind="web", body=tuple(tests), source_location=loc(1, 1), url=url)
    return Program(targets=(target,), source_location=loc(1, 1))


def make_cloud_program(*items: object, provider: str = "aws") -> Program:
    target = TargetBlock(
        kind="cloud",
        body=tuple(items),
        source_location=loc(1, 1),
        provider=provider,
    )
    return Program(targets=(target,), source_location=loc(1, 1))


def test_v001_valid() -> None:
    validator = SemanticValidator()
    program = make_web_program(make_test("auth", make_request("GET", "/login")))
    validator.validate(program)


def test_v001_invalid() -> None:
    validator = SemanticValidator()
    target = TargetBlock(
        kind="web",
        body=(make_test("auth", make_request("GET", "/login")),),
        source_location=loc(1, 1),
        url="example.com",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(Program(targets=(target,), source_location=loc(1, 1)))
    assert exc_info.value.rule_id == "V-001"


def test_v002_valid() -> None:
    validator = SemanticValidator()
    program = make_cloud_program(
        ResourceStatement(kind="storage", source_location=loc(1, 1)),
        provider="aws",
    )
    validator.validate(program)


def test_v002_invalid() -> None:
    validator = SemanticValidator()
    target = TargetBlock(
        kind="cloud",
        body=(ResourceStatement(kind="storage", source_location=loc(1, 1)),),
        source_location=loc(1, 1),
        provider="azure",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(Program(targets=(target,), source_location=loc(1, 1)))
    assert exc_info.value.rule_id == "V-002"


def test_v003_invalid() -> None:
    validator = SemanticValidator()
    target = TargetBlock(
        kind="cloud",
        body=(
            ResourceStatement(kind="storage", source_location=loc(1, 1)),
            make_test("auth", make_request("GET", "/login")),
        ),
        source_location=loc(1, 1),
        provider="aws",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(Program(targets=(target,), source_location=loc(1, 1)))
    assert exc_info.value.rule_id == "V-003"


def test_v004_invalid() -> None:
    validator = SemanticValidator()
    target = TargetBlock(
        kind="web",
        body=(ResourceStatement(kind="storage", source_location=loc(1, 1)),),
        source_location=loc(1, 1),
        url="https://example.com",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(Program(targets=(target,), source_location=loc(1, 1)))
    assert exc_info.value.rule_id == "V-004"


def test_v005_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(
        make_test("duplicate", make_request("GET", "/login")),
        make_test("duplicate", make_request("GET", "/users")),
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-005"


def test_v006_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(make_test("   ", make_request("GET", "/login")))
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-006"


def test_v007_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(make_test("auth", make_request("GET", "login")))
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-007"


def test_v008_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(make_test("auth", make_request("FETCH", "/login")))
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-008"


def test_v009_zero_requests() -> None:
    validator = SemanticValidator()
    program = make_web_program(make_test("auth"))
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-009"


def test_v009_multiple_requests() -> None:
    validator = SemanticValidator()
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            make_request("POST", "/login"),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-009"


def test_v010_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(
        make_test(
            "auth",
            ExpectationStatement(kind="exists", source_location=loc(2, 1)),
            make_request("GET", "/login"),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-010"


def test_v011_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            AuthenticationStatement(method="oauth", source_location=loc(3, 1)),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-011"


def test_v012_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            InjectionStatement(kind="xss", source_location=loc(3, 1)),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-012"


def test_v013_invalid() -> None:
    validator = SemanticValidator()
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            DetectionStatement(kind="error-pattern", source_location=loc(3, 1)),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-013"


def test_v014_invalid() -> None:
    validator = SemanticValidator()
    expr = ComparisonExpression(
        left=IdentifierValue(name="status", source_location=loc(3, 1)),
        operator="==",
        right=IntegerLiteral(value=99, source_location=loc(3, 12)),
        source_location=loc(3, 1),
    )
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            WithStatement(expr, source_location=loc(3, 1)),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-014"


def test_v015_invalid() -> None:
    validator = SemanticValidator()
    expr = ComparisonExpression(
        left=IdentifierValue(name="header", source_location=loc(3, 1)),
        operator="==",
        right=StringLiteral(value="", source_location=loc(3, 12)),
        source_location=loc(3, 1),
    )
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            WithStatement(expr, source_location=loc(3, 1)),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-015"


def test_v016_invalid() -> None:
    validator = SemanticValidator()
    expr = ComparisonExpression(
        left=IdentifierValue(name="body", source_location=loc(3, 1)),
        operator="==",
        right=StringLiteral(value="", source_location=loc(3, 9)),
        source_location=loc(3, 1),
    )
    program = make_web_program(
        make_test(
            "auth",
            make_request("GET", "/login"),
            WithStatement(expr, source_location=loc(3, 1)),
        )
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-016"


def test_v017_invalid() -> None:
    validator = SemanticValidator()
    program = make_cloud_program(
        ResourceStatement(kind="database", source_location=loc(1, 1)),
        provider="aws",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-017"


def test_v018_invalid() -> None:
    validator = SemanticValidator()
    program = make_cloud_program(
        ResourceStatement(kind="storage", source_location=loc(1, 1)),
        ExpectationStatement(kind="unsupported", source_location=loc(2, 1)),
        provider="aws",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-018"


def test_v019_invalid() -> None:
    validator = SemanticValidator()
    program = make_cloud_program(
        ResourceStatement(kind="storage", source_location=loc(1, 1)),
        ExpectationStatement(kind="exists", source_location=loc(2, 1)),
        InspectionStatement(kind="status", source_location=loc(3, 1)),
        provider="aws",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-019"


def test_v020_invalid() -> None:
    validator = SemanticValidator()
    program = make_cloud_program(
        ResourceStatement(kind="storage", source_location=loc(1, 1)),
        ResourceStatement(kind="storage", source_location=loc(2, 1)),
        provider="aws",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(program)
    assert exc_info.value.rule_id == "V-020"


def test_v021_invalid() -> None:
    validator = SemanticValidator()
    expr = ComparisonExpression(
        left=IdentifierValue(name="public_acces", source_location=loc(3, 1)),
        operator="==",
        right=BooleanLiteral(value=True, source_location=loc(3, 20)),
        source_location=loc(3, 1),
    )
    target = TargetBlock(
        kind="cloud",
        body=(
            ResourceStatement(kind="storage", source_location=loc(1, 1)),
            InspectionStatement(kind="status", source_location=loc(2, 1)),
            WithStatement(expr, source_location=loc(3, 1)),
        ),
        source_location=loc(1, 1),
        provider="aws",
    )
    with pytest.raises(SemanticError) as exc_info:
        validator.validate(Program(targets=(target,), source_location=loc(1, 1)))
    assert exc_info.value.rule_id == "V-021"
