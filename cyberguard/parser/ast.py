"""AST nodes for the CyberGuard DSL v0.1."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceLocation:
    """Source location information for an AST node."""

    line: int
    column: int


# Value nodes


@dataclass(frozen=True)
class StringLiteral:
    """A string literal value."""

    value: str
    source_location: SourceLocation


@dataclass(frozen=True)
class IntegerLiteral:
    """An integer literal value."""

    value: int
    source_location: SourceLocation


@dataclass(frozen=True)
class BooleanLiteral:
    """A boolean literal value (true/false)."""

    value: bool
    source_location: SourceLocation


@dataclass(frozen=True)
class IdentifierValue:
    """An identifier value."""

    name: str
    source_location: SourceLocation


# Expression nodes


@dataclass(frozen=True)
class ComparisonExpression:
    """A binary comparison expression (left operator right)."""

    left: IdentifierValue
    operator: str  # == or !=
    right: StringLiteral | IntegerLiteral | BooleanLiteral | IdentifierValue
    source_location: SourceLocation


# Statement nodes


@dataclass(frozen=True)
class RequestStatement:
    """A request statement specifying HTTP method."""

    method: str  # GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
    source_location: SourceLocation


@dataclass(frozen=True)
class AuthenticationStatement:
    """An authentication statement."""

    method: str  # basic, bearer, api-key, cookie
    source_location: SourceLocation


@dataclass(frozen=True)
class WithStatement:
    """A with statement containing a comparison expression."""

    expression: ComparisonExpression
    source_location: SourceLocation


@dataclass(frozen=True)
class InjectionStatement:
    """An injection statement."""

    kind: str  # sql
    source_location: SourceLocation


@dataclass(frozen=True)
class DetectionStatement:
    """A detection statement."""

    kind: str  # sql-error
    source_location: SourceLocation


@dataclass(frozen=True)
class ExpectationStatement:
    """An expectation statement."""

    kind: str  # missing, exists, contains, not-contains, not-exists, enabled, disabled
    source_location: SourceLocation


@dataclass(frozen=True)
class ResourceStatement:
    """A resource statement for cloud targets."""

    kind: str  # storage, iam
    source_location: SourceLocation


@dataclass(frozen=True)
class InspectionStatement:
    """An inspection statement for cloud targets."""

    kind: str  # storage, iam, header, body, status
    source_location: SourceLocation


# Block nodes


@dataclass(frozen=True)
class TestBlock:
    """A test block containing test-related statements."""

    kind: str  # request
    body: tuple[
        RequestStatement
        | AuthenticationStatement
        | WithStatement
        | InjectionStatement
        | DetectionStatement
        | ExpectationStatement,
        ...,
    ]
    source_location: SourceLocation

    __test__ = False


@dataclass(frozen=True)
class TargetBlock:
    """A target block (web or cloud)."""

    kind: str  # web or cloud
    body: tuple[TestBlock | ResourceStatement | InspectionStatement, ...]
    source_location: SourceLocation


@dataclass(frozen=True)
class Program:
    """The root AST node representing an entire CyberGuard program."""

    targets: tuple[TargetBlock, ...]
    source_location: SourceLocation
