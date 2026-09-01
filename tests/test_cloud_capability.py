"""Tests for the non-conclusive cloud security capability boundary."""

from __future__ import annotations

from cyberguard.parser.ast import (
    BooleanLiteral,
    ComparisonExpression,
    IdentifierValue,
    InspectionStatement,
    ResourceStatement,
    SourceLocation,
    TargetBlock,
)
from cyberguard.security import CloudCapability, CloudSecurityCapability, SecurityContext


def loc(line: int, column: int) -> SourceLocation:
    return SourceLocation(line=line, column=column)


def test_cloud_capability_accepts_cloud_target_but_remains_inconclusive() -> None:
    target = TargetBlock(
        kind="cloud",
        body=(
            ResourceStatement(kind="storage", source_location=loc(1, 1)),
            InspectionStatement(kind="storage", source_location=loc(2, 1)),
        ),
        source_location=loc(1, 1),
        provider="aws",
    )

    capability = CloudSecurityCapability()
    result = capability.evaluate(
        target,
        SecurityContext(target="cloud://example", capability="cloud"),
    )

    assert result.outcome == "inconclusive"
    assert result.findings == ()
    assert CloudCapability is CloudSecurityCapability


def test_cloud_capability_handles_cloud_property_comparison_without_fabricating_results() -> None:
    comparison = ComparisonExpression(
        left=IdentifierValue(name="public_access", source_location=loc(1, 1)),
        operator="==",
        right=BooleanLiteral(value=False, source_location=loc(1, 14)),
        source_location=loc(1, 1),
    )

    capability = CloudSecurityCapability()
    result = capability.evaluate(
        comparison,
        SecurityContext(
            target="cloud://example",
            test="public_access == false",
            capability="cloud",
        ),
    )

    assert result.outcome == "inconclusive"
    assert result.findings == ()
