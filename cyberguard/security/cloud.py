"""Safe cloud security capability boundary for CyberGuard.

The project recognizes cloud target and property syntax, but it does not define
provider runtime integration, credential sources, resource discovery semantics, or
cloud evidence models. This capability therefore accepts the validated AST shape
without inventing a provider SDK, cloud credentials, or vulnerability findings.
"""

from __future__ import annotations

from cyberguard.parser.ast import (
    ComparisonExpression,
    InspectionStatement,
    ResourceStatement,
    TargetBlock,
)

from .context import SecurityContext
from .result import SecurityResult


class CloudSecurityCapability:
    """Return an inconclusive result for cloud checks until provider semantics exist."""

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        """Keep cloud checks non-conclusive when runtime provider behavior is undefined."""
        if context is None:
            return SecurityResult(outcome="inconclusive", findings=())

        if isinstance(
            validated_ast_node,
            (TargetBlock, ResourceStatement, InspectionStatement, ComparisonExpression),
        ):
            return SecurityResult(outcome="inconclusive", findings=())

        return SecurityResult(outcome="inconclusive", findings=())


CloudCapability = CloudSecurityCapability
CloudInspectionCapability = CloudSecurityCapability
