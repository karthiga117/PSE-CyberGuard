"""Safe detection capability boundary for CyberGuard.

The DSL and semantic validator recognize `detect: sql-error`, but the current
project does not define the response-analysis rules needed to make a concrete
SQL-error detection decision. This capability therefore accepts the validated AST
node and keeps the result non-conclusive instead of inventing unsupported regex,
status semantics, or vulnerability findings.
"""

from __future__ import annotations

from cyberguard.parser.ast import DetectionStatement

from .context import SecurityContext
from .result import SecurityResult


class SqlErrorDetectionCapability:
    """Recognize a defined detection intent without inventing unsupported rules."""

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        """Return an inconclusive result unless a concrete detection rule is defined."""
        if not isinstance(validated_ast_node, DetectionStatement):
            return SecurityResult(outcome="inconclusive", findings=())

        if getattr(validated_ast_node, "kind", None) != "sql-error":
            return SecurityResult(outcome="inconclusive", findings=())

        if context.response is None:
            return SecurityResult(outcome="inconclusive", findings=())

        # The current design defines the AST and validation surface for
        # `detect: sql-error`, but it does not define the exact response fields,
        # pass/fail semantics, or evidence model for a real SQL-error detection.
        # Therefore, the safe boundary is to keep the capability non-conclusive
        # and to avoid fabricating findings or vulnerability conclusions.
        return SecurityResult(outcome="inconclusive", findings=())


SqlDetectionCapability = SqlErrorDetectionCapability
DetectionCapability = SqlErrorDetectionCapability
