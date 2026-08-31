"""Safe SQL injection capability boundary for CyberGuard.

The current repository recognizes the `inject: sql` DSL construct via
`InjectionStatement(kind="sql")`, but it does not define any payload source,
injection location, mutation semantics, or SQL-error detection rules. This
capability therefore validates the supported AST node and intentionally keeps
behavior non-executing and non-vulnerable by default.
"""

from __future__ import annotations

from cyberguard.execution.result import HttpRequestSpec
from cyberguard.parser.ast import InjectionStatement

from .context import SecurityContext
from .result import SecurityResult


class SqlInjectionCapability:
    """Recognize SQL injection intent without inventing unsupported runtime semantics."""

    def prepare_request(
        self,
        request: HttpRequestSpec,
        payload: object | None = None,
    ) -> HttpRequestSpec | None:
        """Return an immutable copy of the request when mutation semantics are absent."""
        if request is None:
            return None
        return HttpRequestSpec(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            body=request.body,
        )

    def evaluate(self, validated_ast_node: object, context: SecurityContext) -> SecurityResult:
        """Return an inconclusive result unless the runtime contract is actually defined."""
        if not isinstance(validated_ast_node, InjectionStatement):
            return SecurityResult(outcome="inconclusive", findings=())

        if getattr(validated_ast_node, "kind", None) != "sql":
            return SecurityResult(outcome="inconclusive", findings=())

        if context.original_request is None:
            return SecurityResult(outcome="inconclusive", findings=())

        return SecurityResult(outcome="inconclusive", findings=())


SQLInjectionCapability = SqlInjectionCapability
InjectionCapability = SqlInjectionCapability
