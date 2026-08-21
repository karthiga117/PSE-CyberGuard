"""Semantic validation errors for CyberGuard programs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticError(ValueError):
    """Raised when a CyberGuard AST violates a semantic rule."""

    rule_id: str
    message: str
    line: int
    column: int
    suggestion: str | None = None

    def __str__(self) -> str:
        lines = [
            f"CyberGuard Semantic Error [{self.rule_id}]",
            f"Line {self.line}, Column {self.column}:",
            self.message,
        ]
        if self.suggestion:
            lines.append("")
            lines.append("Suggestion:")
            lines.append(self.suggestion)
        return "\n".join(lines)
