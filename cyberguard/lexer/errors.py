"""Lexer-specific errors for CyberGuard DSL."""

from __future__ import annotations


class LexerError(ValueError):
    """Raised when the source text cannot be tokenized."""

    def __init__(self, message: str, line: int, column: int, context: str | None = None) -> None:
        self.message = message
        self.line = line
        self.column = column
        self.context = context
        detail = f"{message} at line {line}, column {column}"
        if context:
            detail = f"{detail}\n{context}"
        super().__init__(detail)
