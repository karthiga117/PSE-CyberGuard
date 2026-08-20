"""Parser-specific errors for the CyberGuard DSL."""

from __future__ import annotations


class ParserError(ValueError):
    """Raised when the token stream cannot be parsed."""

    def __init__(
        self,
        message: str,
        line: int,
        column: int,
        context: str | None = None,
    ) -> None:
        self.message = message
        self.line = line
        self.column = column
        self.context = context
        detail = f"{message} at line {line}, column {column}"
        if context:
            detail = f"{detail}\n{context}"
        super().__init__(detail)
