"""Token definitions for the CyberGuard DSL v0.1."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TokenType(str, Enum):
    """Strongly typed token categories for the CyberGuard DSL."""

    KEYWORD = "KEYWORD"
    IDENTIFIER = "IDENTIFIER"
    STRING = "STRING"
    INTEGER = "INTEGER"
    OPERATOR = "OPERATOR"
    NEWLINE = "NEWLINE"
    INDENT = "INDENT"
    DEDENT = "DEDENT"
    EOF = "EOF"

    @classmethod
    def keyword_values(cls) -> set[str]:
        """Return the full set of v0.1 CyberGuard keywords."""
        return {
            "target",
            "web",
            "cloud",
            "test",
            "request",
            "authenticate",
            "with",
            "basic",
            "bearer",
            "api-key",
            "cookie",
            "inject",
            "sql",
            "detect",
            "sql-error",
            "expect",
            "inspect",
            "resource",
            "storage",
            "iam",
            "true",
            "false",
            "enabled",
            "disabled",
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
            "contains",
            "not-contains",
            "missing",
            "exists",
            "not-exists",
            "header",
            "body",
            "status",
        }


@dataclass(frozen=True)
class Token:
    """A single lexical token in a CyberGuard source stream."""

    type: TokenType
    value: str
    line: int
    column: int

    def __str__(self) -> str:
        return (
            f"Token(type={self.type.value}, value={self.value!r}, "
            f"line={self.line}, column={self.column})"
        )


KEYWORDS = TokenType.keyword_values()
KEYWORD_MAP = {word: TokenType.KEYWORD for word in KEYWORDS}


def is_keyword(value: str) -> bool:
    """Return True when a word matches a CyberGuard keyword."""
    return value in KEYWORDS
