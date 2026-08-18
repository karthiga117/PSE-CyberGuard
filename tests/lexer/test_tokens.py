"""Tests for CyberGuard token definitions."""

from cyberguard.lexer.tokens import TokenType


def test_token_type_count_and_names() -> None:
    """Smoke test for the centralized token definitions."""
    assert TokenType.KEYWORD.value == "KEYWORD"
    assert TokenType.IDENTIFIER.value == "IDENTIFIER"
    assert TokenType.STRING.value == "STRING"
    assert TokenType.INTEGER.value == "INTEGER"
    assert TokenType.OPERATOR.value == "OPERATOR"
    assert TokenType.NEWLINE.value == "NEWLINE"
    assert TokenType.INDENT.value == "INDENT"
    assert TokenType.DEDENT.value == "DEDENT"
    assert TokenType.EOF.value == "EOF"


def test_keyword_set_contains_expected_words() -> None:
    """The finalized v0.1 design keyword set should be explicit and stable."""
    expected = {
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
    assert expected.issubset(TokenType.keyword_values())
