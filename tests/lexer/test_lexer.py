"""Lexer tests for the CyberGuard DSL v0.1."""

import pytest

from cyberguard.lexer import Lexer, LexerError, Token, TokenType


class TestLexerBasics:
    """Test basic lexer functionality."""

    def test_empty_source(self):
        """Tokenize empty source."""
        lexer = Lexer("")
        tokens = lexer.tokenize()
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_single_keyword(self):
        """Tokenize a single keyword."""
        lexer = Lexer("target")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.KEYWORD
        assert tokens[0].value == "target"

    def test_single_identifier(self):
        """Tokenize a single identifier."""
        lexer = Lexer("myvar")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "myvar"

    def test_single_integer(self):
        """Tokenize a single integer."""
        lexer = Lexer("42")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.INTEGER
        assert tokens[0].value == "42"

    def test_single_string_double_quotes(self):
        """Tokenize a string with double quotes."""
        lexer = Lexer('"hello"')
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "hello"

    def test_single_string_single_quotes(self):
        """Tokenize a string with single quotes."""
        lexer = Lexer("'hello'")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "hello"

    def test_colon_operator(self):
        """Tokenize a colon as punctuation/operator."""
        lexer = Lexer(":")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.OPERATOR
        assert tokens[0].value == ":"

    def test_equals_operator(self):
        """Standalone equals is not valid in the frozen v0.1 DSL."""
        lexer = Lexer("=")
        with pytest.raises(LexerError):
            lexer.tokenize()

    def test_double_equals_operator(self):
        """Tokenize a double equals."""
        lexer = Lexer("==")
        tokens = lexer.tokenize()
        found = False
        for token in tokens:
            if token.type == TokenType.OPERATOR and token.value == "==":
                found = True
                break
        assert found

    def test_not_equals_operator(self):
        """Tokenize a not-equals operator."""
        lexer = Lexer("!=")
        tokens = lexer.tokenize()
        found = False
        for token in tokens:
            if token.type == TokenType.OPERATOR and token.value == "!=":
                found = True
                break
        assert found


class TestLexerKeywords:
    """Test lexer keyword recognition."""

    def test_all_keywords(self):
        """Test that all v0.1 keywords are recognized."""
        keywords = {
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
        for kw in keywords:
            lexer = Lexer(kw)
            tokens = lexer.tokenize()
            keyword_tokens = [t for t in tokens if t.type == TokenType.KEYWORD and t.value == kw]
            assert len(keyword_tokens) >= 1, f"Keyword {kw} not recognized"

    def test_identifier_with_underscore(self):
        """Identifier with underscores."""
        lexer = Lexer("my_var")
        tokens = lexer.tokenize()
        identifier_tokens = [t for t in tokens if t.type == TokenType.IDENTIFIER]
        assert len(identifier_tokens) >= 1
        assert identifier_tokens[0].value == "my_var"

    def test_identifier_with_hyphen(self):
        """Generic hyphenated identifiers are invalid in the frozen v0.1 DSL."""
        lexer = Lexer("my-var")
        with pytest.raises(LexerError):
            lexer.tokenize()


class TestLexerStrings:
    """Test string tokenization."""

    def test_empty_string(self):
        """Tokenize an empty string."""
        lexer = Lexer('""')
        tokens = lexer.tokenize()
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) >= 1
        assert string_tokens[0].value == ""

    def test_string_with_spaces(self):
        """String with spaces."""
        lexer = Lexer('"hello world"')
        tokens = lexer.tokenize()
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) >= 1
        assert string_tokens[0].value == "hello world"

    def test_string_with_escaped_quote(self):
        """Backslash-escaped quotes are not supported by the frozen v0.1 lexer."""
        lexer = Lexer(r'"hello\"world"')
        with pytest.raises(LexerError):
            lexer.tokenize()

    def test_unterminated_string(self):
        """Unterminated string raises error."""
        lexer = Lexer('"hello')
        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()
        assert "Unterminated string" in str(exc_info.value)


class TestLexerIntegers:
    """Test integer tokenization."""

    def test_zero(self):
        """Tokenize zero."""
        lexer = Lexer("0")
        tokens = lexer.tokenize()
        int_tokens = [t for t in tokens if t.type == TokenType.INTEGER]
        assert len(int_tokens) >= 1
        assert int_tokens[0].value == "0"

    def test_multidigit_integer(self):
        """Tokenize multidigit integer."""
        lexer = Lexer("12345")
        tokens = lexer.tokenize()
        int_tokens = [t for t in tokens if t.type == TokenType.INTEGER]
        assert len(int_tokens) >= 1
        assert int_tokens[0].value == "12345"


class TestLexerIndentation:
    """Test indentation tracking."""

    def test_single_indent(self):
        """Single level of indentation."""
        source = "target: web\n    test: request"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        token_types = [t.type for t in tokens]
        assert TokenType.INDENT in token_types
        assert TokenType.DEDENT in token_types
        assert token_types[-1] == TokenType.EOF

    def test_single_dedent(self):
        """Single level of dedentation."""
        source = "    test: request\nend"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        dedent_tokens = [t for t in tokens if t.type == TokenType.DEDENT]
        assert len(dedent_tokens) >= 1

    def test_multiple_indentation_levels(self):
        """Multiple levels of indentation."""
        source = "target: web\n    test: request\n        authenticate: basic"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        # Should successfully tokenize without errors
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        assert len(keywords) >= 3


class TestLexerComments:
    """Test comment handling."""

    def test_comment_does_not_cause_infinite_loop(self):
        """Comments between lines do not block tokenization."""
        source = "# comment\n\n# another comment\n\ntarget: web"

        lexer = Lexer(source)
        tokens = lexer.tokenize()

        assert any(
            t.type == TokenType.KEYWORD and t.value == "target"
            for t in tokens
        )

    def test_full_line_comment(self):
        """Full-line comment."""
        source = "# this is a comment\ntarget: web"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        keyword_tokens = [t for t in tokens if t.type == TokenType.KEYWORD and t.value == "target"]
        assert len(keyword_tokens) >= 1

    def test_blank_lines(self):
        """Blank lines are handled."""
        source = "target: web\n\ntest: request"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        # Should have target, colon, web, test, colon, request tokens plus newlines
        assert len(tokens) > 0


class TestLexerLineNumbers:
    """Test line and column tracking."""

    def test_first_token_location(self):
        """First token has correct line and column."""
        lexer = Lexer("target")
        tokens = lexer.tokenize()
        first_token = tokens[0]
        assert first_token.line == 1
        assert first_token.column == 1

    def test_multiline_location(self):
        """Tokens on later lines have correct line numbers."""
        source = "target: web\ntest: request"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        test_tokens = [t for t in tokens if t.value == "test"]
        assert len(test_tokens) >= 1
        assert test_tokens[0].line == 2

    def test_column_tracking(self):
        """Columns are tracked correctly."""
        lexer = Lexer("target web")
        tokens = lexer.tokenize()
        keyword_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        assert len(keyword_tokens) >= 2
        # "web" should come after "target", so its column should be higher
        web_token = next((t for t in keyword_tokens if t.value == "web"), None)
        assert web_token is not None
        assert web_token.column > 1


class TestLexerRealExamples:
    """Test realistic CyberGuard DSL examples."""

    def test_simple_target(self):
        """Simple target block."""
        source = """target: web
    test: request
        authenticate: basic
        with: username == "admin"
"""
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        assert len(keywords) > 0
        keyword_values = {t.value for t in keywords}
        assert "target" in keyword_values
        assert "test" in keyword_values
        assert "authenticate" in keyword_values

    def test_cloud_resource_example(self):
        """Cloud resource inspection."""
        source = """target: cloud
    resource: storage
        inspect: iam
            expect: enabled
"""
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        keyword_values = {t.value for t in keywords}
        assert "target" in keyword_values
        assert "cloud" in keyword_values
        assert "resource" in keyword_values
        assert "inspect" in keyword_values

    def test_detection_example(self):
        """Injection detection example."""
        source = """target: web
    test: request
        inject: sql
        detect: sql-error
            expect: missing
"""
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        keyword_values = {t.value for t in keywords}
        assert "inject" in keyword_values
        assert "detect" in keyword_values
        assert "sql-error" in keyword_values


class TestLexerErrors:
    """Test error handling."""

    def test_unsupported_character_bracket(self):
        """Unsupported character bracket raises error."""
        lexer = Lexer("[")
        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()
        assert "Unexpected character" in str(exc_info.value) or "Unsupported" in str(exc_info.value)

    def test_unsupported_character_pipe(self):
        """Unsupported character pipe raises error."""
        lexer = Lexer("|")
        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()
        assert "Unexpected character" in str(exc_info.value) or "Unsupported" in str(exc_info.value)

    def test_lexer_error_has_context(self):
        """LexerError includes line, column, and context."""
        lexer = Lexer("target: web\n[invalid")
        try:
            lexer.tokenize()
            assert False, "Should have raised LexerError"
        except LexerError as e:
            assert e.line > 0
            assert e.column > 0
            assert e.context is not None


class TestLexerTokenDataclass:
    """Test Token dataclass."""

    def test_token_string_representation(self):
        """Token has reasonable string representation."""
        token = Token(TokenType.KEYWORD, "target", 1, 1)
        token_str = str(token)
        assert "target" in token_str
        assert "KEYWORD" in token_str

    def test_token_is_frozen(self):
        """Token is immutable (frozen dataclass)."""
        token = Token(TokenType.KEYWORD, "target", 1, 1)
        with pytest.raises((AttributeError, Exception)):
            token.value = "changed"


class TestLexerEdgeCases:
    """Test edge cases."""

    def test_carriage_return_line_feed(self):
        """Handle CRLF line endings."""
        source = "target: web\r\ntest: request"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        assert len(keywords) >= 2

    def test_carriage_return_only(self):
        """Handle CR-only line endings."""
        source = "target: web\rtest: request"
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        assert len(keywords) >= 2

    def test_string_with_newline_escape(self):
        """Backslash-n remains literal in the frozen v0.1 lexer; it is not an escape sequence."""
        lexer = Lexer(r'"hello\nworld"')
        tokens = lexer.tokenize()
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) >= 1
        assert string_tokens[0].value == "hello\\nworld"

    def test_multiple_spaces_between_tokens(self):
        """Multiple spaces between tokens are handled."""
        lexer = Lexer("target    :    web")
        tokens = lexer.tokenize()
        keywords = [t for t in tokens if t.type == TokenType.KEYWORD]
        assert len(keywords) >= 2

    def test_trailing_whitespace(self):
        """Trailing whitespace is ignored."""
        lexer = Lexer("target: web   \n")
        tokens = lexer.tokenize()
        keywords = [
            t
            for t in tokens
            if t.type == TokenType.KEYWORD
            and t.value in ("target", "web")
        ]
        assert len(keywords) >= 2

    def test_invalid_three_space_indentation(self):
        """Three-space indentation is invalid in the frozen v0.1 DSL."""
        source = "target: web\n   test: request"
        lexer = Lexer(source)

        with pytest.raises(LexerError):
            lexer.tokenize()

    def test_invalid_five_space_indentation(self):
        """Five-space indentation is invalid in the frozen v0.1 DSL."""
        source = "target: web\n     test: request"
        lexer = Lexer(source)

        with pytest.raises(LexerError):
            lexer.tokenize()

    def test_tab_indentation_is_rejected(self):
        """Tabs are not allowed for indentation."""
        source = "target: web\n\ttest: request"
        lexer = Lexer(source)

        with pytest.raises(LexerError):
            lexer.tokenize()

    def test_tokenize_can_be_called_multiple_times(self):
        """Lexer state resets deterministically between tokenize() calls."""
        source = "target: web"

        lexer = Lexer(source)

        first = lexer.tokenize()
        second = lexer.tokenize()

        assert first == second
