"""Manual lexer for the CyberGuard DSL v0.1."""

from __future__ import annotations

from .errors import LexerError
from .tokens import KEYWORD_MAP, Token, TokenType


class Lexer:
    """Tokenize CyberGuard DSL source text into a stream of lexer tokens."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.index = 0

    def tokenize(self) -> list[Token]:
        """Return the sequence of tokens for this source string."""
        self.index = 0
        tokens: list[Token] = []
        indent_stack = [0]
        line_number = 1

        while self.index < len(self.source):
            line_start = self.index
            line_end = self._line_end_index()
            raw_line = self.source[line_start:line_end]
            if raw_line.endswith("\r"):
                raw_line = raw_line[:-1]

            line_content = raw_line
            leading_spaces = len(line_content) - len(line_content.lstrip(" "))
            stripped = line_content.strip()

            if not stripped or stripped.startswith("#"):
                self.index = line_end
                if self.index < len(self.source) and self.source[self.index] == "\n":
                    self.index += 1
                elif self.index < len(self.source) and self.source[self.index] == "\r":
                    self.index += 1
                    if self.index < len(self.source) and self.source[self.index] == "\n":
                        self.index += 1
                line_number += 1
                continue

            if "\t" in line_content[:leading_spaces]:
                raise LexerError("Tabs are not allowed for indentation", line_number, 1, raw_line)
            if leading_spaces % 4 != 0:
                raise LexerError("Invalid indentation width", line_number, 1, raw_line)

            if leading_spaces > indent_stack[-1]:
                if leading_spaces != indent_stack[-1] + 4:
                    raise LexerError("Inconsistent indentation", line_number, 1, raw_line)
                indent_stack.append(leading_spaces)
                tokens.append(Token(TokenType.INDENT, " " * leading_spaces, line_number, 1))
            elif leading_spaces < indent_stack[-1]:
                while indent_stack and indent_stack[-1] > leading_spaces:
                    indent_stack.pop()
                    tokens.append(Token(TokenType.DEDENT, "DEDENT", line_number, 1))
                if indent_stack[-1] != leading_spaces:
                    raise LexerError("Inconsistent indentation", line_number, 1, raw_line)

            content = line_content[leading_spaces:]
            line_tokens = self._tokenize_line(
                content,
                line_number,
                leading_spaces + 1,
            )
            tokens.extend(line_tokens)
            tokens.append(
                Token(
                    TokenType.NEWLINE,
                    "\n",
                    line_number,
                    len(content) + leading_spaces + 1,
                )
            )

            self.index = line_end
            if self.index < len(self.source) and self.source[self.index] == "\n":
                self.index += 1
            elif self.index < len(self.source) and self.source[self.index] == "\r":
                self.index += 1
                if self.index < len(self.source) and self.source[self.index] == "\n":
                    self.index += 1
            line_number += 1

        while len(indent_stack) > 1:
            indent_stack.pop()
            tokens.append(Token(TokenType.DEDENT, "DEDENT", line_number, 1))

        tokens.append(Token(TokenType.EOF, "EOF", line_number, 1))
        return tokens

    def _line_end_index(self) -> int:
        idx = self.index
        while idx < len(self.source):
            ch = self.source[idx]
            if ch == "\n":
                return idx
            if ch == "\r":
                next_idx = idx + 1
                if next_idx < len(self.source) and self.source[next_idx] == "\n":
                    return next_idx
                return idx
            idx += 1
        return len(self.source)

    def _tokenize_line(self, text: str, line_number: int, start_column: int) -> list[Token]:
        tokens: list[Token] = []
        index = 0
        while index < len(text):
            ch = text[index]
            if ch == "\t":
                raise LexerError("Tabs are not allowed", line_number, start_column + index, text)
            if ch.isspace():
                index += 1
                continue
            if ch == "#":
                raise LexerError(
                    "Unexpected character '#'",
                    line_number,
                    start_column + index,
                    text,
                )
            if ch in ('"', "'"):
                token, index = self._read_string(text, index, line_number, start_column)
                tokens.append(token)
                continue
            if ch.isdigit():
                start = index
                while index < len(text) and text[index].isdigit():
                    index += 1
                if index < len(text) and (text[index].isalpha() or text[index] == "_"):
                    raise LexerError(
                        f"Invalid integer literal {text[start:index + 1]!r}",
                        line_number,
                        start_column + start,
                        text,
                    )
                tokens.append(
                    Token(
                        TokenType.INTEGER,
                        text[start:index],
                        line_number,
                        start_column + start,
                    )
                )
                continue
            if ch.isalpha() or ch == "_":
                start = index
                while index < len(text) and (text[index].isalnum() or text[index] == "_"):
                    index += 1
                word = text[start:index]
                if index < len(text) and text[index] == "-":
                    parts = [word]
                    while index < len(text) and text[index] == "-":
                        index += 1
                        if index >= len(text) or not (
                            text[index].isalpha() or text[index] == "_"
                        ):
                            raise LexerError(
                                f"Invalid identifier {'-'.join(parts)!r}",
                                line_number,
                                start_column + start,
                                text,
                            )
                        part_start = index
                        while index < len(text) and (
                            text[index].isalnum() or text[index] == "_"
                        ):
                            index += 1
                        parts.append(text[part_start:index])
                    candidate = "-".join(parts)
                    if candidate in KEYWORD_MAP:
                        tokens.append(
                            Token(TokenType.KEYWORD, candidate, line_number, start_column + start)
                        )
                        continue
                    raise LexerError(
                        f"Invalid identifier {candidate!r}",
                        line_number,
                        start_column + start,
                        text,
                    )
                if word in KEYWORD_MAP:
                    tokens.append(
                        Token(TokenType.KEYWORD, word, line_number, start_column + start)
                    )
                else:
                    tokens.append(
                        Token(TokenType.IDENTIFIER, word, line_number, start_column + start)
                    )
                continue
            if text.startswith("==", index):
                tokens.append(Token(TokenType.OPERATOR, "==", line_number, start_column + index))
                index += 2
                continue
            if text.startswith("!=", index):
                tokens.append(Token(TokenType.OPERATOR, "!=", line_number, start_column + index))
                index += 2
                continue
            if ch == "=":
                raise LexerError(
                    "Standalone '=' is not supported in CyberGuard v0.1",
                    line_number,
                    start_column + index,
                    text,
                )
            if ch == ":":
                tokens.append(Token(TokenType.OPERATOR, ":", line_number, start_column + index))
                index += 1
                continue
            raise LexerError(
                f"Unexpected character {ch!r}",
                line_number,
                start_column + index,
                text,
            )
        return tokens

    def _read_string(
        self,
        text: str,
        index: int,
        line_number: int,
        start_column: int,
    ) -> tuple[Token, int]:
        quote = text[index]
        value_chars: list[str] = []
        idx = index + 1
        while idx < len(text):
            ch = text[idx]
            if ch == quote:
                return (
                    Token(
                        TokenType.STRING,
                        "".join(value_chars),
                        line_number,
                        start_column + index,
                    ),
                    idx + 1,
                )
            if ch in {"\n", "\r"}:
                raise LexerError(
                    "Unterminated string literal",
                    line_number,
                    start_column + index,
                    text,
                )
            value_chars.append(ch)
            idx += 1
        raise LexerError(
            "Unterminated string literal",
            line_number,
            start_column + index,
            text,
        )
