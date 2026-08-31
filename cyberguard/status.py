"""Shared, neutral status comparison helpers for CyberGuard."""

from __future__ import annotations


def compare_status(actual: int, expected: int, operator: str) -> bool:
    """Compare an HTTP status code using the project's supported operators."""
    if operator == "==":
        return actual == expected
    if operator == "!=":
        return actual != expected
    return False
