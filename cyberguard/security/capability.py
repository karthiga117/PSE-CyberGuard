"""Minimal security capability contract for CyberGuard."""

from __future__ import annotations

from typing import Protocol

from .context import SecurityContext
from .result import SecurityResult


class SecurityCapability(Protocol):
    def evaluate(
        self,
        validated_ast_node: object,
        context: SecurityContext
    ) -> SecurityResult:
        ...
