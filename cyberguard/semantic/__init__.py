"""Semantic validation package for CyberGuard programs."""

from .errors import SemanticError
from .validator import SemanticValidator

__all__ = ["SemanticError", "SemanticValidator"]
