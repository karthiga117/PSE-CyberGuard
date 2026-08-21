"""
CyberGuard - A cybersecurity domain-specific language (DSL) for security engineers and developers.

CyberGuard enables security engineers to express security intent in a simple, declarative DSL
and execute security specifications from the command line.

Supported domains:
- PenTesting & Application Security (AppSec)
- Cloud Security
"""

__version__ = "0.1.0"
__author__ = "CyberGuard Contributors"
__license__ = "MIT"

from .semantic import SemanticError, SemanticValidator

__all__ = ["__version__", "SemanticError", "SemanticValidator"]
