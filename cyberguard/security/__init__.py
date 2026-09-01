"""Security result models for CyberGuard."""

from .capability import (
    AuthenticationCapability,
    BasicAuthCapability,
    BasicAuthenticationCapability,
    HttpAssertionCapability,
    SecurityCapability,
)
from .context import SecurityContext
from .detection import (
    DetectionCapability,
    SqlDetectionCapability,
    SqlErrorDetectionCapability,
)
from .finding import SecurityFinding
from .injection import InjectionCapability, SQLInjectionCapability, SqlInjectionCapability
from .result import SecurityResult

__all__ = [
    "AuthenticationCapability",
    "BasicAuthCapability",
    "BasicAuthenticationCapability",
    "DetectionCapability",
    "HttpAssertionCapability",
    "InjectionCapability",
    "SecurityCapability",
    "SecurityContext",
    "SecurityFinding",
    "SecurityResult",
    "SQLInjectionCapability",
    "SqlDetectionCapability",
    "SqlErrorDetectionCapability",
    "SqlInjectionCapability",
]
