"""Security finding model for CyberGuard secure-analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_SENSITIVE_KEYS = (
    "authorization",
    "auth",
    "token",
    "secret",
    "password",
    "cookie",
    "api_key",
    "apikey",
)


def _redact_sensitive(value: Any) -> Any:
    """Return a minimally redacted copy of structured security evidence."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and any(
                sensitive in key.lower() for sensitive in _SENSITIVE_KEYS
            ):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive(item)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item) for item in value)

    if isinstance(value, str):
        lowered = value.lower()
        if any(sensitive in lowered for sensitive in _SENSITIVE_KEYS):
            return "[REDACTED]"
        if "authorization:" in lowered or "bearer " in lowered:
            return "[REDACTED]"
        return value

    return value


@dataclass(frozen=True)
class SecurityFinding:
    """A single security-relevant observation produced during analysis."""

    capability: str
    target: str
    test: str
    evidence: Any
    outcome: str
    rule: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    expected: Any = None
    actual: Any = None
    remediation: str | None = None

    def sanitize(self) -> SecurityFinding:
        """Return a copy of this finding with sensitive values redacted."""
        return SecurityFinding(
            capability=self.capability,
            target=self.target,
            test=self.test,
            evidence=_redact_sensitive(self.evidence),
            outcome=self.outcome,
            rule=self.rule,
            severity=self.severity,
            title=self.title,
            description=self.description,
            expected=_redact_sensitive(self.expected),
            actual=_redact_sensitive(self.actual),
            remediation=self.remediation,
        )
