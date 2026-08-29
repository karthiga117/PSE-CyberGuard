"""Aggregated security results for CyberGuard."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .finding import SecurityFinding


@dataclass(frozen=True)
class SecurityResult:
    """Overall security evaluation produced for a target or test."""

    outcome: str = "unknown"
    findings: tuple[SecurityFinding, ...] = field(default_factory=tuple)

    def add_finding(self, finding: SecurityFinding) -> SecurityResult:
        """Return a new result with an additional finding."""
        return replace(self, findings=(*self.findings, finding))

    def sanitize(self) -> SecurityResult:
        """Return a redacted copy of the overall result."""
        return SecurityResult(
            outcome=self.outcome,
            findings=tuple(finding.sanitize() for finding in self.findings),
        )

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def total_findings(self) -> int:
        return len(self.findings)
