"""Shared constants and validation helpers for CyberGuard semantic checks."""

from __future__ import annotations

from difflib import get_close_matches
from urllib.parse import urlparse

SUPPORTED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
SUPPORTED_AUTH_METHODS = {"basic", "bearer", "api-key", "cookie"}
SUPPORTED_INJECTION_TYPES = {"sql"}
SUPPORTED_DETECTION_TYPES = {"sql-error"}
SUPPORTED_RESOURCE_TYPES = {"storage", "iam"}
SUPPORTED_INSPECTION_TYPES = {"storage", "iam", "header", "body", "status"}
SUPPORTED_EXPECTATION_KINDS = {
    "missing",
    "exists",
    "contains",
    "not-contains",
    "not-exists",
    "enabled",
    "disabled",
}
SUPPORTED_CLOUD_PROPERTIES = {
    "public_access",
    "encryption",
    "versioning",
    "logging",
    "mfa_enabled",
    "root_access_disabled",
    "public_accessible",
    "access_logging",
    "bucket_policy",
    "default_encryption",
    "network_acl",
    "iam_policy",
    "resource_policy",
    "firewall",
    "vpc",
    "subnet",
    "tags",
    "region",
    "ownership",
    "key_rotation",
    "certificate_validity",
}
COMMON_CLOUD_PROPERTY_SUGGESTIONS = {
    "public_acces": "public_access",
    "encrytion": "encryption",
    "mfa_enableds": "mfa_enabled",
    "root_access_disable": "root_access_disabled",
    "public_accessible": "public_access",
    "logging_enabled": "logging",
}


def is_blank(value: str | None) -> bool:
    """Return True when a value is missing or whitespace only."""
    return value is None or not str(value).strip()


def is_valid_url(value: str | None) -> bool:
    """Validate a web target URL without performing a network request."""
    if is_blank(value):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and not any(ch.isspace() for ch in value)
    )


def get_suggestion(value: str, valid_values: set[str]) -> str | None:
    """Return a near-match suggestion for a common typo."""
    normalized = str(value).strip()
    matches = get_close_matches(normalized.lower(), {item.lower() for item in valid_values}, n=1)
    if matches:
        return matches[0]
    return None


def validate_status_code(value: int | None) -> bool:
    """Return True for valid HTTP status codes in the v0.1 range."""
    return value is not None and 100 <= int(value) <= 599
