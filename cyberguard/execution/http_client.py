"""HTTP client abstractions for the CyberGuard execution engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from urllib import error as urllib_error
from urllib import request as urllib_request


@dataclass(frozen=True)
class HttpResponse:
    """Normalized HTTP response returned by the client."""

    status_code: int
    headers: dict[str, str]
    body: str
    url: str


class HttpClient(Protocol):
    """Network protocol for executing an HTTP request."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: float = 5.0,
    ) -> HttpResponse:
        """Execute an HTTP request and return a normalized response."""


class UrllibHttpClient:
    """Small built-in HTTP client used by the execution engine."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: float = 5.0,
    ) -> HttpResponse:
        request = urllib_request.Request(
            url,
            data=(body.encode("utf-8") if body is not None else None),
            headers=headers or {},
            method=method,
        )
        try:
            with urllib_request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
                return HttpResponse(
                    status_code=response.status,
                    headers=dict(response.headers.items()),
                    body=payload.decode("utf-8", errors="replace"),
                    url=response.geturl(),
                )
        except urllib_error.HTTPError as exc:
            payload = exc.read()
            return HttpResponse(
                status_code=exc.code,
                headers=dict(exc.headers.items()),
                body=payload.decode("utf-8", errors="replace"),
                url=exc.geturl(),
            )
        except urllib_error.URLError as exc:
            raise RuntimeError(f"HTTP execution error: {exc.reason}") from exc
