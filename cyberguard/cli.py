"""CyberGuard CLI - Command-line interface for the cybersecurity DSL."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Optional

import typer

from cyberguard import __version__
from cyberguard.execution.engine import ExecutionEngine
from cyberguard.execution.http_client import UrllibHttpClient
from cyberguard.lexer.lexer import Lexer
from cyberguard.parser import Parser
from cyberguard.semantic import SemanticValidator

app = typer.Typer(
    name="cyberguard",
    help=(
        "CyberGuard - A cybersecurity domain-specific language "
        "for PenTesting, AppSec, and Cloud Security."
    ),
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"CyberGuard {__version__}")
        raise typer.Exit()


def _format_result(result: object) -> None:
    """Print a compact, human-readable result summary for a completed execution."""
    status = getattr(result, "status", None)
    target_url = getattr(result, "target_url", None)
    test_name = getattr(result, "test_name", None)
    request = getattr(result, "request", None)
    response = getattr(result, "response", None)
    message = getattr(result, "message", "")
    error = getattr(result, "error", None)
    expected = getattr(result, "expected", None)
    actual = getattr(result, "actual", None)

    typer.echo(f"Status: {status.value if hasattr(status, 'value') else status}")
    typer.echo(f"Target: {target_url}")
    typer.echo(f"Test: {test_name}")
    if request is not None:
        typer.echo(f"Request: {request.method} {request.url}")
    if response is not None:
        typer.echo(f"Response: {response.status_code}")
    if message:
        typer.echo(f"Message: {message}")
    if error:
        typer.echo(f"Error: {error}")
    if expected is not None and actual is not None:
        typer.echo(f"Expected: {expected}")
        typer.echo(f"Actual: {actual}")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        help="Show version and exit.",
        is_eager=True,
    ),
) -> None:
    """
    CyberGuard - A cybersecurity domain-specific language (DSL).

    Use 'cyberguard COMMAND --help' for more information on a command.
    """
    if ctx.invoked_subcommand is None and version is None:
        typer.echo(ctx.get_help())


@app.command()
def run(
    file: str = typer.Argument(..., help="Path to the CyberGuard DSL file (.cg)"),
    url: str = typer.Option(
        "http://localhost",
        "--url",
        help="Target URL to use for web requests when the DSL does not supply one.",
    ),
) -> None:
    """Execute a CyberGuard DSL file using the existing parser, validator, and engine."""
    typer.echo(f"[*] CyberGuard: Executing file '{file}'")

    file_path = Path(file)
    if not file_path.exists():
        typer.echo(f"[!] File not found: '{file}'")
        raise typer.Exit(code=0)

    try:
        source = file_path.read_text(encoding="utf-8")
        program = Parser(Lexer(source).tokenize()).parse()
    except Exception as exc:  # pragma: no cover - exercised via CLI errors
        typer.echo("✗ Parse failed")
        typer.echo(f"  {exc}")
        raise typer.Exit(code=1) from exc

    try:
        SemanticValidator().validate(program)
    except Exception as exc:  # pragma: no cover - exercised via CLI errors
        typer.echo("✗ Semantic validation failed")
        typer.echo(f"  {exc}")
        raise typer.Exit(code=1) from exc

    try:
        targets = []
        for target in program.targets:
            if getattr(target, "kind", None) == "web":
                targets.append(replace(target, url=url))
            else:
                targets.append(target)
        program = replace(program, targets=tuple(targets))

        result = ExecutionEngine(program=program, http_client=UrllibHttpClient()).execute()
        results = result if isinstance(result, list) else [result]
        for item in results:
            _format_result(item)
            if getattr(item, "failed", False):
                raise typer.Exit(code=1)
    except Exception as exc:  # pragma: no cover - exercised via CLI errors
        typer.echo("✗ Execution failed")
        typer.echo(f"  {exc}")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()

