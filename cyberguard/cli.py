"""CyberGuard CLI - Command-line interface for the cybersecurity DSL."""

from typing import Optional

import typer

from cyberguard import __version__

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
) -> None:
    """
    Execute a CyberGuard DSL file.

    Args:
        file: Path to the CyberGuard DSL file (.cg)

    Example:
        cyberguard run examples/authentication.cg
    """
    typer.echo(f"[*] CyberGuard: Executing file '{file}'")
    typer.echo("[!] DSL execution not yet implemented (Phase 2)")


if __name__ == "__main__":
    app()

