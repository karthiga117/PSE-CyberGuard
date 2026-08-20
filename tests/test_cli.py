"""Tests for CyberGuard CLI."""

from typer.testing import CliRunner

from cyberguard import __version__
from cyberguard.cli import app

runner = CliRunner()


class TestVersion:
    """Test version command."""

    def test_version_flag(self) -> None:
        """Test that --version returns the correct version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert f"CyberGuard {__version__}" in result.stdout

    def test_version_matches_module(self) -> None:
        """Test that CLI version matches module version."""
        result = runner.invoke(app, ["--version"])
        assert "0.1.0" in result.stdout


class TestHelp:
    """Test help command."""

    def test_help_flag(self) -> None:
        """Test that --help displays help text."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "cyberguard" in result.stdout.lower()
        assert "cybersecurity" in result.stdout.lower()

    def test_command_help(self) -> None:
        """Test help for run command."""
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "Execute a CyberGuard DSL file" in result.stdout


class TestRunCommand:
    """Test run command."""

    def test_run_nonexistent_file(self) -> None:
        """Test run with a nonexistent file."""
        result = runner.invoke(app, ["run", "nonexistent.cg"])
        assert result.exit_code == 0
        assert "Executing file" in result.stdout
