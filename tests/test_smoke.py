from importlib import metadata

from click.testing import CliRunner

from skillfortify import __version__
from skillfortify.cli.main import cli


def test_version():
    """__version__ must track the installed distribution, not a literal.

    A hardcoded literal here is what allowed the published 0.4.3 to report
    itself as 0.3.3: the constant and the test drifted together, so nothing
    could detect the mismatch.
    """
    assert __version__ == metadata.version("skillfortify")


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Formal verification" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert metadata.version("skillfortify") in result.output
