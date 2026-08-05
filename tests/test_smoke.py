from importlib import metadata

import pytest
from click.testing import CliRunner

from skillfortify import __version__
from skillfortify.cli.main import cli


def _installed() -> bool:
    """Whether an installed distribution's metadata is readable."""
    try:
        metadata.version("skillfortify")
    except metadata.PackageNotFoundError:
        return False
    return True


# Only the assertions that read distribution metadata are conditional. A bare
# source checkout has none, and skipping there keeps the signal meaningful: a
# failure means a genuine version mismatch, not an uninstalled package.
needs_install = pytest.mark.skipif(
    not _installed(),
    reason="skillfortify is not installed; run `pip install -e .` to exercise this",
)


@needs_install
def test_version():
    """``__version__`` must track the installed distribution, not a literal.

    Reading the packaging metadata is what keeps the reported version, the
    CLI's ``--version`` output, and pyproject.toml from disagreeing.
    """
    assert __version__ == metadata.version("skillfortify")


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Formal verification" in result.output


@needs_install
def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert metadata.version("skillfortify") in result.output
