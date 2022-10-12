import pytest
from click.testing import CliRunner

from tuf_repository_service.__version__ import version
from tuf_repository_service.cli import trs


@pytest.fixture
def cli_runner():
    runner = CliRunner()

    return runner


class TestTrsCLI:
    def test_trs_version_parameter(self, cli_runner):
        """Tests the CLI --version parameter existence and output format."""
        result = cli_runner.invoke(trs, ["--version"])

        assert result.exit_code == 0
        assert result.output == f"trs-cli, version {version}\n"
