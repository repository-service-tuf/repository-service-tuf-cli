import pytest  # type: ignore
from click.testing import CliRunner  # type: ignore


@pytest.fixture
def client():
    runner = CliRunner()
    return runner
