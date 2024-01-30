from pathlib import Path

import pretend
import pytest
from click.testing import CliRunner
from rich.console import Console
from rich.pretty import pprint
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli import admin2
from repository_service_tuf.cli.admin2 import sign

_FILES = Path(__file__).parent.parent.parent / "files"
_ROOTS = _FILES / "root"
_PEMS = _FILES / "pem"


@pytest.fixture
def patch_getpass(monkeypatch):
    """Fixture to mock password prompt return value for encrypted test keys.

    NOTE: we need this, because getpass does not receive the inputs passed to
    click's invoke method (interestingly, click's own password prompt, which
    also uses getpass, does receive them)
    """

    def mock_getpass(prompt, stream=None):
        # no need to mock prompt output, rich prompts independently
        return "hunter2"

    import rich.console

    monkeypatch.setattr(rich.console, "getpass", mock_getpass)


# flake8: noqa
class TestSign:
    def test_sign_v2(self, client: CliRunner, monkeypatch, patch_getpass):
        signer_keyid = (
            "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3"
        )
        root1 = Metadata[Root].from_file(f"{_ROOTS / 'v1.json'}")
        root2 = Metadata[Root].from_file(f"{_ROOTS / 'v2.json'}")

        inputs = [signer_keyid, f"{_PEMS / 'ec'}"]

        mock_api = pretend.call_recorder(lambda x, y: None)
        monkeypatch.setattr(
            admin2, "_fetch_metadata", lambda x: (root2, root1.signed)
        )
        monkeypatch.setattr(admin2, "_push_signature", mock_api)

        assert not root2.signatures
        result = client.invoke(
            sign, "--api-server mocked", input="\n".join(inputs)
        )

        # Assert signature was added to metadata and sent to mock API
        assert root2.signatures[signer_keyid] == mock_api.calls[0].args[1]
