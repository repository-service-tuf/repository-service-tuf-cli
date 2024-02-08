from pathlib import Path

import pretend
import pytest
from click.testing import CliRunner
from tuf.api.metadata import Metadata, Root

import repository_service_tuf.cli.admin2 as admin2
from repository_service_tuf.cli.admin2 import sign, update

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

        mock_api = pretend.call_recorder(lambda x, y: "mock_task_id")
        monkeypatch.setattr(
            admin2, "_fetch_metadata", lambda x: (root2, root1.signed)
        )
        monkeypatch.setattr(admin2, "_push_signature", mock_api)
        monkeypatch.setattr(admin2, "_wait_for_success", lambda x: None)

        assert not root2.signatures
        result = client.invoke(
            sign,
            "--api-server mocked",
            input="\n".join(inputs),
            catch_exceptions=False,
        )

        # Assert signature was added to metadata and sent to mock API
        assert root2.signatures[signer_keyid] == mock_api.calls[0].args[1]


class TestUpdate:
    def test_update(self, client, monkeypatch, patch_getpass):
        """Exemplary root v1 update w/o signing (tested above) ."""
        root = Metadata[Root].from_file(f"{_ROOTS / 'v1.json'}")
        mock_save = pretend.call_recorder(lambda x: None)
        monkeypatch.setattr(admin2, "_save", mock_save)

        inputs = [
            f"{_ROOTS / 'v1.json'}",  # Enter path to root to update:
            "10",  # Please enter number of days from now, when root should expire:
            "n",  # Do you want to change the expiry date? [y/n]:
            "y",  # Do you want to change root keys? [y/n]:
            "y",  # Do you want to change the root signature threshold? [y/n]:
            "1",  # Please enter root signature threshold:
            "y",  # Do you want to remove a root key? [y/n]:
            "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",  # Choose key to remove [50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]:
            "y",  # Do you want to remove a root key? [y/n]:
            "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # Choose key to remove [c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]:
            f"{_PEMS / 'rsa.pub'}",  # Please enter a public key path:
            "my rsa root key",  # Please enter a key name, or press enter to continue without name:
            "n",  # Do you want to add a root key? [y/n]:
            "n",  # Do you want to change root keys? [y/n]:
            "y",  # Do you want to change the online key? [y/n]:
            f"{_PEMS / 'ec.pub'}",  # Please enter a public key path:
            "n",  # Do you want to change the online key? [y/n]:
            "n",  # Do you want to sign?
        ]
        # Assert pre-update root threshold, root keys, and online key
        assert root.signed.roles["root"].threshold == 2
        assert sorted(root.signed.roles["root"].keyids) == [
            "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
        ]
        assert sorted(root.signed.roles["timestamp"].keyids) == [
            "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc"
        ]
        result = client.invoke(update, input="\n".join(inputs))

        new_root = mock_save.calls[0].args[0]
        # Assert post-update root threshold, root keys, and online key
        assert new_root.signed.roles["root"].threshold == 1
        assert new_root.signed.roles["root"].keyids == [
            "2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241"
        ]
        assert sorted(new_root.signed.roles["timestamp"].keyids) == [
            "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3"
        ]
