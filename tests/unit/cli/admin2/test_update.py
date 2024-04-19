import json

from repository_service_tuf.cli.admin2 import update
from tests.conftest import _PAYLOADS, _PEMS, _ROOTS, invoke_command


class TestMetadataUpdate:
    def test_update(self, client, patch_getpass, patch_utcnow):
        inputs = [
            "n",  # Do you want to change the expiry date? [y/n] (y)
            "n",  # Do you want to change the threshold? [y/n] (n)
            "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to continue  # noqa
            "0",  # Please press 0 to add key, or remove key by entering its index. Press enter to continue  # noqa
            f"{_PEMS / 'rsa.pub'}",  # Please enter path to public key
            "Martin's Key",  # Please enter a key name
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to continue:  # noqa
            "",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'new_online_key_ecdsa.pub'}",  # Please enter path to public key  # noqa
            "New Online Key",  # Please enter a key name
            "1",  # Please enter signing key index
            f"{_PEMS / 'ed25519'}",  # Please enter path to encrypted private key  # noqa
            "1",  # Please enter signing key index
            f"{_PEMS / 'ecdsa'}",  # Please enter path to encrypted private key
            "1",  # Please enter signing key index
            f"{_PEMS / 'rsa'}",  # Please enter path to encrypted private key
        ]
        args = [f"{_ROOTS / 'v1.json'}"]

        result = invoke_command(client, update.update, inputs, args)
        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
