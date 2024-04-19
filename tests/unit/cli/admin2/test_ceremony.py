import json

from repository_service_tuf.cli.admin2 import ceremony
from tests.conftest import _PAYLOADS, _PEMS, invoke_command


class TestCeremony:
    def test_ceremony(self, client, patch_getpass, patch_utcnow):
        inputs = [
            "",  # Please enter days until expiry for timestamp role (1)
            "",  # Please enter days until expiry for snapshot role (1)
            "",  # Please enter days until expiry for targets role (365)
            "",  # Please enter days until expiry for bins role (1)
            "4",  # Please enter number of delegated hash bins [2/4/8/16/32/64/128/256/512/1024/2048/4096/8192/16384] (256)  # noqa
            "",  # Please enter days until expiry for root role (365)
            "2",  # Please enter root threshold
            f"{_PEMS / 'rsa.pub'}",  # Please enter path to public key
            "my rsa key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index  # noqa
            f"{_PEMS / 'ed25519.pub'}",  # Please enter path to public key
            "Kairo's key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
            f"{_PEMS / 'ecdsa.pub'}",  # Please enter path to public key
            "Lukas's Key",  # Please enter key name
            "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
            f"{_PEMS / 'online_key_rsa.pub'}",  # Please enter path to public key  # noqa
            "Online Key",  # Please enter a key name
            "1",  # Please enter signing key index
            f"{_PEMS / 'ed25519'}",  # Please enter path to encrypted private key  # noqa
            "1",  # Please enter signing key index
            f"{_PEMS / 'ecdsa'}",  # Please enter path to encrypted private key
        ]

        result = invoke_command(client, ceremony.ceremony, inputs, [])

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
