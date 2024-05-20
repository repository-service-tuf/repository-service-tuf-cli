import json

from repository_service_tuf.cli.admin import ceremony
from tests.conftest import _PAYLOADS, _PEMS, invoke_command


class TestCeremony:
    def test_ceremony(self, ceremony_inputs, patch_getpass, patch_utcnow):
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

    def test_ceremony_online_key_one_of_root_keys(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        # Test that online key cannot be one of root key's.
        input_step1, input_step2, _, input_step4 = ceremony_inputs
        input_step3 = [  # Configure Online Key
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub'}",  # Please enter path to public key  # noqa
            "Online Key",  # Please enter a key name
        ]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Key already in use." in result.stdout
