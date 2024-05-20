import json

from repository_service_tuf.cli.admin import ceremony
from tests.conftest import _PAYLOADS, invoke_command


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
