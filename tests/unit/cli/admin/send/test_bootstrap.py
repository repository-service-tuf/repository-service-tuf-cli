import json

import pretend

from repository_service_tuf.cli.admin.send import bootstrap
from repository_service_tuf.helpers.api_client import URL
from tests.conftest import _PAYLOADS, invoke_command

PATH = "repository_service_tuf.cli.admin.send.bootstrap"


class TestSendBootstrap:
    def test_bootstrap(self, test_context, monkeypatch):
        fake_task_id = "task_id"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(f"{PATH}.send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(f"{PATH}.task_status", fake_task_status)
        bootstrap_payload_path = f"{_PAYLOADS / 'ceremony.json'}"
        test_context["settings"].SERVER = "http://127.0.0.1"
        args = [bootstrap_payload_path]

        result = invoke_command(bootstrap.bootstrap, [], args, test_context)

        with open(_PAYLOADS / "ceremony.json") as f:
            expected_data = json.load(f)

        assert fake_send_payload.calls == [
            pretend.call(
                settings=result.context["settings"],
                url=URL.BOOTSTRAP.value,
                payload=expected_data,
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )
        ]
        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id, result.context["settings"], "Bootstrap status: "
            )
        ]
        assert "Bootstrap completed. 🔐 🎉" in result.stdout
