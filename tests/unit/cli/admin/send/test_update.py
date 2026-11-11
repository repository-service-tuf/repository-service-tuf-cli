import json

import pretend

from repository_service_tuf.cli.admin.send import update
from repository_service_tuf.helpers.api_client import URL
from tests.conftest import _PAYLOADS, invoke_command

PATH = "repository_service_tuf.cli.admin.send.update"


class TestSendMdUpdate:
    def test_update(self, test_context, monkeypatch):
        fake_task_id = "task_id"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(f"{PATH}.send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(f"{PATH}.task_status", fake_task_status)
        update_payload_path = f"{_PAYLOADS / 'update.json'}"
        test_context["settings"].SERVER = "http://127.0.0.1"
        args = [update_payload_path]

        result = invoke_command(update.update, [], args, test_context)

        with open(_PAYLOADS / "update.json") as f:
            expected_data = json.load(f)

        assert fake_send_payload.calls == [
            pretend.call(
                settings=result.context["settings"],
                url=URL.METADATA.value,
                payload=expected_data,
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update",
            )
        ]
        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id,
                result.context["settings"],
                "Metadata Update status: ",
            )
        ]
        assert "Root metadata update completed. 🔐 🎉" in result.stdout
