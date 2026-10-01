import pytest
import click
import pretend

from repository_service_tuf.cli.admin.metadata import update
from repository_service_tuf.helpers.api_client import URL

class TestUpdateExtra:
    def test_update_server_send_payload(self, monkeypatch):
        # We want to mock everything until the end where it sends the payload
        monkeypatch.setattr(update, "_get_latest_md", pretend.call_recorder(lambda *a: pretend.stub(signed=pretend.stub(version=1))))
        
        # Mock the root object fully to avoid prompt errors
        import datetime
        class MockRoot:
            version = 1
            def is_expired(self): return False
            expires = datetime.datetime.now()
            def get_delegated_role(self, role_type):
                return pretend.stub(threshold=1)
                
        mock_root = MockRoot()
        
        mock_md = pretend.stub(
            signed=mock_root,
            to_dict=lambda: {"mock": "dict"}
        )
        class MockMetadata:
            @classmethod
            def from_bytes(cls, b):
                return mock_md
                
            def __init__(self, root):
                pass
                
            def to_dict(self):
                return {"mock": "dict"}
                
        monkeypatch.setattr(update, "Metadata", MockMetadata)
        monkeypatch.setattr(update.Confirm, "ask", lambda *a, **kw: False)
        monkeypatch.setattr(update, "_configure_root_keys_prompt", lambda *a: None)
        monkeypatch.setattr(update, "_configure_online_key_prompt", lambda *a: None)
        monkeypatch.setattr(update, "_print_root", lambda *a: None)
        monkeypatch.setattr(update, "_add_root_signatures_prompt", lambda *a: None)
        
        fake_task_id = "task-123"
        monkeypatch.setattr(update, "send_payload", pretend.call_recorder(lambda **kw: fake_task_id))
        monkeypatch.setattr(update, "task_status", pretend.call_recorder(lambda *a: None))
        
        settings_mock = pretend.stub(
            get=lambda k: "http://server",
            SERVER="http://server"
        )
        
        @click.command()
        @click.pass_context
        def wrapper(ctx):
            ctx.obj = {"settings": settings_mock}
            # Provide a dummy input file object to avoid NoneType errors
            class DummyFile:
                def read(self): return b"data"
            ctx.invoke(update.update, dry_run=False, out=None, input=DummyFile(), metadata_url=None)
            
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(wrapper)
        
        assert result.exit_code == 0
        assert "Root metadata update completed. 🔐 🎉" in result.output
        assert update.send_payload.calls == [
            pretend.call(
                settings=settings_mock,
                url=URL.METADATA.value,
                payload={"metadata": {"root": {"mock": "dict"}}},
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update"
            )
        ]
        assert update.task_status.calls == [
            pretend.call(
                fake_task_id,
                settings_mock,
                "Metadata Update status: "
            )
        ]
