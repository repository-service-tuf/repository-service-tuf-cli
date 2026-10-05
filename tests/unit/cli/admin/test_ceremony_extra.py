import json
import pytest
import click
import pretend

from repository_service_tuf.cli.admin import ceremony
from repository_service_tuf.cli.admin.helpers import Settings, Roles, Role
from repository_service_tuf.helpers.api_client import URL

class TestCeremonyExtra:
    def test_ceremony_custom_delegations(self, monkeypatch):
        # Mock _settings_prompt to return a dummy settings object
        class DummyDelegations:
            def to_dict(self):
                return {"keys": {}, "roles": [{"name": "custom_role"}]}

        class DummySettings:
            timestamp_expiry = 1
            snapshot_expiry = 1
            targets_expiry = 1
            bins_expiry = None
            bins_number = None
            delegations = DummyDelegations()
            
        dummy_settings = DummySettings()
        
        monkeypatch.setattr(ceremony, "_settings_prompt", lambda: dummy_settings)
        monkeypatch.setattr(ceremony, "_configure_delegations_prompt", lambda bs: None)
        
        # Mock _expiry_prompt
        monkeypatch.setattr(ceremony, "_expiry_prompt", lambda role: (365, "2030-01-01T00:00:00Z"))
        
        mock_root_role = pretend.stub(threshold=1)
        class MockRoot:
            type = "root"
            def __init__(self):
                self.expires = "2030-01-01T00:00:00Z"
                self.version = 1
            def get_delegated_role(self, role_type):
                return mock_root_role
                
        monkeypatch.setattr(ceremony, "Root", MockRoot)
        
        monkeypatch.setattr(ceremony, "_threshold_prompt", lambda role: 1)
        monkeypatch.setattr(ceremony, "_configure_root_keys_prompt", lambda root: None)
        monkeypatch.setattr(ceremony, "_configure_online_key_prompt", lambda root: None)
        monkeypatch.setattr(ceremony, "_print_root", lambda root: None)
        
        mock_md = pretend.stub(
            to_dict=lambda: {"mock": "root_md"}
        )
        monkeypatch.setattr(ceremony, "Metadata", lambda root: mock_md)
        monkeypatch.setattr(ceremony, "_add_root_signatures_prompt", lambda md, old: None)
        
        fake_task_id = "task-123"
        monkeypatch.setattr(ceremony, "send_payload", pretend.call_recorder(lambda **kw: fake_task_id))
        monkeypatch.setattr(ceremony, "task_status", pretend.call_recorder(lambda *a: None))
        
        settings_mock = pretend.stub(
            get=lambda k: "http://server",
            SERVER="http://server"
        )
        
        @click.command()
        @click.pass_context
        def wrapper(ctx):
            ctx.obj = {"settings": settings_mock}
            ctx.invoke(ceremony.ceremony, dry_run=False, out=None, timeout=300)
            
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(wrapper)
        
        assert result.exit_code == 0
        assert "Ceremony done. 🔐 🎉. Bootstrap completed." in result.output
        
        assert ceremony.send_payload.calls[0].kwargs["expected_msg"] == "Bootstrap accepted."
        # Confirm that delegations is indeed included in the payload
        payload = ceremony.send_payload.calls[0].kwargs["payload"]
        assert payload["settings"]["roles"]["delegations"] == {"keys": {}, "roles": [{"name": "custom_role"}]}
