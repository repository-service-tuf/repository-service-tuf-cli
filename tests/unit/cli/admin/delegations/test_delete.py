import json
import pretend
import pytest
from click import ClickException
from click.testing import CliRunner

from repository_service_tuf.cli.admin.delegations import delete

class TestDelegationsDelete:
    def test_delete_command_dry_run(self, monkeypatch):
        runner = CliRunner()
        class FakeSettings:
            SERVER = None
            def get(self, key, default=None):
                return getattr(self, key, default)
        
        settings = FakeSettings()
        
        targets_stub = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=False,
                    roles=["role1", "role2"]
                )
            )
        )
        get_latest_md = pretend.call_recorder(lambda *a, **kw: targets_stub)
        monkeypatch.setattr(delete, "_get_latest_md", get_latest_md)
        
        select_multiple = pretend.call_recorder(lambda roles, **kw: ["role1"])
        monkeypatch.setattr(delete, "select_multiple", select_multiple)
        
        result = runner.invoke(delete.delete, ["--metadata-url", "http://test", "--dry-run"], obj={"settings": settings})
        
        assert result.exit_code == 0
        assert get_latest_md.calls == [pretend.call("http://test", "targets")]
        assert select_multiple.calls == [pretend.call(["role1", "role2"])]

    def test_delete_command_out_file_and_api(self, monkeypatch, tmp_path):
        runner = CliRunner()
        class FakeSettings:
            SERVER = "http://test-server"
            def get(self, key, default=None):
                return getattr(self, key, default)
        
        settings = FakeSettings()
        
        targets_stub = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=False,
                    roles=["role1", "role2"]
                )
            )
        )
        get_latest_md = pretend.call_recorder(lambda *a, **kw: targets_stub)
        monkeypatch.setattr(delete, "_get_latest_md", get_latest_md)
        
        select_multiple = pretend.call_recorder(lambda roles, **kw: ["role2"])
        monkeypatch.setattr(delete, "select_multiple", select_multiple)
        
        send_payload = pretend.call_recorder(lambda *a, **kw: "task_id")
        monkeypatch.setattr(delete, "send_payload", send_payload)

        task_status = pretend.call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(delete, "task_status", task_status)
        
        test_file = tmp_path / "test-delete.json"
        
        result = runner.invoke(delete.delete, ["--metadata-url", "http://test", "--out", str(test_file)], obj={"settings": settings})
        
        assert result.exit_code == 0
        assert send_payload.calls == [
            pretend.call(
                settings,
                delete.URL.DELEGATIONS_DELETE.value,
                {"delegations": {"roles": [{"name": "role2"}]}},
                "Metadata delegation delete accepted.",
                "Metadata Delegation Processed.",
            )
        ]
        
        with open(test_file) as f:
            content = json.load(f)
            assert content == {"delegations": {"roles": [{"name": "role2"}]}}

    def test_delete_command_succinct_roles(self, monkeypatch):
        runner = CliRunner()
        class FakeSettings:
            SERVER = None
            def get(self, key, default=None):
                return getattr(self, key, default)
        settings = FakeSettings()
        
        targets_stub = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=True,
                    roles=["role1", "role2"]
                )
            )
        )
        get_latest_md = pretend.call_recorder(lambda *a, **kw: targets_stub)
        monkeypatch.setattr(delete, "_get_latest_md", get_latest_md)
        
        result = runner.invoke(delete.delete, ["--metadata-url", "http://test", "--dry-run"], obj={"settings": settings})
        
        assert result.exit_code == 1
        assert "Metadata uses succinct roles, not allowed." in result.output

    def test_delete_command_api_error_no_server_no_dry_run(self, monkeypatch):
        runner = CliRunner()
        class FakeSettings:
            SERVER = None
            def get(self, key, default=None):
                return getattr(self, key, default)
        settings = FakeSettings()
        
        result = runner.invoke(delete.delete, ["--metadata-url", "http://test"], obj={"settings": settings})
        
        assert result.exit_code == 1
        assert "Either '--api-sever' admin option" in result.output
