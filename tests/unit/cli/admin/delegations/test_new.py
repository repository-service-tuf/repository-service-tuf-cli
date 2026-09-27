import json
import pretend
import pytest
from click import ClickException
from click.testing import CliRunner

from repository_service_tuf.cli.admin.delegations import new


class TestDelegationsNew:
    def test__parse_pending_data(self):
        data = {"data": {"metadata": {"role1": {}}}}
        result = new._parse_pending_data(data)
        assert result == {"role1": {}}

    def test__parse_pending_data_missing_data(self):
        data = {}
        with pytest.raises(ClickException, match="'data' field missing"):
            new._parse_pending_data(data)

    def test__parse_pending_data_missing_metadata(self):
        data = {"data": {"metadata": {}}}
        with pytest.raises(
            ClickException, match="No metadata available for signing"
        ):
            new._parse_pending_data(data)

    def test__get_pending_roles(self, monkeypatch):
        settings = pretend.stub(
            SERVER="test-server", HEADERS={"Authorization": "Bearer token"}
        )
        response = pretend.stub(
            status_code=200,
            json=lambda: {"data": {"metadata": {"role1": {}}}},
        )

        request_server = pretend.call_recorder(lambda *a, **kw: response)
        monkeypatch.setattr(new, "request_server", request_server)

        result = new._get_pending_roles(settings)
        assert result == {"role1": {}}
        assert request_server.calls == [
            pretend.call(
                "test-server",
                new.URL.METADATA_SIGN.value,
                new.Methods.GET,
                headers={"Authorization": "Bearer token"},
            )
        ]

    def test__get_pending_roles_error(self, monkeypatch):
        settings = pretend.stub(
            SERVER="test-server", HEADERS={"Authorization": "Bearer token"}
        )
        response = pretend.stub(status_code=500, text="Internal Server Error")

        request_server = pretend.call_recorder(lambda *a, **kw: response)
        monkeypatch.setattr(new, "request_server", request_server)

        with pytest.raises(
            ClickException, match="Failed to fetch metadata for signing"
        ):
            new._get_pending_roles(settings)

    def test_new_command_dry_run(self, monkeypatch):
        runner = CliRunner()

        class FakeSettings:
            SERVER = None
            def get(self, key, default=None):
                return getattr(self, key, default)

        settings = FakeSettings()

        delegations_stub = pretend.stub(to_dict=lambda: {"mock": "data"})
        configure_delegations = pretend.call_recorder(
            lambda: delegations_stub
        )
        monkeypatch.setattr(
            new, "_configure_delegations", configure_delegations
        )

        result = runner.invoke(
            new.new, ["--dry-run"], obj={"settings": settings}
        )

        assert result.exit_code == 0
        assert configure_delegations.calls == [pretend.call()]
        assert "New Targets Metadata Tool" in result.output

    def test_new_command_out_file_and_api(self, monkeypatch, tmp_path):
        runner = CliRunner()
        
        class FakeSettings:
            SERVER = "http://test-server"
            def get(self, key, default=None):
                return getattr(self, key, default)
        
        settings = FakeSettings()

        delegations_stub = pretend.stub(to_dict=lambda: {"mock": "data"})
        configure_delegations = pretend.call_recorder(
            lambda: delegations_stub
        )
        monkeypatch.setattr(
            new, "_configure_delegations", configure_delegations
        )

        send_payload = pretend.call_recorder(lambda *a, **kw: "task_id")
        monkeypatch.setattr(new, "send_payload", send_payload)

        task_status = pretend.call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(new, "task_status", task_status)

        test_file = tmp_path / "test-out.json"

        result = runner.invoke(
            new.new,
            ["--out", str(test_file)],
            obj={"settings": settings},
        )

        assert result.exit_code == 0
        assert configure_delegations.calls == [pretend.call()]
        assert send_payload.calls == [
            pretend.call(
                settings,
                new.URL.DELEGATIONS.value,
                {"delegations": {"mock": "data"}},
                "Metadata delegation add accepted.",
                "New Metadata finished.",
            )
        ]
        assert task_status.calls == [
            pretend.call("task_id", settings, "New Metadata status:")
        ]

        with open(test_file) as f:
            content = json.load(f)
            assert content == {"delegations": {"mock": "data"}}

    def test_new_command_api_error_no_server_no_dry_run(self, monkeypatch):
        runner = CliRunner()
        
        class FakeSettings:
            SERVER = None
            def get(self, key, default=None):
                return getattr(self, key, default)
                
        settings = FakeSettings()

        result = runner.invoke(new.new, [], obj={"settings": settings})

        assert result.exit_code == 1
        assert "Either '--api-sever' admin option" in result.output
