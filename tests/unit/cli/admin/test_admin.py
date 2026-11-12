import json
import os
import tempfile

import pretend
import pytest
from click import ClickException
from tuf.api.metadata import DelegatedRole, Delegations

from repository_service_tuf.cli.admin import _set_settings
from repository_service_tuf.cli.admin.delegations import delete as del_cmd
from repository_service_tuf.cli.admin.delegations import new as new_cmd
from repository_service_tuf.helpers.api_client import URL

SRC_PATH = "repository_service_tuf.cli.admin.delegations"


class TestAdmin:
    def test_admin__set_settings_api_server(self):
        api_server = "http://localhost:80"
        fake_settings = pretend.stub(SERVER=None)
        context = pretend.stub(obj={"settings": fake_settings})
        _set_settings(
            context,
            api_server,
            headers=None,
        )

        assert context.obj["settings"].SERVER == api_server
        assert context.obj["settings"].HEADERS is None

    def test_admin__set_settings_api_server_with_headers(self):
        api_server = "http://localhost:80"
        fake_settings = pretend.stub(SERVER=None)
        context = pretend.stub(obj={"settings": fake_settings})
        _set_settings(
            context,
            api_server,
            headers="apikey: 1234, Content-Type: application/json",
        )

        assert context.obj["settings"].SERVER == api_server
        assert context.obj["settings"].HEADERS == {
            "apikey": "1234",
            "Content-Type": "application/json",
        }

    def test_admin__set_settings_api_server_with_bad_headers(self):
        api_server = "http://localhost:80"
        fake_settings = pretend.stub(SERVER=None)
        context = pretend.stub(obj={"settings": fake_settings})

        with pytest.raises(ClickException) as err:
            _set_settings(
                context,
                api_server,
                headers="apikey1234, Content-Type: application/json",
            )

        assert context.obj["settings"].SERVER == api_server
        assert "Invalid headers format" in str(err.value)


class TestDelegationsDelete:
    """Tests for the ``delegations delete`` sub-command."""

    def test_delete_no_server_no_dry_run_raises(
        self, client, test_context, monkeypatch
    ):
        """Missing SERVER without --dry-run must raise ClickException."""
        dummy = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=False, roles=["role-a"]
                )
            )
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.delete._get_latest_md", lambda *_: dummy
        )
        test_context["settings"].SERVER = None
        result = client.invoke(
            del_cmd.delete,
            ["--metadata-url", "http://example/meta"],
            obj=test_context,
        )
        assert result.exit_code == 1
        assert "Either '--api-sever'" in result.output

    def test_delete_succinct_roles_raises(
        self, client, test_context, monkeypatch
    ):
        """Command must raise when metadata uses succinct roles."""
        dummy = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(succinct_roles=True, roles=[])
            )
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.delete._get_latest_md", lambda *_: dummy
        )
        test_context["settings"].SERVER = None
        result = client.invoke(
            del_cmd.delete,
            ["--metadata-url", "http://example/meta", "--dry-run"],
            obj=test_context,
        )
        assert result.exit_code == 1
        assert "succinct roles" in result.output

    def test_delete_dry_run_writes_file(
        self, client, test_context, monkeypatch
    ):
        """Dry-run must write payload locally and not call send_payload."""
        dummy = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=False, roles=["role-a", "role-b"]
                )
            )
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.delete._get_latest_md", lambda *_: dummy
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.delete.select_multiple",
            pretend.call_recorder(lambda *_: ["role-a"]),
        )
        fake_send_payload = pretend.call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(
            f"{SRC_PATH}.delete.send_payload", fake_send_payload
        )

        test_context["settings"].SERVER = None
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "del.json")
            result = client.invoke(
                del_cmd.delete,
                [
                    "--metadata-url",
                    "http://example/meta",
                    "--out",
                    out_path,
                    "--dry-run",
                ],
                obj=test_context,
                catch_exceptions=False,
            )
            assert result.exit_code == 0, result.output
            with open(out_path) as f:
                payload = json.load(f)
            assert payload == {"delegations": {"roles": [{"name": "role-a"}]}}
        assert fake_send_payload.calls == []

    def test_delete_real_run_calls_api(
        self, client, test_context, monkeypatch
    ):
        """When SERVER is present and not dry-run, the API is called."""
        dummy = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=False, roles=["role-c"]
                )
            )
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.delete._get_latest_md", lambda *_: dummy
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.delete.select_multiple", lambda *_: ["role-c"]
        )
        fake_send_payload = pretend.call_recorder(
            lambda *a, **kw: "task-id-123"
        )
        fake_task_status = pretend.call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(
            f"{SRC_PATH}.delete.send_payload", fake_send_payload
        )
        monkeypatch.setattr(f"{SRC_PATH}.delete.task_status", fake_task_status)
        test_context["settings"].SERVER = "https://api.example.com"
        result = client.invoke(
            del_cmd.delete,
            ["--metadata-url", "http://example/meta"],
            obj=test_context,
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert fake_send_payload.calls == [
            pretend.call(
                test_context["settings"],
                URL.DELEGATIONS_DELETE.value,
                {"delegations": {"roles": [{"name": "role-c"}]}},
                "Metadata delegation delete accepted.",
                "Metadata Delegation Processed.",
            )
        ]
        assert fake_task_status.calls == [
            pretend.call(
                "task-id-123",
                test_context["settings"],
                "New Metadata status:",
            )
        ]


class TestDelegationsNew:
    """Tests for the ``delegations new`` sub-command."""

    def test_new_no_server_no_dry_run_raises(self, client, test_context):
        """Missing SERVER without --dry-run must raise ClickException."""
        test_context["settings"].SERVER = None
        result = client.invoke(
            new_cmd.new,
            [],
            obj=test_context,
        )
        assert result.exit_code == 1
        assert "Either '--api-sever'" in result.output

    def test_new_dry_run_writes_file(self, client, test_context, monkeypatch):
        """Dry-run writes the new delegation payload locally."""
        fake_delegations = Delegations(
            keys={},
            roles={
                "myrole": DelegatedRole(
                    name="myrole",
                    keyids=[],
                    threshold=1,
                    terminating=False,
                    paths=[],
                )
            },
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.new._configure_delegations",
            lambda: fake_delegations,
        )
        test_context["settings"].SERVER = None
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "new.json")
            result = client.invoke(
                new_cmd.new,
                ["--out", out_path, "--dry-run"],
                obj=test_context,
                catch_exceptions=False,
            )
            assert result.exit_code == 0, result.output
            with open(out_path) as f:
                payload = json.load(f)
            assert "delegations" in payload
            assert any(
                r["name"] == "myrole" for r in payload["delegations"]["roles"]
            )

    def test_new_real_run_calls_api(self, client, test_context, monkeypatch):
        """When SERVER is set and not dry-run, the API endpoint is called."""
        fake_delegations = Delegations(
            keys={},
            roles={
                "myrole": DelegatedRole(
                    name="myrole",
                    keyids=[],
                    threshold=1,
                    terminating=False,
                    paths=[],
                )
            },
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.new._configure_delegations", lambda: fake_delegations
        )
        fake_send_payload = pretend.call_recorder(
            lambda *a, **kw: "task-id-new"
        )
        fake_task_status = pretend.call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(f"{SRC_PATH}.new.send_payload", fake_send_payload)
        monkeypatch.setattr(f"{SRC_PATH}.new.task_status", fake_task_status)
        test_context["settings"].SERVER = "https://api.example.com"
        result = client.invoke(
            new_cmd.new,
            [],
            obj=test_context,
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert len(fake_send_payload.calls) == 1
        call_args = fake_send_payload.calls[0]
        assert call_args.args[0] == test_context["settings"]
        assert call_args.args[1] == URL.DELEGATIONS.value
        assert "delegations" in call_args.args[2]
        assert fake_task_status.calls == [
            pretend.call(
                "task-id-new",
                test_context["settings"],
                "New Metadata status:",
            )
        ]

    def test_new_parse_pending_data_success(self):
        fake_md = {"role1": {}}
        res = new_cmd._parse_pending_data({"data": {"metadata": fake_md}})
        assert res == fake_md

    def test_new_parse_pending_data_no_data(self):
        with pytest.raises(ClickException) as err:
            new_cmd._parse_pending_data({})
        assert "'data' field missing" in str(err.value)

    def test_new_parse_pending_data_empty_metadata(self):
        with pytest.raises(ClickException) as err:
            new_cmd._parse_pending_data({"data": {"metadata": {}}})
        assert "No metadata available for signing" in str(err.value)

    def test_new_get_pending_roles_success(self, monkeypatch):
        fake_settings = pretend.stub(SERVER="http://localhost", HEADERS=None)
        fake_resp = pretend.stub(
            status_code=200,
            json=lambda: {"data": {"metadata": {"role1": {}}}},
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.new.request_server", lambda *a, **kw: fake_resp
        )
        res = new_cmd._get_pending_roles(fake_settings)
        assert res == {"role1": {}}

    def test_new_get_pending_roles_error(self, monkeypatch):
        fake_settings = pretend.stub(SERVER="http://localhost", HEADERS=None)
        fake_resp = pretend.stub(status_code=500, text="internal error")
        monkeypatch.setattr(
            f"{SRC_PATH}.new.request_server", lambda *a, **kw: fake_resp
        )
        with pytest.raises(ClickException) as err:
            new_cmd._get_pending_roles(fake_settings)
        assert "Failed to fetch metadata for signing" in str(err.value)
