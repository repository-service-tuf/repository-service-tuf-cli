import click
import pretend
import pytest

from repository_service_tuf.cli.admin import _set_settings


class TestAdmin:
    def test_admin__set_settings_api_server_and_offline_fail(self):
        with pytest.raises(click.ClickException) as e:
            _set_settings(None, "http://localhost:80", True)

        err = "Using both '--api-server' and '--offline' is not allowed"
        assert err in str(e)

    def test_admin__set_settings_api_server(self):
        api_server = "http://localhost:80"
        fake_settings = pretend.stub(SERVER=None, OFFLINE=None)
        context = pretend.stub(obj={"settings": fake_settings})
        _set_settings(context, api_server, False)

        assert context.obj["settings"].SERVER == api_server
        assert context.obj["settings"].OFFLINE is False

    def test_admin__set_settings_offline(self):
        fake_settings = pretend.stub(SERVER=None, OFFLINE=None)
        context = pretend.stub(obj={"settings": fake_settings})
        _set_settings(context, None, True)

        assert context.obj["settings"].SERVER is None
        assert context.obj["settings"].OFFLINE is True
