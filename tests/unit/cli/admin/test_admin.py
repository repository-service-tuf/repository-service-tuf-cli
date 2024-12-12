import pretend
import pytest
from click import ClickException

from repository_service_tuf.cli.admin import _set_settings


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
