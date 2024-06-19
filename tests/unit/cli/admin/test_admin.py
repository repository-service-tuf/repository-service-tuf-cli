import pretend

from repository_service_tuf.cli.admin import _set_settings


class TestAdmin:
    def test_admin__set_settings_api_server(self):
        api_server = "http://localhost:80"
        fake_settings = pretend.stub(SERVER=None)
        context = pretend.stub(obj={"settings": fake_settings})
        _set_settings(context, api_server)

        assert context.obj["settings"].SERVER == api_server
