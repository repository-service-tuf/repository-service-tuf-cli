import pretend
import pytest

from repository_service_tuf.cli.admin import click, send


class TestSend:
    def test__validate_settings(self, test_context):
        test_context["settings"].SERVER = "http://localhost:80"
        fake_context = pretend.stub(obj={"settings": test_context["settings"]})
        send._validate_settings(fake_context)

        assert fake_context.obj["settings"].SERVER == "http://localhost:80"

    def test__validate_settings_server_missing(self, test_context):
        fake_context = pretend.stub(obj={"settings": test_context["settings"]})
        with pytest.raises(click.ClickException) as err:
            send._validate_settings(fake_context)

        assert "Needed '--api-server' admin option or 'SERVER'" in str(err)
