import pretend
import pytest

from kaprien.cli.admin import login


class TestLoginGroupCLI:
    def test__login(self):

        expected_response = {"data": {"k": "v"}}
        login.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=pretend.call_recorder(lambda *a: expected_response),
            )
        )
        test_data = {"k", "v"}
        result = login._login(server="fake_server", data=test_data)
        assert result == expected_response
        assert login.request_server.calls == [
            pretend.call(
                "fake_server",
                "api/v1/token/",
                login.Methods.post,
                data=test_data,
            )
        ]

    def test__login_unauthorized(self):

        expected_response = {"detail": "Unauthorized."}
        login.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=401,
                json=pretend.call_recorder(lambda *a: expected_response),
            )
        )
        test_data = {"k", "v"}

        with pytest.raises(login.click.ClickException) as err:
            login._login(server="fake_server", data=test_data)

        assert "Unauthorized" in str(err)
        assert login.request_server.calls == [
            pretend.call(
                "fake_server",
                "api/v1/token/",
                login.Methods.post,
                data=test_data,
            )
        ]

    def test_login(self, client, test_context):
        steps = [
            "http://test-kaprien",
            "admin",
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert "Login successfuly." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_force(self, client, test_context):

        # simulate the settings file
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        steps = [
            "http://test-kaprien",
            "admin",
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_result = client.invoke(
            login.login, ["--force"], input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert "Login successfuly." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_expired_token(self, client, test_context):

        # simulate the settings file with invalid/expired token
        test_context["settings"].SERVER = "http://test-kaprien"
        test_context["settings"].TOKEN = "fake-token"

        steps = [
            "http://test-kaprien",
            "admin",
            "pass",
            "1",
        ]

        login.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=False)
        )
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )
        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )

        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert "Login successfuly." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]
        assert login.is_logged.calls == [
            pretend.call(test_context["settings"].SERVER, "fake-token")
        ]

    def test_login_already_logged(self, client, test_context):

        # simulate the settings file with invalid/expired token
        test_context["settings"].SERVER = "http://test-kaprien"
        test_context["settings"].TOKEN = "fake-token"

        steps = [
            "http://test-kaprien",
            "admin",
            "pass",
            "1",
        ]

        login.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(
                state=True,
                data={"expired": False, "expiration": "2022-08-23T09:10:14"},
            )
        )
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )
        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )

        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert (
            "Already logged. Valid until '2022-08-23T09:10:14'"
            in test_result.output
        )
        assert login.is_logged.calls == [
            pretend.call(test_context["settings"].SERVER, "fake-token")
        ]

    def test_login_missing_http_protocol(
        self, monkeypatch, client, test_context
    ):
        steps = [
            "test-kaprien",
            "http://test-kaprien",
            "admin",
            "pass",
            "1",
        ]

        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )
        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )
        assert test_result.exit_code == 0
        assert "Login successfuly." in test_result.output
