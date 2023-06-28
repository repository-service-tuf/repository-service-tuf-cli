# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest

from repository_service_tuf.cli.admin import login


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
            "http://test-rstuf",
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )
        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_no_auth(self, client, test_context):
        steps = [
            "http://test-rstuf",
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
        assert login.loaders.write.calls == []

    def test_login_force(self, client, test_context):
        # simulate the settings file
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        steps = [
            "http://test-rstuf",
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True
        test_result = client.invoke(
            login.login, ["--force"], input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_expired_token(self, client, test_context):
        # simulate the settings file with invalid/expired token
        test_context["settings"].SERVER = "http://test-rstuf"
        test_context["settings"].TOKEN = "fake-token"

        steps = [
            "http://test-rstuf",
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
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]
        assert login.is_logged.calls == [
            pretend.call(test_context["settings"])
        ]

    def test_login_already_logged(self, client, test_context):
        # simulate the settings file with invalid/expired token
        test_context["settings"].SERVER = "http://test-rstuf"
        test_context["settings"].TOKEN = "fake-token"

        steps = [
            "http://test-rstuf",
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
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )

        assert test_result.exit_code == 0
        assert (
            "Already logged to http://test-rstuf."
            " Valid until '2022-08-23T09:10:14'" in test_result.output
        )
        assert login.is_logged.calls == [
            pretend.call(test_context["settings"])
        ]

    def test_login_missing_http_protocol(self, client, test_context):
        steps = [
            "test-rstuf",
            "http://test-rstuf",
            "pass",
            "1",
        ]

        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )
        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login, input="\n".join(steps), obj=test_context
        )
        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output

    def test_login_with_server(self, client, test_context):
        steps = [
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login,
            ["-s", "http://test-rstuf"],
            input="\n".join(steps),
            obj=test_context,
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_with_server_bad_address(self, client, test_context):
        steps = [
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login,
            ["-s", "test-rstuf"],
            input="\n".join(steps),
            obj=test_context,
        )

        assert test_result.exit_code == 1
        assert (
            "Please use 'http://test-rstuf' or 'https://test-rstuf'"
            in test_result.output
        )

    def test_login_with_server_bad_address_them_fixed(
        self, client, test_context
    ):
        steps = [
            "http://test-rstuf",
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login,
            ["-s", "test-rstuf"],
            input="\n".join(steps),
            obj=test_context,
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_with_server_user_pass(self, client, test_context):
        steps = [
            "pass",
            "1",
        ]
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login,
            ["-s", "http://test-rstuf", "-p", "pass"],
            input="\n".join(steps),
            obj=test_context,
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]

    def test_login_with_non_intereactive(self, client, test_context):
        login._login = pretend.call_recorder(
            lambda *a: {"access_token": "fake-token"}
        )

        login.loaders = pretend.stub(
            write=pretend.call_recorder(lambda *a: None)
        )
        test_context["settings"].AUTH = True

        test_result = client.invoke(
            login.login,
            [
                "-s",
                "http://test-rstuf",
                "-p",
                "pass",
                "-e",
                "1",
            ],
            obj=test_context,
        )

        assert test_result.exit_code == 0
        assert "Login successful." in test_result.output
        assert login.loaders.write.calls == [
            pretend.call(
                test_context["config"], test_context["settings"].to_dict()
            )
        ]
