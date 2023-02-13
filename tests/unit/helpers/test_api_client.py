# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from unittest.mock import Mock

import pretend
import pytest

from repository_service_tuf.helpers import api_client


class TestAPIClient:
    def test_request_server_get(self):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"key": "value"}),
        )
        api_client.requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        result = api_client.request_server(
            "http://server", "url", api_client.Methods.get
        )

        assert result == fake_response
        assert api_client.requests.get.calls == [
            pretend.call(
                "http://server/url", json=None, data=None, headers=None
            )
        ]

    def test_request_server_post(self):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"key": "value"}),
        )
        api_client.requests = pretend.stub(
            post=pretend.call_recorder(lambda *a, **kw: fake_response)
        )

        result = api_client.request_server(
            "http://server", "url", api_client.Methods.post, {"k": "v"}
        )

        assert result == fake_response
        assert api_client.requests.post.calls == [
            pretend.call(
                "http://server/url", json={"k": "v"}, data=None, headers=None
            )
        ]

    def test_request_server_invalid_method(self):
        with pytest.raises(ValueError) as err:
            api_client.request_server(
                "http://server", "url", "Invalid", {"k": "v"}
            )

        assert "Internal Error. Invalid HTTP/S Method." in str(err.value)

    def test_request_server_ConnectionError(self):
        api_client.requests = pretend.stub(
            post=pretend.raiser(api_client.ConnectionError("Failed request"))
        )
        with pytest.raises(api_client.click.exceptions.ClickException) as err:
            api_client.request_server(
                "http://server", "url", api_client.Methods.post, {"k": "v"}
            )

        assert "Failed to connect to http://server" in str(err.value)

    def test_is_logged(self):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"data": {"expired": False}}),
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )

        result = api_client.is_logged("http://server", "fake_token")
        assert result == api_client.Login(state=True, data={"expired": False})
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/token/?token=fake_token",
                api_client.Methods.get,
                headers={"Authorization": "Bearer fake_token"},
            )
        ]

    def test_is_logged_401(self):
        fake_response = pretend.stub(
            status_code=401,
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )

        result = api_client.is_logged("http://server", "fake_token")
        assert result == api_client.Login(state=False, data=None)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/token/?token=fake_token",
                api_client.Methods.get,
                headers={"Authorization": "Bearer fake_token"},
            )
        ]

    def test_is_logged_500(self):
        fake_response = pretend.stub(
            status_code=500,
            text="body",
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.is_logged("http://server", "fake_token")

        assert "Error 500 body" in str(err)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/token/?token=fake_token",
                api_client.Methods.get,
                headers={"Authorization": "Bearer fake_token"},
            )
        ]

    def test_get_headers(self):
        api_client.is_logged = pretend.call_recorder(
            lambda *a: api_client.Login(
                state=True, data={"data": {"expired": False}}
            )
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=200)
        )

        result = api_client.get_headers(
            {"SERVER": "http://server", "TOKEN": "fake_token"}
        )

        assert result == {"Authorization": "Bearer fake_token"}
        assert api_client.is_logged.calls == [
            pretend.call("http://server", "fake_token")
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                api_client.URL.bootstrap.value,
                api_client.Methods.get,
                headers={"Authorization": "Bearer fake_token"},
            )
        ]

    def test_get_headers_never_logged(self):
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.get_headers({})

        assert "Login first. Run 'rstuf admin login'" in str(err)

    def test_get_headers_is_logged_state_false(self):
        api_client.is_logged = pretend.call_recorder(
            lambda *a: api_client.Login(state=False, data={"expired": False})
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.get_headers(
                {"SERVER": "http://server", "TOKEN": "fake_token"}
            )

        assert "re-login" in str(err)
        assert api_client.is_logged.calls == [
            pretend.call("http://server", "fake_token")
        ]

    def test_get_headers_is_logged_state_true_expired_token(self):
        api_client.is_logged = pretend.call_recorder(
            lambda *a: api_client.Login(state=True, data={"expired": True})
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.get_headers(
                {"SERVER": "http://server", "TOKEN": "fake_token"}
            )

        assert "The token has expired" in str(err)
        assert api_client.is_logged.calls == [
            pretend.call("http://server", "fake_token")
        ]

    def test_get_headers_unexpected_error(self):
        api_client.is_logged = pretend.call_recorder(
            lambda *a: api_client.Login(state=True, data={"expired": False})
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=500, text="error body")
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.get_headers(
                {"SERVER": "http://server", "TOKEN": "fake_token"}
            )

        assert "Unexpected error" in str(err)
        assert api_client.is_logged.calls == [
            pretend.call("http://server", "fake_token")
        ]

    def test_bootstrap_status(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"bootstrap": True}, "message": "text"},
            )
        )
        result = api_client.bootstrap_status(test_context["settings"])
        assert result == {"data": {"bootstrap": True}, "message": "text"}
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.bootstrap.value,
                api_client.Methods.get,
                headers={"auth": "token"},
            )
        ]

    def test_bootstrap_status_404_disabled(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=404,
                json=lambda: {"data": {"bootstrap": True}, "message": "text"},
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.bootstrap_status(test_context["settings"])

        assert "Server http://server does not allow bootstrap" in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.bootstrap.value,
                api_client.Methods.get,
                headers={"auth": "token"},
            )
        ]

    def test_bootstrap_status_not_200(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=500,
                text="Internal Server Error :P",
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.bootstrap_status(test_context["settings"])

        assert "Internal Server Error :P" in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.bootstrap.value,
                api_client.Methods.get,
                headers={"auth": "token"},
            )
        ]

    def test_bootstrap_status_not_json_body(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200, json=lambda: None, text="No json for you"
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.bootstrap_status(test_context["settings"])

        assert "Unexpected error No json for you" in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.bootstrap.value,
                api_client.Methods.get,
                headers={"auth": "token"},
            )
        ]

    def test_task_status(self, test_context):
        test_context["settings"].SERVER = "http://server"
        fake_json = Mock()
        fake_json.side_effect = [
            {"data": {"state": "STARTED", "k": "v"}},
            {"data": {"state": "RUNNING", "k": "v"}},
            {"data": {"state": "RUNNING", "k": "v"}},
            {"data": {"state": "SUCCESS", "k": "v"}},
        ]
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=200, json=fake_json)
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )
        result = api_client.task_status(
            "task_id", test_context["settings"], "Test task: "
        )

        assert result == {"state": "SUCCESS", "k": "v"}
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
        ]

    def test_task_status_unexpected_error(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=500, text="body error")
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "Unexpected response body error" in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"k": "v"}},
                text="",
            )
        )

    def test_task_status_failure(self, test_context):
        test_context["settings"].SERVER = "http://server"
        fake_json = Mock()
        fake_json.side_effect = [
            {"data": {"state": "STARTED", "k": "v"}},
            {"data": {"state": "RUNNING", "k": "v"}},
            {"data": {"state": "FAILURE", "k": "v"}},
        ]
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=fake_json,
                text="{'data': {'state': 'FAILURE', 'k': 'v'}",
            )
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "Failed: " in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
        ]

    def test_task_status_without_state(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"k": "v"}},
                text="",
            )
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "No state in data received " in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
        ]

    def test_task_status_without_data(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {},
                text="",
            )
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "No data received " in str(err)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
        ]
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]

    def test_publish_targets(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=202,
                json=pretend.call_recorder(
                    lambda: {"data": {"task_id": "213sferer"}}
                ),
            )
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )

        result = api_client.publish_targets(test_context["settings"])

        assert result == "213sferer"
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.publish_targets.value,
                api_client.Methods.post,
                headers={"Auth": "Token"},
            )
        ]
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]

    def test_publish_targets_unexpected_error(self, test_context):
        test_context["settings"].SERVER = "http://server"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=500, text="Internal Error"
            )
        )
        api_client.get_headers = pretend.call_recorder(
            lambda *a: {"Auth": "Token"}
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.publish_targets(test_context["settings"])

        assert "Failed to publish targets. 500 Internal Error" in str(err)
        assert api_client.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.publish_targets.value,
                api_client.Methods.post,
                headers={"Auth": "Token"},
            )
        ]
