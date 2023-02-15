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

    def test_task_status(self):
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

        result = api_client.task_status(
            "task_id", "http://server", {"Auth": "Token"}, "Test task: "
        )

        assert result == {"state": "SUCCESS", "k": "v"}
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

    def test_task_status_unexpected_error(self):
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=500, text="body error")
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", "http://server", {"Auth": "Token"}, "Test task: "
            )

        assert "Unexpected response body error" in str(err)

    def test_task_status_failure(self):
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

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", "http://server", {"Auth": "Token"}, "Test task: "
            )

        assert "Failed: " in str(err)
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

    def test_task_status_without_state(self):
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"k": "v"}},
                text="",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", "http://server", {"Auth": "Token"}, "Test task: "
            )

        assert "No state in data received " in str(err)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.get,
                headers={"Auth": "Token"},
            ),
        ]

    def test_task_status_without_data(self):
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {},
                text="",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", "http://server", {"Auth": "Token"}, "Test task: "
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

    def test_publish_targets(self):
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=202,
                json=pretend.call_recorder(
                    lambda: {"data": {"task_id": "213sferer"}}
                ),
            )
        )
        result = api_client.publish_targets(
            "http://127.0.0.1", {"Auth": "Token"}
        )
        assert result == "213sferer"

    def test_publish_targets_unexpected_error(self):
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=500, text="Internal Error"
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.publish_targets("http://127.0.0.1", {"Auth": "Token"})
        assert "Failed to publish targets. 500 Internal Error" in str(err)
