# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from unittest.mock import Mock

import pretend
import pytest
import rich_click as click

from repository_service_tuf.helpers import api_client


class TestAPIClient:
    path = "repository_service_tuf.helpers.api_client"

    def test_request_server_get(self):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"key": "value"}),
        )
        api_client.requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        result = api_client.request_server(
            "http://server", "url", api_client.Methods.GET
        )

        assert result == fake_response
        assert api_client.requests.get.calls == [
            pretend.call(
                "http://server/url",
                json=None,
                data=None,
                headers=None,
                timeout=300,
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
            "http://server", "url", api_client.Methods.POST, {"k": "v"}
        )

        assert result == fake_response
        assert api_client.requests.post.calls == [
            pretend.call(
                "http://server/url",
                json={"k": "v"},
                data=None,
                headers=None,
                timeout=300,
            )
        ]

    def test_request_server_delete(self):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"key": "value"}),
        )
        api_client.requests = pretend.stub(
            delete=pretend.call_recorder(lambda *a, **kw: fake_response)
        )

        result = api_client.request_server(
            "http://server", "url", api_client.Methods.DELETE, {"k": "v"}
        )

        assert result == fake_response
        assert api_client.requests.delete.calls == [
            pretend.call(
                "http://server/url",
                json={"k": "v"},
                data=None,
                headers=None,
                timeout=300,
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
                "http://server", "url", api_client.Methods.POST, {"k": "v"}
            )

        assert "Failed to connect to http://server" in str(err.value)

    def test_bootstrap_status(self, test_context):
        test_context["settings"].SERVER = "http://server"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"bootstrap": True}, "message": "text"},
            )
        )
        result = api_client.bootstrap_status(test_context["settings"])
        assert result == {"data": {"bootstrap": True}, "message": "text"}
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.GET,
            )
        ]

    def test_bootstrap_status_404_disabled(self, test_context):
        test_context["settings"].SERVER = "http://server"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=404,
                json=lambda: {"data": {"bootstrap": True}, "message": "text"},
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.bootstrap_status(test_context["settings"])

        assert "Server http://server does not allow bootstrap" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.GET,
            )
        ]

    def test_bootstrap_status_not_200(self, test_context):
        test_context["settings"].SERVER = "http://server"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=500,
                text="Internal Server Error :P",
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.bootstrap_status(test_context["settings"])

        assert "Internal Server Error :P" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.GET,
            )
        ]

    def test_bootstrap_status_not_json_body(self, test_context):
        test_context["settings"].SERVER = "http://server"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200, json=lambda: None, text="No json for you"
            )
        )
        with pytest.raises(api_client.click.ClickException) as err:
            api_client.bootstrap_status(test_context["settings"])

        assert "Unexpected error No json for you" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.GET,
            )
        ]

    def test_task_status(self, test_context):
        test_context["settings"].SERVER = "http://server"
        fake_json = Mock()
        fake_json.side_effect = [
            {"data": {"state": "STARTED", "k": "v"}},
            {"data": {"state": "RUNNING", "k": "v"}},
            {"data": {"state": "RUNNING", "k": "v"}},
            {
                "data": {
                    "state": "SUCCESS",
                    "result": {"status": True},
                    "k": "v",
                }
            },
        ]
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=200, json=fake_json)
        )

        result = api_client.task_status(
            "task_id", test_context["settings"], "Test task: "
        )

        assert result == {
            "state": "SUCCESS",
            "result": {"status": True},
            "k": "v",
        }
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
        ]

    def test_task_status_unexpected_error(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(status_code=500, text="body error")
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "Unexpected response body error" in str(err)

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"k": "v"}},
                text="",
            )
        )

    def test_task_status_state_failure(self, test_context):
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

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "Failed: " in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
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

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "No state in data received " in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
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

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "No data received " in str(err)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
        ]

    def test_task_status_without_result(self, test_context):
        test_context["settings"].SERVER = "http://server"
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=lambda: {"data": {"state": "SUCCESS", "k": "v"}},
                text="",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "No result received in data " in str(err)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
        ]

    def test_task_status_status_failure(self, test_context):
        test_context["settings"].SERVER = "http://server"
        fake_json = Mock()
        fake_json.side_effect = [
            {"data": {"state": "STARTED", "k": "v"}},
            {"data": {"state": "RUNNING", "k": "v"}},
            {
                "data": {
                    "state": "SUCCESS",
                    "result": {"status": False},
                    "k": "v",
                }
            },
        ]
        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=fake_json,
                text=(
                    "{'data': {'state': 'SUCCESS', "
                    "'result': {'status': False}, 'k': 'v'}"
                ),
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.task_status(
                "task_id", test_context["settings"], "Test task: "
            )

        assert "Task status is not successful: " in str(err)
        assert api_client.request_server.calls == [
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
            pretend.call(
                "http://server",
                "api/v1/task/?task_id=task_id",
                api_client.Methods.GET,
            ),
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

        result = api_client.publish_targets(test_context["settings"])

        assert result == "213sferer"
        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.PUBLISH_TARGETS.value,
                api_client.Methods.POST,
            )
        ]

    def test_publish_targets_unexpected_error(self, test_context):
        test_context["settings"].SERVER = "http://server"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=500, text="Internal Error"
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.publish_targets(test_context["settings"])

        assert "Failed to publish artifacts. 500 Internal Error" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.PUBLISH_TARGETS.value,
                api_client.Methods.POST,
            )
        ]

    def test_send_payload(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=202,
                json=pretend.call_recorder(
                    lambda: {
                        "data": {"task_id": "task_id_123"},
                        "message": "Bootstrap accepted.",
                    }
                ),
            )
        )
        result = api_client.send_payload(
            settings=test_context["settings"],
            url=api_client.URL.BOOTSTRAP.value,
            payload={"payload": "data"},
            expected_msg="Bootstrap accepted.",
            command_name="Bootstrap",
        )
        assert result == "task_id_123"

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.POST,
                {"payload": "data"},
            )
        ]

    def test_send_payload_not_202(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200,
                json=pretend.call_recorder(
                    lambda: {
                        "data": {"task_id": "task_id_123"},
                        "message": "Bootstrap accepted.",
                    }
                ),
                text="Unexpected result data",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.send_payload(
                settings=test_context["settings"],
                url=api_client.URL.BOOTSTRAP.value,
                payload={"payload": "data"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )

        assert "Error 200" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.POST,
                {"payload": "data"},
            )
        ]

    def test_send_payload_no_message(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=202,
                json=pretend.call_recorder(
                    lambda: {
                        "data": {"task_id": "task_id_123"},
                    }
                ),
                text="No message available.",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.send_payload(
                settings=test_context["settings"],
                url=api_client.URL.BOOTSTRAP.value,
                payload={"payload": "data"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )

        assert "No message available." in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.POST,
                {"payload": "data"},
            )
        ]

    def test_send_payload_no_task_id(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=202,
                json=pretend.call_recorder(
                    lambda: {
                        "data": {"task_id": None},
                        "message": "Bootstrap accepted.",
                    }
                ),
                text="No task id",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.send_payload(
                settings=test_context["settings"],
                url=api_client.URL.BOOTSTRAP.value,
                payload={"payload": "data"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )

        assert "Failed to get `task id`" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.POST,
                {"payload": "data"},
            )
        ]

    def test_send_payload_no_data(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"

        api_client.request_server = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=202,
                json=pretend.call_recorder(
                    lambda: {
                        "data": {},
                        "message": "Bootstrap accepted.",
                    }
                ),
                text="No data",
            )
        )

        with pytest.raises(api_client.click.ClickException) as err:
            api_client.send_payload(
                settings=test_context["settings"],
                url=api_client.URL.BOOTSTRAP.value,
                payload={"payload": "data"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )

        assert "Failed to get task response data" in str(err)

        assert api_client.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                api_client.URL.BOOTSTRAP.value,
                api_client.Methods.POST,
                {"payload": "data"},
            )
        ]

    def test_get_md_file_local_file(self):
        api_client.Metadata.from_file = pretend.call_recorder(
            lambda *a: bytes("abc", "utf-8")
        )
        result = api_client.get_md_file("tests/files/root.json")
        assert result == bytes("abc", "utf-8")
        assert api_client.Metadata.from_file.calls == [
            pretend.call("tests/files/root.json")
        ]

    def test_get_md_file_url(self, monkeypatch):
        api_client.console.print = pretend.call_recorder(lambda *a: None)
        api_client.requests.get = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=200, content='{"metadata": "root"}'
            )
        )
        fake_from_bytes = pretend.call_recorder(
            lambda *a: bytes("abc", "utf-8")
        )
        monkeypatch.setattr(
            f"{self.path}.Metadata.from_bytes", fake_from_bytes
        )
        file = "1.root.json"
        url = f"http://localhost/{file}"
        result = api_client.get_md_file(url)
        assert result == bytes("abc", "utf-8")
        assert api_client.console.print.calls == [
            pretend.call(f"Fetching file {url}"),
        ]
        assert api_client.requests.get.calls == [
            pretend.call(url, timeout=300),
        ]
        assert fake_from_bytes.calls == [pretend.call('{"metadata": "root"}')]

    def test_get_md_file_url_response_not_200(self):
        api_client.console.print = pretend.call_recorder(lambda *a: None)
        api_client.requests.get = pretend.call_recorder(
            lambda *a, **kw: pretend.stub(
                status_code=404,
            )
        )
        file = "1.root.json"
        url = f"http://localhost/{file}"
        with pytest.raises(click.ClickException) as err:
            result = api_client.get_md_file(url)
            assert result is None

        assert f"Cannot fetch {url}" in str(err.value)
        assert api_client.console.print.calls == [
            pretend.call(f"Fetching file {url}"),
        ]
        assert api_client.requests.get.calls == [
            pretend.call(url, timeout=300),
        ]
