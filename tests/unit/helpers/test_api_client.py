import pretend
import pytest

from repository_service_tuf.helpers.api_client import Methods, request_server


class TestAPICLient:
    def test_request_server_get(self, monkeypatch):

        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"key": "value"}),
        )
        fake_requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        monkeypatch.setattr(
            "repository_service_tuf.helpers.api_client.requests", fake_requests
        )

        request_server("http://server", "url", Methods.get)

        assert fake_requests.get.calls == [
            pretend.call(
                "http://server/url", json=None, data=None, headers=None
            )
        ]

    def test_request_server_post(self, monkeypatch):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"key": "value"}),
        )
        fake_requests = pretend.stub(
            post=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        monkeypatch.setattr(
            "repository_service_tuf.helpers.api_client.requests", fake_requests
        )

        request_server("http://server", "url", Methods.post, {"k": "v"})

        assert fake_requests.post.calls == [
            pretend.call(
                "http://server/url", json={"k": "v"}, data=None, headers=None
            )
        ]

    def test_request_server_invalid_method(self, monkeypatch):

        with pytest.raises(ValueError) as err:
            request_server("http://server", "url", "Invalid", {"k": "v"})

        assert "Internal Error. Invalid HTTP/S Method." in str(err.value)
