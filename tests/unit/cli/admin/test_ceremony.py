from unittest.mock import MagicMock

import pretend  # type: ignore
import pytest
import requests  # type: ignore
from securesystemslib.keys import generate_ed25519_key  # type: ignore

from kaprien.cli.admin.ceremony import Methods, _request_server, ceremony


class TestCeremonyGroupCLI:
    def test_ceremony(self, client):
        test_result = client.invoke(ceremony)
        assert test_result.exit_code == 1
        assert (
            "Repository Metadata and Settings for Kaprien"
            in test_result.output
        )

    def test_ceremony_start_no(self, client):
        test_result = client.invoke(ceremony, input="n\nn\n")
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_not_ready_load_the_keys(self, client):
        input_step1 = [
            "n",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "http://www.example.com/repository",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = ["n"]
        test_result = client.invoke(
            ceremony, input="\n".join(input_step1 + input_step2)
        )
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_default_values(self, client, monkeypatch):
        input_step1 = [
            "y",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "http://www.example.com/repository",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "4",
            "",
        ]
        input_step2 = [
            "Y",
            "tests/files/JimiHendrix.key",
            "strongPass",
            "tests/files/JanisJoplin.key",
            "strongPass",
            "tests/files/ChrisCornel.key",
            "strongPass",
            "tests/files/KurtCobain.key",
            "strongPass",
            "tests/files/snapshot1.key",
            "strongPass",
            "tests/files/timestamp1.key",
            "strongPass",
            "tests/files/JoeCocker.key",
            "strongPass",
            "tests/files/bins1.key",
            "strongPass",
            "y",
            "y",
            "y",
            "y",
            "y",
            "y",
        ]

        class FakeKey:
            def __init__(self):
                self.error = None
                self.key = generate_ed25519_key()

        fake__load_key = pretend.call_recorder(lambda *a, **kw: FakeKey())
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._load_key", fake__load_key
        )

        test_result = client.invoke(
            ceremony, input="\n".join(input_step1 + input_step2)
        )

        assert test_result.exit_code == 0
        assert "Role: root" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "Threshold: 1" in test_result.output
        assert "Keys Type: offline" in test_result.output
        assert "JimiHendrix.key" in test_result.output
        assert "Role: targets" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "JanisJoplin.key" in test_result.output
        assert "ChrisCornel.key" in test_result.output
        assert "Role: snapshot" in test_result.output
        assert "Keys Type: online" in test_result.output
        assert "Role: timestamp" in test_result.output
        assert "KurtCobain.key" in test_result.output
        assert "JoeCocker.key" in test_result.output
        assert "bins1.key" in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_start_default_values_reconfigure_one_role(
        self, client, monkeypatch
    ):
        input_step1 = [
            "y",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "http://www.example.com/repository",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = [
            "Y",
            "tests/files/JimiHendrix.key",
            "strongPass",
            "tests/files/JanisJoplin.key",
            "strongPass",
            "tests/files/ChrisCornel.key",
            "strongPass",
            "tests/files/KurtCobain.key",
            "strongPass",
            "tests/files/snapshot1.key",
            "strongPass",
            "tests/files/timestamp1.key",
            "strongPass",
            "tests/files/JoeCocker.key",
            "strongPass",
            "tests/files/bins1.key",
            "strongPass",
            "y",
            "y",
            "n",
            "",
            "",
            "",
            "tests/files/snapshot1.key",
            "strongPass",
            "y",
            "y",
            "y",
            "y",
        ]

        class FakeKey:
            def __init__(self):
                self.error = None
                self.key = generate_ed25519_key()

        fake__load_key = pretend.call_recorder(lambda *a, **kw: FakeKey())
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._load_key", fake__load_key
        )

        test_result = client.invoke(
            ceremony, input="\n".join(input_step1 + input_step2)
        )
        assert test_result.exit_code == 0
        assert "Role: root" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "Threshold: 1" in test_result.output
        assert "Keys Type: offline" in test_result.output
        assert "JimiHendrix.key" in test_result.output
        assert "Role: targets" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "JanisJoplin.key" in test_result.output
        assert "ChrisCornel.key" in test_result.output
        assert "Role: snapshot" in test_result.output
        assert "Keys Type: online" in test_result.output
        assert "Role: timestamp" in test_result.output
        assert "KurtCobain.key" in test_result.output
        assert "JoeCocker.key" in test_result.output
        assert "bins1.key" in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test__request_server_get(self, monkeypatch):
        fake_requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: "FakeResponse")
        )
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony.requests", fake_requests
        )

        _request_server("http://server", "url", Methods.get)

        assert fake_requests.get.calls == [
            pretend.call("http://server/url", json=None)
        ]

    def test__request_server_post(self, monkeypatch):
        fake_requests = pretend.stub(
            post=pretend.call_recorder(lambda *a, **kw: "FakeResponse")
        )
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony.requests", fake_requests
        )

        _request_server("http://server", "url", Methods.post, {"k": "v"})

        assert fake_requests.post.calls == [
            pretend.call("http://server/url", json={"k": "v"})
        ]

    def test__request_server_invalid_method(self, monkeypatch):

        with pytest.raises(ValueError) as err:
            _request_server("http://server", "url", "Invalid", {"k": "v"})

        assert "Invalid Method" in str(err.value)

    def test_ceremony_with_flag_bootstrap(self, client, monkeypatch):
        input_step1 = [
            "y",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "http://www.example.com/repository",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = [
            "Y",
            "tests/files/JimiHendrix.key",
            "strongPass",
            "tests/files/JanisJoplin.key",
            "strongPass",
            "tests/files/ChrisCornel.key",
            "strongPass",
            "tests/files/KurtCobain.key",
            "strongPass",
            "tests/files/snapshot1.key",
            "strongPass",
            "tests/files/timestamp1.key",
            "strongPass",
            "tests/files/JoeCocker.key",
            "strongPass",
            "tests/files/bins1.key",
            "strongPass",
            "y",
            "y",
            "y",
            "y",
            "y",
            "y",
        ]

        fake__request_server_get = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"bootstrap": False}),
        )
        fake__request_server_post = pretend.stub(status_code=201)
        mocked_request_server = MagicMock()
        mocked_request_server.side_effect = [
            fake__request_server_get,
            fake__request_server_post,
        ]
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._request_server", mocked_request_server
        )

        class FakeKey:
            def __init__(self):
                self.error = None
                self.key = generate_ed25519_key()

        fake__load_key = pretend.call_recorder(lambda *a, **kw: FakeKey())
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._load_key", fake__load_key
        )

        test_result = client.invoke(
            ceremony,
            ["--bootstrap", "http://fakeserver"],
            input="\n".join(input_step1 + input_step2),
        )

        assert test_result.exit_code == 0
        assert "Ceremony and Bootstrap done" in test_result.output
        assert fake__request_server_get.json.calls == [pretend.call()]
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_with_flag_bootstrap_already_done(
        self, client, monkeypatch
    ):
        fake__request_server_get = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(
                lambda: {
                    "bootstrap": True,
                    "message": "System already has a Metadata.",
                }
            ),
        )
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._request_server",
            lambda *a: fake__request_server_get,
        )

        test_result = client.invoke(
            ceremony, ["--bootstrap", "http://fakeserver"]
        )

        assert test_result.exit_code == 1
        assert "System already has a Metadata." in test_result.output
        assert fake__request_server_get.json.calls == [pretend.call()]

    def test_ceremony_with_flag_bootstrap_connection_error(
        self, client, monkeypatch
    ):

        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._request_server",
            pretend.raiser(requests.exceptions.ConnectionError),
        )

        test_result = client.invoke(
            ceremony, ["--bootstrap", "http://fakeserver"]
        )

        assert test_result.exit_code == 1
        assert "Failed to connect to http://fakeserver" in test_result.output

    def test_ceremony_with_flag_bootstrap_wrong_status_code(
        self, client, monkeypatch
    ):
        fake__request_server_get = pretend.stub(
            status_code=404,
            text=pretend.call_recorder(
                lambda: {
                    "detail": "URL not found",
                }
            ),
        )
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._request_server",
            lambda *a: fake__request_server_get,
        )

        test_result = client.invoke(
            ceremony, ["--bootstrap", "http://fakeserver"]
        )

        assert test_result.exit_code == 1
        assert "Error: 404" in test_result.output

    def test_ceremony_with_flag_bootstrap_failed_post(
        self, client, monkeypatch
    ):
        input_step1 = [
            "y",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "http://www.example.com/repository",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = [
            "Y",
            "tests/files/JimiHendrix.key",
            "strongPass",
            "tests/files/JanisJoplin.key",
            "strongPass",
            "tests/files/ChrisCornel.key",
            "strongPass",
            "tests/files/KurtCobain.key",
            "strongPass",
            "tests/files/snapshot1.key",
            "strongPass",
            "tests/files/timestamp1.key",
            "strongPass",
            "tests/files/JoeCocker.key",
            "strongPass",
            "tests/files/bins1.key",
            "strongPass",
            "y",
            "y",
            "y",
            "y",
            "y",
            "y",
        ]

        fake__request_server_get = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"bootstrap": False}),
        )
        fake__request_server_post = pretend.stub(
            status_code=200, text="Failed!"
        )
        mocked_request_server = MagicMock()
        mocked_request_server.side_effect = [
            fake__request_server_get,
            fake__request_server_post,
        ]
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._request_server", mocked_request_server
        )

        class FakeKey:
            def __init__(self):
                self.error = None
                self.key = generate_ed25519_key()

        fake__load_key = pretend.call_recorder(lambda *a, **kw: FakeKey())
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._load_key", fake__load_key
        )

        test_result = client.invoke(
            ceremony,
            ["--bootstrap", "http://fakeserver"],
            input="\n".join(input_step1 + input_step2),
        )

        assert test_result.exit_code == 1
        assert "Failed" in test_result.output
        assert fake__request_server_get.json.calls == [pretend.call()]
