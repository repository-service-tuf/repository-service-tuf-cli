# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json

import click
import pretend
import pytest

from repository_service_tuf.cli.admin import sign
from repository_service_tuf.helpers.api_client import URL, Methods
from tests.conftest import _PAYLOADS, _PEMS, _ROOTS, invoke_command


class TestSign:
    def test_sign_with_previous_root(self, patch_getpass):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        with open(f"{_PAYLOADS / 'sign_pending_roles.json'}") as f:
            fake_response_data = json.load(f)

        fake_response = pretend.stub(
            json=pretend.call_recorder(lambda: fake_response_data),
            status_code=200,
        )
        sign.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        sign.send_payload = pretend.call_recorder(lambda *a: "fake-taskid")
        sign.task_status = pretend.call_recorder(lambda *a: "OK")
        args = ["--api-server", "http://127.0.0.1"]

        result = invoke_command(sign.sign, inputs, args)

        with open(_PAYLOADS / "sign.json") as f:
            expected = json.load(f)

        assert result.data["role"] == "root"
        assert (
            result.data["signature"]["keyid"] == expected["signature"]["keyid"]
        )
        assert "Metadata Signed and sent to the API! 🔑" in result.output
        assert sign.request_server.calls == [
            pretend.call(
                "http://127.0.0.1",
                "api/v1/metadata/sign/",
                Methods.GET,
            )
        ]
        assert sign.send_payload.calls == [
            pretend.call(
                result.context["settings"],
                URL.METADATA_SIGN.value,
                {
                    "role": "root",
                    "signature": {
                        "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
                        "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
                    },
                },
                "Metadata sign accepted.",
                "Metadata sign",
            )
        ]
        assert sign.task_status.calls == [
            pretend.call(
                "fake-taskid",
                result.context["settings"],
                "Metadata sign status:",
            )
        ]

    def test_sign_bootstap_root(self, patch_getpass):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]

        with open(f"{_ROOTS / 'v1.json'}") as f:
            v1_das_root = f.read()

        fake_response_data = {
            "data": {"metadata": {"root": json.loads(v1_das_root)}}
        }
        fake_response = pretend.stub(
            json=pretend.call_recorder(lambda: fake_response_data),
            status_code=200,
        )
        sign.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        sign.send_payload = pretend.call_recorder(lambda *a: "fake-taskid")
        sign.task_status = pretend.call_recorder(lambda *a: "OK")
        args = ["--api-server", "http://127.0.0.1"]

        result = invoke_command(sign.sign, inputs, args)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert "Metadata Signed and sent to the API! 🔑" in result.output
        assert sign.request_server.calls == [
            pretend.call(
                "http://127.0.0.1",
                "api/v1/metadata/sign/",
                Methods.GET,
            )
        ]
        assert sign.send_payload.calls == [
            pretend.call(
                result.context["settings"],
                URL.METADATA_SIGN.value,
                {
                    "role": "root",
                    "signature": {
                        "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
                        "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
                    },
                },
                "Metadata sign accepted.",
                "Metadata sign",
            )
        ]
        assert sign.task_status.calls == [
            pretend.call(
                "fake-taskid",
                result.context["settings"],
                "Metadata sign status:",
            )
        ]

    def test_sign_local_file_input_and_custom_save(
        self, client, test_context, patch_getpass
    ):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]

        args = [f"{_PAYLOADS / 'sign_pending_roles.json'}"]
        custom_path = "custom_sign_path.json"
        with client.isolated_filesystem():
            result = client.invoke(
                sign.sign,
                args=args + ["-s", custom_path],
                input="\n".join(inputs),
                obj=test_context,
                catch_exceptions=False,
            )
            with open(custom_path) as f:
                result.data = json.load(f)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert result.data["signature"]["sig"] == expected["sig"]
        assert f"Saved result to '{custom_path}'" in result.output

    def test_sign_local_file_no_save_option_given(
        self, client, test_context, patch_getpass
    ):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]

        args = [f"{_PAYLOADS / 'sign_pending_roles.json'}"]
        default_path = "sign-payload.json"
        with client.isolated_filesystem():
            result = client.invoke(
                sign.sign,
                args=args,
                input="\n".join(inputs),
                obj=test_context,
                catch_exceptions=False,
            )
            assert result.stderr == ""
            with open(default_path) as f:
                result.data = json.load(f)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert result.data["signature"]["sig"] == expected["sig"]
        assert f"Saved result to '{default_path}'" in result.output

    def test_sign_bootstap_root_with_file_input_with_api_server(
        self, patch_getpass
    ):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        sign.send_payload = pretend.call_recorder(lambda *a: "fake-taskid")
        sign.task_status = pretend.call_recorder(lambda *a: "OK")
        sign_input_path = f"{_PAYLOADS / 'sign_pending_roles.json'}"
        api_server = "http://localhost:80"
        args = ["--api-server", api_server, sign_input_path]
        result = invoke_command(sign.sign, inputs, args)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert "Metadata Signed and sent to the API! 🔑" in result.output
        assert sign.send_payload.calls == [
            pretend.call(
                result.context["settings"],
                URL.METADATA_SIGN.value,
                {
                    "role": "root",
                    "signature": {
                        "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
                        "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
                    },
                },
                "Metadata sign accepted.",
                "Metadata sign",
            )
        ]
        assert sign.task_status.calls == [
            pretend.call(
                "fake-taskid",
                result.context["settings"],
                "Metadata sign status:",
            )
        ]

    def test_sign_bootstap_root_with_file_input_no_api_server_no_save(
        self, client, patch_getpass, test_context
    ):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]

        sign_input_path = f"{_PAYLOADS / 'sign_pending_roles.json'}"
        args = [sign_input_path]

        with client.isolated_filesystem():
            result = client.invoke(
                sign.sign,
                args=args,
                input="\n".join(inputs),
                obj=test_context,
                catch_exceptions=False,
            )

            assert result.stderr == ""
            with open(sign.DEFAULT_PATH) as f:
                result.data = json.load(f)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert "Metadata Signed and sent to the API! 🔑" not in result.output
        assert f"Saved result to {sign.DEFAULT_PATH}"

    def test_sign_no_api_server_and_no_file_input(self):
        result = invoke_command(sign.sign, [], [], std_err_empty=False)

        assert "Either '--api-sever'/'SERVER'" in result.stderr


class TestSignError:
    def test_sign_with_previous_root_but_wrong_version(self, patch_getpass):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        with open(f"{_ROOTS / 'v2.json'}") as f:
            v2_das_root = f.read()

        fake_response_data = {
            "data": {
                "metadata": {
                    "root": json.loads(v2_das_root),
                }
            }
        }
        fake_response = pretend.stub(
            json=pretend.call_recorder(lambda: fake_response_data),
            status_code=200,
        )
        sign.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        args = ["--api-server", "http://127.0.0.1"]
        test_result = invoke_command(
            sign.sign, inputs, args, std_err_empty=False
        )

        assert test_result.exit_code == 1, test_result.output
        assert "Previous root v1 needed to sign root v2" in test_result.stderr
        assert sign.request_server.calls == [
            pretend.call(
                "http://127.0.0.1",
                "api/v1/metadata/sign/",
                Methods.GET,
            )
        ]

    def test_sign_fully_signed_metadata(self, patch_getpass):
        inputs = [
            "1",  # Please enter signing key index
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        with open("tests/files/payload/ceremony.json", "r") as f:
            ceremony_payload = json.loads(f.read())

        fake_response_data = {
            "data": {
                "metadata": {
                    "root": ceremony_payload["metadata"]["root"],
                }
            }
        }
        fake_response = pretend.stub(
            json=pretend.call_recorder(lambda: fake_response_data),
            status_code=200,
        )
        sign.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        args = ["--api-server", "http://127.0.0.1"]
        test_result = invoke_command(
            sign.sign, inputs, args, std_err_empty=False
        )

        assert test_result.exit_code == 1, test_result.output
        assert "Metadata already fully signed." in test_result.stderr
        assert sign.request_server.calls == [
            pretend.call(
                "http://127.0.0.1",
                "api/v1/metadata/sign/",
                Methods.GET,
            )
        ]


class TestHelpers:
    def test__parse_pending_data(self):
        fake_md = ["md1", "md2"]
        result = sign._parse_pending_data({"data": {"metadata": fake_md}})

        assert result == fake_md

    def test__parse_pending_data_missing_metadata(self):
        with pytest.raises(click.ClickException) as e:
            sign._parse_pending_data({"data": {}})

        assert "No metadata available for signing" in str(e)

    def test__parse_pending_data_missing_data(self):
        with pytest.raises(click.ClickException) as e:
            sign._parse_pending_data({})

        err = "'data' field missing from api server response/file input"
        assert err in str(e)

    def test__get_pending_roles_request(self, monkeypatch):
        fake_settings = pretend.stub(SERVER=None)
        fake_json = pretend.stub()
        response = pretend.stub(
            status_code=200, json=pretend.call_recorder(lambda: fake_json)
        )
        sign.request_server = pretend.call_recorder(lambda *a, **kw: response)

        parsed_data = pretend.stub()
        fake__parse_pending_data = pretend.call_recorder(lambda a: parsed_data)
        monkeypatch.setattr(
            sign, "_parse_pending_data", fake__parse_pending_data
        )

        result = sign._get_pending_roles(fake_settings)

        assert result == parsed_data
        assert sign.request_server.calls == [
            pretend.call(
                fake_settings.SERVER,
                sign.URL.METADATA_SIGN.value,
                sign.Methods.GET,
            )
        ]
        assert response.json.calls == [pretend.call()]
        assert fake__parse_pending_data.calls == [pretend.call(fake_json)]

    def test__get_pending_roles_request_bad_status_code(self):
        fake_settings = pretend.stub(
            SERVER="http://localhost:80",
        )
        response = pretend.stub(status_code=400, text="")
        sign.request_server = pretend.call_recorder(lambda *a, **kw: response)
        with pytest.raises(click.ClickException) as e:
            sign._get_pending_roles(fake_settings)

        assert "Failed to fetch metadata for signing" in str(e)
        assert sign.request_server.calls == [
            pretend.call(
                fake_settings.SERVER,
                sign.URL.METADATA_SIGN.value,
                sign.Methods.GET,
            )
        ]
