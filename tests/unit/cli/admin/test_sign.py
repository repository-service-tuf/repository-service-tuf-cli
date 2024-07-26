# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json

import click
import pretend
import pytest

from repository_service_tuf.cli.admin import sign
from repository_service_tuf.helpers.api_client import URL, Methods
from tests.conftest import _HELPERS, _PAYLOADS, _PEMS, _ROOTS, invoke_command


class TestSign:
    def test_sign_with_previous_root(
        self, monkeypatch, test_context, patch_getpass
    ):
        inputs = [
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        # selections interface
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: "JimiHendrix's Key",
        )

        with open(f"{_PAYLOADS / 'sign_pending_roles.json'}") as f:
            fake_response_data = json.load(f)

        fake_response = pretend.stub(
            json=pretend.call_recorder(lambda: fake_response_data),
            status_code=200,
        )
        sign.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        sign.send_payload = pretend.call_recorder(lambda **kw: "fake-taskid")
        sign.task_status = pretend.call_recorder(lambda *a: "OK")
        api_server = "http://127.0.0.1"
        test_context["settings"].SERVER = api_server

        result = invoke_command(sign.sign, inputs, [], test_context)

        with open(_PAYLOADS / "sign.json") as f:
            expected = json.load(f)

        assert result.data["role"] == "root"
        assert (
            result.data["signature"]["keyid"] == expected["signature"]["keyid"]
        )
        assert "Metadata Signed and sent to the API! 🔑" in result.stdout
        assert sign.request_server.calls == [
            pretend.call(api_server, "api/v1/metadata/sign/", Methods.GET)
        ]
        assert sign.send_payload.calls == [
            pretend.call(
                settings=result.context["settings"],
                url=URL.METADATA_SIGN.value,
                payload={
                    "role": "root",
                    "signature": {
                        "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
                        "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
                    },
                },
                expected_msg="Metadata sign accepted.",
                command_name="Metadata sign",
            )
        ]
        assert sign.task_status.calls == [
            pretend.call(
                "fake-taskid",
                result.context["settings"],
                "Metadata sign status:",
            )
        ]

    def test_sign_bootstrap_root(
        self, monkeypatch, test_context, patch_getpass
    ):
        inputs = [
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        # selections interface
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: "JimiHendrix's Key",
        )

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
        sign.send_payload = pretend.call_recorder(lambda **kw: "fake-taskid")
        sign.task_status = pretend.call_recorder(lambda *a: "OK")
        api_server = "http://127.0.0.1"
        test_context["settings"].SERVER = api_server

        result = invoke_command(sign.sign, inputs, [], test_context)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert "Metadata Signed and sent to the API! 🔑" in result.stdout
        assert sign.request_server.calls == [
            pretend.call(api_server, "api/v1/metadata/sign/", Methods.GET)
        ]
        assert sign.send_payload.calls == [
            pretend.call(
                settings=result.context["settings"],
                url=URL.METADATA_SIGN.value,
                payload={
                    "role": "root",
                    "signature": {
                        "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
                        "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
                    },
                },
                expected_msg="Metadata sign accepted.",
                command_name="Metadata sign",
            )
        ]
        assert sign.task_status.calls == [
            pretend.call(
                "fake-taskid",
                result.context["settings"],
                "Metadata sign status:",
            )
        ]

    def test_sign_dry_run_and_input_option_and_custom_out(
        self, monkeypatch, test_context, patch_getpass
    ):
        """
        Test that '--dry-run', '--in' and '--out' are compatible options
        without connecting to the API.
        """
        inputs = [
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        # selections interface
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: "JimiHendrix's Key",
        )
        input_path = f"{_PAYLOADS / 'sign_pending_roles.json'}"
        custom_out_path = "custom_sign_path.json"
        args = ["--dry-run", "--in", input_path, "--out", custom_out_path]

        result = invoke_command(
            sign.sign, inputs=inputs, args=args, test_context=test_context
        )

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert result.data["signature"]["sig"] == expected["sig"]
        assert f"Saved result to '{custom_out_path}'" in result.stdout
        assert "Metadata Signed and sent to the API" not in result.stdout

    def test_sign_with_input_option_and_api_server_set(
        self, monkeypatch, test_context, patch_getpass
    ):
        inputs = [
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        ]
        # selections interface
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: "JimiHendrix's Key",
        )
        sign.send_payload = pretend.call_recorder(lambda **kw: "fake-taskid")
        sign.task_status = pretend.call_recorder(lambda *a: "OK")
        sign_input_path = f"{_PAYLOADS / 'sign_pending_roles.json'}"
        test_context["settings"].SERVER = "http://localhost:80"
        args = ["--in", sign_input_path]

        result = invoke_command(sign.sign, inputs, args, test_context)

        expected = {
            "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
            "sig": "828a659bc34972504b9dab16bc44818b8a7d49ffee2a9021df6a6be4dd3b7a026d1f890b952303d1cf32dda90fbdf60e9fcfeb5f0af6498f0f55cad31c750a02",  # noqa
        }

        assert result.data["role"] == "root"
        assert result.data["signature"]["keyid"] == expected["keyid"]
        assert "Metadata Signed and sent to the API! 🔑" in result.stdout
        assert sign.send_payload.calls == [
            pretend.call(
                settings=result.context["settings"],
                url=URL.METADATA_SIGN.value,
                payload={
                    "role": "root",
                    "signature": {
                        "keyid": "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa
                        "sig": "917046f9076eae41876be7c031be149aa2a960fd21f0d52f72128f55d9c423e2ec1632f98c96693dd801bd064e37efd6e5a5d32712fd5701a42099ece6b88c05",  # noqa
                    },
                },
                expected_msg="Metadata sign accepted.",
                command_name="Metadata sign",
            )
        ]
        assert sign.task_status.calls == [
            pretend.call(
                "fake-taskid",
                result.context["settings"],
                "Metadata sign status:",
            )
        ]

    def test_sign_dry_run_with_server_config_set(
        self,
        monkeypatch,
        ceremony_inputs,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        """
        Test that '--dry-run' is with higher priority than 'settings.SERVER'.
        """
        # selections interface
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: "JimiHendrix's Key",
        )
        sign_input_path = f"{_PAYLOADS / 'sign_pending_roles.json'}"
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        # We want to test when only "--dry-run" is used we will not save a file
        # locally and will not send payload to the API.
        # Given that "invoke_command" always saves a file, so the result can be
        # read we cannot use it.
        with client.isolated_filesystem():
            result = client.invoke(
                sign.sign,
                args=["--dry-run", "--in", sign_input_path],
                input="\n".join(
                    input_step1 + input_step2 + input_step3 + input_step4
                ),
                obj=test_context,
                catch_exceptions=False,
            )

        assert result.stderr == ""
        assert "Saved result to " not in result.stdout
        assert "Bootstrap completed." not in result.stdout


class TestSignError:
    def test_sign_no_api_server_and_no_input_option(self):
        result = invoke_command(sign.sign, [], [], std_err_empty=False)

        err_prefix = "Either '--api-server' admin option/'SERVER'"
        err_suffix = "or '--in'"
        assert err_prefix in result.stderr
        assert err_suffix in result.stderr

    def test_sign_no_api_server_and_no_dry_run_option(self):
        sign_input_path = f"{_PAYLOADS / 'sign_pending_roles.json'}"
        args = ["--in", sign_input_path]

        result = invoke_command(sign.sign, [], args, std_err_empty=False)

        err_prefix = "Either '--api-server' admin option/'SERVER'"
        err_suffix = "or '--dry-run'"
        assert err_prefix in result.stderr
        assert err_suffix in result.stderr

    def test_sign_with_previous_root_but_wrong_version(
        self, test_context, patch_getpass
    ):
        inputs = [
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
        api_server = "http://127.0.0.1"
        test_context["settings"].SERVER = api_server

        test_result = invoke_command(
            sign.sign, inputs, [], test_context, std_err_empty=False
        )

        assert test_result.exit_code == 1, test_result.stdout
        assert "Previous root v1 needed to sign root v2" in test_result.stderr
        assert sign.request_server.calls == [
            pretend.call(api_server, "api/v1/metadata/sign/", Methods.GET)
        ]

    def test_sign_fully_signed_metadata(self, test_context, patch_getpass):
        inputs = [
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
        api_server = "http://127.0.0.1"
        test_context["settings"].SERVER = api_server

        test_result = invoke_command(
            sign.sign, inputs, [], test_context, std_err_empty=False
        )

        assert test_result.exit_code == 1, test_result.stdout
        assert "Metadata already fully signed." in test_result.stderr
        assert sign.request_server.calls == [
            pretend.call(api_server, "api/v1/metadata/sign/", Methods.GET)
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
