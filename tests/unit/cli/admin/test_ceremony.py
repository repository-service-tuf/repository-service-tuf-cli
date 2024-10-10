import json

import pretend
from tuf.api.metadata import Signature

from repository_service_tuf.cli.admin import ceremony
from tests.conftest import _HELPERS, _PAYLOADS, _PEMS, invoke_command


class TestCeremony:
    def test_ceremony_with_dry_run_and_custom_out(
        self,
        monkeypatch,
        ceremony_inputs,
        key_selection,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        """
        Test that '--dry-run' and '--out' are compatible without connecting to
        the API.
        """
        # public keys and signing keys selection options
        monkeypatch.setattr(f"{_HELPERS}._select", key_selection)

        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        custom_path = "file.json"
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args=["--dry-run", "--out", custom_path],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert f"Saved result to '{custom_path}'" in result.stdout
        assert "Bootstrap completed." not in result.stdout

    def test_ceremony_with_dry_run_and_custom_out_pem_and_sigstore_keys(
        self,
        monkeypatch,
        ceremony_inputs,
        key_selection,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        """
        Test that '--dry-run' and '--out' are compatible without connecting to
        the API.
        """
        # public keys and signing keys selection options
        selection = iter(
            (
                # select delegation type
                "Bins (online key only)",
                # selections for input_step4
                "Key PEM File",  # select key type
                "add",  # add key
                "Sigstore",  # select key type
                "https://github.com/login/oauth",  # enter oidc issuer
                "add",  # add key
                "Key PEM File",  # select key type
                "remove",  # remove key
                "my rsa key",  # select key to remove
                "continue",  # continue
                "Key PEM File",  # select Online Key type
                # selections for input_step4
                "JanisJoplin's Key",  # select key to sign
                "user@domain.com",  # select key to sign
                "continue",  # continue
            )
        )
        mocked_select = pretend.call_recorder(lambda *a: next(selection))
        monkeypatch.setattr(f"{_HELPERS}._select", mocked_select)
        fake_sigstore_signer = pretend.stub(
            from_priv_key_uri=lambda *a, **kw: pretend.stub(
                sign=lambda *a, **kw: Signature(
                    keyid="fake-keyid", sig="fake_sigstore"
                )
            )
        )
        monkeypatch.setattr(f"{_HELPERS}.SigstoreSigner", fake_sigstore_signer)

        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        input_step2 = [  # Configure Root Keys
            "2",  # Please enter root threshold
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "my rsa key",  # Please enter key name
            "user@domain.com",  # Please enter path to public key
            "",  # Please enter key name
            f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
            "JanisJoplin's Key",  # Please enter key name
        ]
        custom_path = "file.json"
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args=["--dry-run", "--out", custom_path],
        )

        {"keyid": "fake-keyid", "sig": "fake_sigstore"} in result.data[
            "metadata"
        ]["root"]["signatures"]
        assert f"Saved result to '{custom_path}'" in result.stdout
        assert "Bootstrap completed." not in result.stdout

    def test_ceremony_threshold_less_than_2(
        self,
        monkeypatch,
        ceremony_inputs,
        key_selection,
        patch_getpass,
        patch_utcnow,
    ):
        input_step1, _, input_step3, input_step4 = ceremony_inputs
        input_step2 = [  # Configure Root Keys
            "0",  # Please enter root threshold
            "1",  # Please enter root threshold
            "2",  # Please enter root threshold
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "my rsa key",  # Please enter key name
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            "JimiHendrix's Key",  # Please enter key name
            f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
            "JanisJoplin's Key",  # Please enter key name
        ]

        # public keys and signing keys selection options
        monkeypatch.setattr(f"{_HELPERS}._select", key_selection)

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            ["--dry-run"],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Please enter threshold above 1" in result.stdout

    def test_ceremony__non_positive_expiration(
        self,
        monkeypatch,
        ceremony_inputs,
        key_selection,
        patch_getpass,
        patch_utcnow,
    ):
        _, input_step2, input_step3, input_step4 = ceremony_inputs
        input_step1 = [  # Configure online role settings and root expiration
            "-1",  # Please enter days until expiry for timestamp role (1)
            "0",  # Please enter days until expiry for timestamp role (1)
            "",  # Please enter days until expiry for timestamp role (1)
            "",  # Please enter days until expiry for snapshot role (1)
            "",  # Please enter days until expiry for targets role (365)
            "",  # Please enter days until expiry for bins role (1)
            "4",  # Please enter number of delegated hash bins [2/4/8/16/32/64/128/256/512/1024/2048/4096/8192/16384] (256)  # noqa
            "",  # Please enter days until expiry for root role (365)
        ]
        # public keys and signing keys selection options
        monkeypatch.setattr(f"{_HELPERS}._select", key_selection)

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            ["--dry-run"],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Please enter a valid positive integer number" in result.stdout

    def test_ceremony_api_server(
        self,
        ceremony_inputs,
        key_selection,
        monkeypatch,
        patch_getpass,
        patch_utcnow,
        test_context,
    ):
        fake_task_id = "123ab"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(ceremony, "send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(ceremony, "task_status", fake_task_status)
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        test_context["settings"].SERVER = "http://localhost:80"
        # public keys and signing keys selection options
        monkeypatch.setattr(f"{_HELPERS}._select", key_selection)

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
            test_context,
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

        # One of the used key with id "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3"  # noqa
        # is an ecdsa type meaning it's not deterministic and have different
        # signature each run. That's why we do more granular check to work
        # around that limitation.
        call = fake_send_payload.calls[0]
        assert call.kwargs["settings"] == result.context["settings"]
        assert call.kwargs["url"] == ceremony.URL.BOOTSTRAP.value
        # The "payload" arg of fake_send_payload() calls is the same as
        # result.data which already has been verified.
        assert call.kwargs["expected_msg"] == "Bootstrap accepted."
        assert call.kwargs["command_name"] == "Bootstrap"
        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id, result.context["settings"], "Bootstrap status: "
            )
        ]
        assert "Ceremony done. 🔐 🎉. Bootstrap completed." in result.stdout

    def test_ceremony_api_server_with_out_option_custom_timeout(
        self,
        ceremony_inputs,
        key_selection,
        monkeypatch,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        fake_task_id = "123ab"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(ceremony, "send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(ceremony, "task_status", fake_task_status)
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        test_context["settings"].SERVER = "http://localhost:80"
        custom_path = "file.json"
        # public keys and signing keys selection options
        monkeypatch.setattr(f"{_HELPERS}._select", key_selection)
        timeout_e = 450

        result = invoke_command(
            ceremony.ceremony,
            inputs=input_step1 + input_step2 + input_step3 + input_step4,
            args=["--out", custom_path, "--timeout", timeout_e],
            test_context=test_context,
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")
        timeout_r = result.data.pop("timeout")
        # We don't want to use the default timeout, but a custom one.
        expected.pop("timeout")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert timeout_r == timeout_e
        assert result.data == expected

        # One of the used key with id "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3"  # noqa
        # is an ecdsa type meaning it's not deterministic and have different
        # signature each run. That's why we do more granular check to work
        # around that limitation.
        call = fake_send_payload.calls[0]
        assert call.kwargs["settings"] == test_context["settings"]
        assert call.kwargs["url"] == ceremony.URL.BOOTSTRAP.value
        # The "payload" arg of fake_send_payload() calls is the same as
        # result.data which already has been verified.
        assert call.kwargs["expected_msg"] == "Bootstrap accepted."
        assert call.kwargs["command_name"] == "Bootstrap"

        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id, test_context["settings"], "Bootstrap status: "
            )
        ]
        assert f"Saved result to '{custom_path}'" in result.stdout
        assert "Ceremony done. 🔐 🎉. Bootstrap completed." in result.stdout

    def test_ceremony_online_key_one_of_root_keys(
        self,
        monkeypatch,
        ceremony_inputs,
        patch_getpass,
        patch_utcnow,
    ):
        # Test that online key cannot be one of root key's.
        input_step1, input_step2, _, input_step4 = ceremony_inputs
        input_step3 = [  # Configure Online Key
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub'}",  # Please enter path to public key  # noqa
            "Online Key",  # Please enter a key name
        ]

        selection_options = iter(
            (
                # select delegation type
                "Bins (online key only)",
                # selections for input_step4
                "Key PEM File",  # select key type
                "add",  # add key
                "Key PEM File",  # select key type
                "add",  # add key
                "Key PEM File",  # select key type
                "remove",  # remove key
                "my rsa key",  # select key to remove
                "continue",  # continue
                # selections for input_step4
                "Key PEM File",  # select Online Key type
                "Key PEM File",  # select Online Key type
                "JimiHendrix's Key",  # select key to sign
                "JanisJoplin's Key",  # select key to sign
                "continue",  # continue
            )
        )
        # public keys and signing keys selection options
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            pretend.call_recorder(lambda *a: next(selection_options)),
        )

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            ["--dry-run"],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Key already in use." in result.stdout

    def test_ceremony_dry_run_with_server_config_set(
        self,
        monkeypatch,
        ceremony_inputs,
        key_selection,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        """
        Test that '--dry-run' is with higher priority than 'settings.SERVER'.
        """
        # public keys and signing keys selection options
        monkeypatch.setattr(f"{_HELPERS}._select", key_selection)
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        test_context["settings"].SERVER = "http://localhost:80"
        # We want to test when only "--dry-run" is used we will not save a file
        # locally and will not send payload to the API.
        # Given that "invoke_command" always saves a file, so the result can be
        # read we cannot use it.
        with client.isolated_filesystem():
            result = client.invoke(
                ceremony.ceremony,
                args=["--dry-run"],
                input="\n".join(
                    input_step1 + input_step2 + input_step3 + input_step4
                ),
                obj=test_context,
                catch_exceptions=False,
            )

        assert result.stderr == ""
        assert "Saved result to " not in result.stdout
        assert "Bootstrap completed." not in result.stdout


class TestCeremonyError:
    def test_ceremony_no_api_server_and_no_dry_run_option(self):
        result = invoke_command(ceremony.ceremony, [], [], std_err_empty=False)

        err_prefix = "Either '--api-server' admin option/'SERVER'"
        err_suffix = "or '--dry-run'"
        assert err_prefix in result.stderr
        assert err_suffix in result.stderr
