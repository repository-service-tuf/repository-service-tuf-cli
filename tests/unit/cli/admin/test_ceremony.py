import json

import pretend

from repository_service_tuf.cli.admin import ceremony
from tests.conftest import _PAYLOADS, _PEMS, invoke_command


class TestCeremony:
    def test_ceremony_with_custom_out(
        self,
        ceremony_inputs,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        custom_path = "file.json"
        with client.isolated_filesystem():
            result = client.invoke(
                ceremony.ceremony,
                args=["--out", custom_path],
                input="\n".join(
                    input_step1 + input_step2 + input_step3 + input_step4
                ),
                obj=test_context,
                catch_exceptions=False,
            )
            with open(custom_path) as f:
                result.data = json.load(f)

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

    def test_ceremony_threshold_less_than_2(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        input_step1, _, input_step3, input_step4 = ceremony_inputs
        input_step2 = [  # Configure Root Keys
            "0",  # Please enter root threshold
            "1",  # Please enter root threshold
            "2",  # Please enter root threshold
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "my rsa key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index  # noqa
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            "JimiHendrix's Key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index.  # noqa
            f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
            "JanisJoplin's Key",  # Please enter key name
            "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
        ]

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Please enter threshold above 1" in result.stdout

    def test_ceremony__non_positive_expiration(
        self, ceremony_inputs, patch_getpass, patch_utcnow
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

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
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
        monkeypatch,
        patch_getpass,
        patch_utcnow,
    ):
        status = {"data": {"bootstrap": False}}
        fake_bootstrap_status = pretend.call_recorder(lambda a: status)
        monkeypatch.setattr(
            ceremony, "bootstrap_status", fake_bootstrap_status
        )
        fake_task_id = "123ab"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(ceremony, "send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(ceremony, "task_status", fake_task_status)
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        args = ["--api-server", "http://localhost:80"]

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args,
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

        assert fake_bootstrap_status.calls == [
            pretend.call(result.context["settings"])
        ]
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

    def test_ceremony_api_server_with_out_option(
        self,
        ceremony_inputs,
        monkeypatch,
        client,
        test_context,
        patch_getpass,
        patch_utcnow,
    ):
        """Test case 3 using custom OUTPUT argument."""
        status = {"data": {"bootstrap": False}}
        fake_bootstrap_status = pretend.call_recorder(lambda a: status)
        monkeypatch.setattr(
            ceremony, "bootstrap_status", fake_bootstrap_status
        )
        fake_task_id = "123ab"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(ceremony, "send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(ceremony, "task_status", fake_task_status)
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        test_context["settings"].SERVER = "http://localhost:80"
        custom_path = "file.json"
        with client.isolated_filesystem():
            result = client.invoke(
                ceremony.ceremony,
                args=["--out", custom_path],
                input="\n".join(
                    input_step1 + input_step2 + input_step3 + input_step4
                ),
                obj=test_context,
                catch_exceptions=False,
            )
            assert result.stderr == ""
            with open(custom_path) as f:
                result.data = json.load(f)

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

        assert fake_bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]
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
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        # Test that online key cannot be one of root key's.
        input_step1, input_step2, _, input_step4 = ceremony_inputs
        input_step3 = [  # Configure Online Key
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub'}",  # Please enter path to public key  # noqa
            "Online Key",  # Please enter a key name
        ]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Key already in use." in result.stdout

    def test_ceremony_try_setting_root_keys_less_than_threshold(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        input_step1, _, input_step3, input_step4 = ceremony_inputs
        # After setting one key we are trying to continue with pressing "enter"
        # This wouldn't work as threshold is 2 and its required to set 2 keys.
        input_step2 = [  # Configure Root Keys
            "2",  # Please enter root threshold
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            "JimiHendrix's Key",  # Please enter key name
            # Try continuing even though threshold is not reached.
            "",  # Please press 0 to add key, or remove key by entering its index.  # noqa
            "0",  # Please press 0 to add key, or remove key by entering its index. # noqa
            f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
            "JanisJoplin's Key",  # Please enter key name
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
        ]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        # Asser that at least root_threshold number of public keys are added.
        root_role = result.data["metadata"]["root"]["signed"]["roles"]["root"]
        assert len(root_role["keyids"]) == root_role["threshold"]


class TestCeremonyError:
    def test_ceremony_no_api_server_and_no_output_option(
        self, client, test_context, ceremony_inputs
    ):
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        result = client.invoke(
            ceremony.ceremony,
            args=[],
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
            catch_exceptions=False,
        )

        assert "Either '--api-sever'/'SERVER'" in result.stderr

    def test_ceremony_bootstrap_api_server_locked_for_bootstrap(
        self, ceremony_inputs, monkeypatch
    ):
        status = {
            "data": {"bootstrap": True},
            "message": "Locked for bootstrap",
        }
        fake_bootstrap_status = pretend.call_recorder(lambda a: status)
        monkeypatch.setattr(
            ceremony, "bootstrap_status", fake_bootstrap_status
        )
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        args = ["--api-server", "http://localhost"]

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args,
            std_err_empty=False,
        )

        assert status["message"] in result.stderr
        assert fake_bootstrap_status.calls == [
            pretend.call(result.context["settings"])
        ]
