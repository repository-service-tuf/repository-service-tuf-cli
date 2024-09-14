# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from datetime import datetime, timedelta, timezone

import pretend
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin.metadata import update
from tests.conftest import _HELPERS, _PAYLOADS, _PEMS, _ROOTS, invoke_command

MOCK_PATH = "repository_service_tuf.cli.admin.metadata.update"


class TestMetadataUpdate:
    def test_update_input_dry_run(
        self, monkeypatch, update_inputs, update_key_selection, patch_getpass
    ):
        args = ["--in", f"{_ROOTS / 'v1.json'}", "--dry-run"]
        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", update_key_selection)

        result = invoke_command(update.update, update_inputs, args)

        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

    def test_update_input_and_server(
        self,
        monkeypatch,
        update_inputs,
        update_key_selection,
        test_context,
        patch_getpass,
    ):
        fake_task_id = "123a"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(f"{MOCK_PATH}.send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(f"{MOCK_PATH}.task_status", fake_task_status)
        test_context["settings"].SERVER = "http://localhost:80"
        args = ["--in", f"{_ROOTS / 'v1.json'}"]

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", update_key_selection)

        result = invoke_command(
            update.update, update_inputs, args, test_context
        )

        with open(_PAYLOADS / "update.json") as f:
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
        assert call.kwargs["url"] == update.URL.METADATA.value
        # The "payload" arg of fake_send_payload() calls is the same as
        # result.data which already has been verified.
        assert call.kwargs["expected_msg"] == "Metadata update accepted."
        assert call.kwargs["command_name"] == "Metadata Update"
        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id,
                test_context["settings"],
                "Metadata Update status: ",
            )
        ]
        assert "Root metadata update completed." in result.stdout

    def test_update_metadata_url_and_server(
        self,
        monkeypatch,
        update_inputs,
        update_key_selection,
        test_context,
        patch_getpass,
    ):
        root_md = Metadata.from_file(f"{_ROOTS / 'v1.json'}")
        fake__get_latest_md = pretend.call_recorder(lambda *a: root_md)
        monkeypatch.setattr(f"{MOCK_PATH}._get_latest_md", fake__get_latest_md)
        fake_task_id = "123a"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(f"{MOCK_PATH}.send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(f"{MOCK_PATH}.task_status", fake_task_status)
        fake_url = "http://fake-server/1.root.json"
        test_context["settings"].SERVER = "http://localhost:80"
        args = ["--metadata-url", fake_url]

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", update_key_selection)

        result = invoke_command(
            update.update, update_inputs, args, test_context
        )

        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert fake__get_latest_md.calls == [pretend.call(fake_url, Root.type)]
        # One of the used key with id "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3"  # noqa
        # is an ecdsa type meaning it's not deterministic and have different
        # signature each run. That's why we do more granular check to work
        # around that limitation.
        call = fake_send_payload.calls[0]
        assert call.kwargs["settings"] == result.context["settings"]
        assert call.kwargs["url"] == update.URL.METADATA.value
        # The "payload" arg of fake_send_payload() calls is the same as
        # result.data which already has been verified.
        assert call.kwargs["expected_msg"] == "Metadata update accepted."
        assert call.kwargs["command_name"] == "Metadata Update"
        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id,
                test_context["settings"],
                "Metadata Update status: ",
            )
        ]
        assert "Root metadata update completed. 🔐 🎉" in result.stdout

    def test_update_metadata_url_dry_run(
        self, monkeypatch, update_inputs, update_key_selection, patch_getpass
    ):
        root_md = Metadata.from_file(f"{_ROOTS / 'v1.json'}")
        fake__get_latest_md = pretend.call_recorder(lambda *a: root_md)
        monkeypatch.setattr(f"{MOCK_PATH}._get_latest_md", fake__get_latest_md)
        fake_url = "http://fake-server/1.root.json"
        args = ["--metadata-url", fake_url, "--dry-run"]

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", update_key_selection)

        result = invoke_command(update.update, update_inputs, args)

        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert fake__get_latest_md.calls == [pretend.call(fake_url, Root.type)]

    def test_update_metadata_url_and_input_file(
        self, monkeypatch, update_inputs, update_key_selection, patch_getpass
    ):
        """Test that '--metadata-url' is with higher priority than '--in'."""
        root_md = Metadata.from_file(f"{_ROOTS / 'v1.json'}")
        fake__get_latest_md = pretend.call_recorder(lambda *a: root_md)
        monkeypatch.setattr(f"{MOCK_PATH}._get_latest_md", fake__get_latest_md)
        fake_url = "http://fake-server/1.root.json"
        args = [
            "--metadata-url",
            fake_url,
            "--in",
            f"{_ROOTS / 'v1.json'}",
            "--dry-run",
        ]

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", update_key_selection)

        result = invoke_command(update.update, update_inputs, args)

        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert fake__get_latest_md.calls == [pretend.call(fake_url, Root.type)]
        assert "Latest root version found" in result.stdout

    def test_update_dry_run_with_server_config_set(
        self,
        monkeypatch,
        update_inputs,
        update_key_selection,
        test_context,
        client,
        patch_getpass,
    ):
        """
        Test that '--dry-run' is with higher priority than 'settings.SERVER'.
        """
        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", update_key_selection)
        args = ["--in", f"{_ROOTS / 'v1.json'}", "--dry-run"]
        test_context["settings"].SERVER = "http://localhost:80"
        # We want to test when only "--dry-run" is used we will not save a file
        # locally and will not send payload to the API.
        # Given that "invoke_command" always saves a file, so the result can be
        # read we cannot use it.
        with client.isolated_filesystem():
            result = client.invoke(
                update.update,
                args=args,
                input="\n".join(update_inputs),
                obj=test_context,
                catch_exceptions=False,
            )

        assert result.stderr == ""
        assert "Saved result to " not in result.stdout
        assert "Bootstrap completed." not in result.stdout

    def test_update_change_expiration_and_threshold(
        self, monkeypatch, patch_getpass
    ):
        future_date = datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        fake_replace = pretend.stub(
            replace=pretend.call_recorder(lambda **kw: future_date)
        )
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda *a: fake_replace)
        )
        additional_days = 365

        monkeypatch.setattr(f"{_HELPERS}.datetime", fake_datetime)

        inputs = [
            "y",  # Do you want to change the expiry date? [y/n] (y)
            f"{additional_days}",  # Please enter days until expiry for root role  # noqa
            "y",  # Do you want to change the threshold? [y/n] (n)
            "3",  # "Please enter root threshold"
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "JoeCocker's Key",  # Please enter a key name
            "y",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'cb20fa1061dde8e6267e0bef0981766aaadae168e917030f7f26edc7a0bab9c2.pub'}",  # Please enter path to public key  # noqa
            "New Online Key",  # Please enter a key name
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JJ.ecdsa'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JC.rsa'}",  # Please enter path to encrypted private key  # noqa
        ]
        args = ["--in", f"{_ROOTS / 'v1.json'}", "--dry-run"]

        # selections interface
        selection_options = iter(
            (
                # selection for inputs (update root keys)
                "add",  # remove key
                "Key PEM File",  # select key type
                "continue",  # continue
                "Key PEM File",  # select key type
                # selection for inputs (signing root key)
                "JimiHendrix's Key",  # select key to sign
                "JanisJoplin's Key",  # select key to sign
                "JoeCocker's Key",  # select key to sign
                "continue",  # continue
            )
        )
        mocked_select = pretend.call_recorder(
            lambda *a: next(selection_options)
        )

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", mocked_select)

        result = invoke_command(update.update, inputs, args)

        exp_date = future_date + timedelta(days=additional_days)
        res_root = result.data["metadata"]["root"]["signed"]
        # Make sure new expiration is the same as expected.
        assert res_root["expires"] == exp_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Make sure new threshold is the same .
        assert res_root["roles"]["root"]["threshold"] == 3


class TestUpdateError:
    def test_update_no_input_or_metadata_url(self):
        result = invoke_command(update.update, [], [], std_err_empty=False)
        assert "Either '--in' or '--metadata-url' needed" in result.stderr

    def test_update_no_server_config_or_dry_run(self):
        args = ["--in", f"{_ROOTS / 'v1.json'}"]
        result = invoke_command(update.update, [], args, std_err_empty=False)

        err_prefix = "Either '--api-server' admin option/'SERVER'"
        err_suffix = "or '--dry-run'"
        assert err_prefix in result.stderr
        assert err_suffix in result.stderr
