# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import json
import os
from datetime import datetime, timedelta

import pretend  # type: ignore
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin import metadata
from repository_service_tuf.helpers.api_client import URL


class TestMetadataUpdate:
    """Test the Ceremony Interaction"""

    def test_metadata_update_start(self, client, test_context):
        test_result = client.invoke(metadata.update, obj=test_context)
        assert test_result.exit_code == 1
        assert "Metadata Update" in test_result.output

    def test_metadata_update(self, client, test_context, md_update_input):
        input_step1, input_step2, input_step3, input_step4 = md_update_input

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

        root: Metadata[Root]
        with open("metadata-update-payload.json") as f:
            data = json.loads(f.read())
            root = Metadata.from_dict(data["metadata"]["root"])

        assert root.signed.roles["root"].threshold == 1

        # Verify the changes in the new root
        assert root.signed.version == 2

        expected = datetime.now() + timedelta(days=365)
        assert root.signed.expires.date() == expected.date()

        is_steven_key_found = False
        is_kairo_key_found = False
        for root_key_id in root.signed.roles["root"].keyids:
            root_key = root.signed.keys[root_key_id]
            if root_key.unrecognized_fields["name"] == "Steven's Key":
                is_steven_key_found = True
            elif root_key.unrecognized_fields["name"] == "Kairo's Key":
                is_kairo_key_found = True

        assert is_steven_key_found is True
        assert is_kairo_key_found is True
        online_key_id = root.signed.roles["timestamp"].keyids[0]
        online_key = root.signed.keys[online_key_id]
        assert online_key.unrecognized_fields["name"] == "New RSA Online Key"

    def test_md_update_no_key_names_given(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, _ = md_update_input

        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "y",  # Do you want to remove a key [y/n]
            "Martin's Key",  # Name/Tag/ID prefix of the key to remove
            "n",  # Do you want to remove a key [y/n]
            "y",  # Do you want to add a new key? [y/n]
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]
        input_step4 = [
            "y",  # Do you want to change the online key? [y/n]
            "rsa",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/online-rsa.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to change the online key? [y/n]
        ]

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

        root: Metadata[Root]
        with open("metadata-update-payload.json") as f:
            data = json.loads(f.read())
            root = Metadata.from_dict(data["metadata"]["root"])

        for root_key_id in root.signed.roles["root"].keyids:
            root_key = root.signed.keys[root_key_id]
            # Only "Steven's key" is left which existed from the initial root
            if root_key.unrecognized_fields.get("name") != "Steven's Key":
                assert root_key.unrecognized_fields.get("name") is None

        online_roles = ["timestamp", "snapshot", "targets"]
        for role in online_roles:
            keyid = root.signed.roles[role].keyids[0]
            key = root.signed.keys[keyid]
            assert key.unrecognized_fields.get("name") is None

    def test_metadata_update_no_root_changes(
        self, client, test_context, md_update_input
    ):
        input_step1, _, _, _ = md_update_input

        input_step2 = [
            "n"  # Do you want to extend the root's expiration? [y/n]  # noqa
        ]
        input_step3 = ["n"]  # Do you want to modify root keys? [y/n]
        input_step4 = ["n"]  # Do you want to change the online key? [y/n]

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "No file will be generated as no changes were made"
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

    def test_metadata_update_fail_loading_key(self, client, test_context):
        input_step1 = [
            "tests/files/root.json",  # File name or URL to the current root metadata  # noqa
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "non_existent",  # Enter the root`s private key path
            "foo",  # Enter the root`s private key password
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
        ]
        input_step2 = [
            "n"  # Do you want to extend the root's expiration? [y/n]  # noqa
        ]
        input_step3 = ["n"]  # Do you want to modify root keys? [y/n]
        input_step4 = ["n"]  # Do you want to change the online key? [y/n]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        expected_msg = "Failed loading key 0 of 1"
        assert expected_msg in test_result.output
        finish_msg = "No file will be generated as no changes were made"
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

    def test_metadata_update_authorize_wrong_key_info_and_retry(
        self, client, test_context, md_update_input
    ):
        _, input_step2, input_step3, input_step4 = md_update_input
        input_step1 = [
            "tests/files/root.json",  # File name or URL to the current root metadata  # noqa
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "non_existent",  # Enter the root`s private key path
            "foo",  # Enter the root`s private key password
            "y",  # Try again?
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

    def test_metadata_update_no_update_expiration(
        self, client, test_context, md_update_input
    ):
        input_step1, _, input_step3, input_step4 = md_update_input
        input_step2 = [
            "n",  # Do you want to extend the root's expiration? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        skipping_expiration_change_msg = "Skipping root expiration changes"
        assert skipping_expiration_change_msg in test_result.output

    def test_metadata_update_no_update_expired_expiration(
        self, client, test_context, monkeypatch, md_update_input
    ):
        fake_date = datetime(2050, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_date)
        )
        monkeypatch.setattr(
            "repository_service_tuf.cli.admin.metadata.datetime",
            fake_datetime,
        )
        input_step1, _, input_step3, input_step4 = md_update_input
        input_step2 = [
            "",  # Days to extend root's expiration starting from today (365)
            "y",  # New root expiration: YYYY-M-DD. Do you agree? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning_msg = "Root root has expired - expiration must be extend"
        assert warning_msg in test_result.output

    def test_metadata_update_no_update_expiration_negative(
        self, client, test_context, md_update_input
    ):
        input_step1, _, input_step3, input_step4 = md_update_input
        input_step2 = [
            "y",  # Do you want to extend the root's expiration? [y/n]
            "-1",  # Days to extend root's expiration starting from today (365)
            "",  # Days to extend root's expiration starting from today (365)
            "y",  # New root expiration: YYYY-M-DD. Do you agree? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        assert "Expiration extension must be at least 1" in test_result.output

    def test_metadata_update_no_root_keys_modification(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, input_step4 = md_update_input
        input_step3 = [
            "n",  # Do you want to modify root keys? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        assert "Skipping further root keys changes" in test_result.output

    def test_metadata_update_negative_threshold(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, input_step4 = md_update_input
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "-1",  # What should be the root role threshold?
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "n",  # Do you want to remove a key [y/n]
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        assert "Threshold must be at least 1" in test_result.output

    def test_metadata_update_key_removal_of_non_existent_key(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, input_step4 = md_update_input
        key_name = "none existent"
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "y",  # Do you want to remove a key [y/n]
            key_name,  # Name/Tag/ID prefix of the key to remove
            "n",  # Do you want to remove a key [y/n]
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        assert f"Failed: key {key_name} is not in root" in test_result.output

    def test_metadata_update_key_remove_all_keys(
        self, client, test_context, md_update_input
    ):
        # We are removing all keys, but then re-adding a key which was used by
        # the current trusted root. That's why the threshold check is passed
        # and the check for number of signing keys existing in trusted root
        # passes as well.
        input_step1, input_step2, _, input_step4 = md_update_input
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "y",  # Do you want to remove a key [y/n]
            "Martin's Key",  # Name/Tag/ID prefix of the key to remove
            "y",  # Do you want to remove a key [y/n]
            "Steven's Key",  # Name/Tag/ID prefix of the key to remove
            "y",  # Do you want to add a new key? [y/n]
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Kairo's Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        assert "No keys are left for removal." in test_result.output

    def test_metadata_update_add_keys_to_fulfill_threshold_requirement(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, _ = md_update_input
        # First set high threshold requirement not met by current keys amount
        # Second refuse to add any other keys and fail metadata update
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "2",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "n",  # Do you want to remove a key [y/n]
            "rsa",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/online-rsa.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Kairo's Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]
        # Don't change the online key as otherwise it will try to add a key
        # used in root.
        input_step4 = [
            "n",  # Do you want to change the online key? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning = "You must add 1 more key(s)"
        assert warning in test_result.output

    def test_metadata_update_remove_key_then_add_to_fulfill_threshold(
        self, client, test_context, md_update_input
    ):
        # Verify that if a key is removed, then another one must be added to
        # fulfill the threshold requirement
        input_step1, input_step2, _, _ = md_update_input
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "y",  # Do you want to remove a key [y/n]
            "Martin's Key",  # Name/Tag/ID prefix of the key to remove
            "n",  # Do you want to remove a key [y/n]
            "rsa",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/online-rsa.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Kairo's Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]
        # Don't change the online key as otherwise it will try to add a key
        # used in root.
        input_step4 = [
            "n",  # Do you want to change the online key? [y/n]
        ]
        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning = "You must add 1 more key(s)"
        assert warning in test_result.output

    def test_metadata_update_add_curr_online_key(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, input_step4 = md_update_input
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "n",  # Do you want to remove a key [y/n]
            "y",  # Do you want to add a new key? [y/n]
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/online.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Online Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning = "Failed: This is the current online key. Cannot be added"
        assert warning in test_result.output

    def test_metadata_update_add_used_key(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, _, input_step4 = md_update_input
        input_step3 = [
            "y",  # Do you want to modify root keys? [y/n]
            "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)  # noqa
            "n",  # Do you want to remove a key [y/n]
            "y",  # Do you want to add a new key? [y/n]
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JimiHendrix.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Steven's Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to add a new key? [y/n]
            "n",  # Do you want to modify root keys? [y/n]
        ]

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning = "Failed: Key is already used"
        assert warning in test_result.output

    def test_metadata_update_change_online_key_to_the_same(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, input_step3, _ = md_update_input
        input_step4 = [
            "y",  # Do you want to change the online key? [y/n]
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/online.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Online Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to change the online key? [y/n]
        ]

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning = "Failed: New online key and current match"
        assert warning in test_result.output

    def test_metadata_update_change_online_key_to_one_of_root_keys(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, input_step3, _ = md_update_input
        input_step4 = [
            "y",  # Do you want to change the online key? [y/n]
            "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "Online Root Key",  # [Optional] Give a name/tag to the key
            "n",  # Do you want to change the online key? [y/n]
        ]

        test_result = client.invoke(
            metadata.update,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        warning = "Failed: Key matches one of the root keys"
        assert warning in test_result.output


class TestMetadataUpdateOptions:
    """Test the metadata update command with options."""

    path = "repository_service_tuf.cli.admin.metadata"

    def test_metadata_update_auth_set_without_upload_server_ClickException(
        self, client, test_context
    ):
        test_context["settings"].AUTH = True
        test_result = client.invoke(
            metadata.update, "--upload", obj=test_context
        )
        assert test_result.exit_code == 1, test_result.output
        error_msg = "Requires '--upload-server' when using '--auth'."
        assert error_msg in test_result.output

    def test_metadata_update_send_payload_to_upload_server(
        self, client, test_context
    ):
        test_context["settings"].SERVER = "foo"
        metadata.load_payload = pretend.call_recorder(lambda *a: {"data": "а"})
        metadata.send_payload = pretend.call_recorder(lambda **kw: "task_id")
        metadata.task_status = pretend.call_recorder(lambda *a: None)

        result = client.invoke(metadata.update, "--upload", obj=test_context)
        finish_msg = "Existing payload metadata-update-payload.json sent"
        assert result.exit_code == 0
        assert finish_msg in result.output

        assert metadata.load_payload.calls == [
            pretend.call("metadata-update-payload.json"),
        ]
        assert metadata.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.metadata.value,
                payload={"data": "а"},
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update",
                token=test_context.get("token"),
            )
        ]
        assert metadata.task_status.calls == [
            pretend.call(
                "task_id", test_context["settings"], "Metadata Update status: "
            )
        ]

    def test_metadata_update_passing_current_root(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, input_step3, input_step4 = md_update_input

        # Remove answer to: "File name or URL to the current root metadata"
        input_step1 = input_step1[1:]

        test_result = client.invoke(
            metadata.update,
            ["--current-root-uri", "tests/files/root.json"],
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

    def test_metadata_update_custom_name_payload(
        self, client, test_context, md_update_input
    ):
        input_step1, input_step2, input_step3, input_step4 = md_update_input
        custom_payload = "custom_md_payload_name"
        test_result = client.invoke(
            metadata.update,
            ["--file", custom_payload],
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )
        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0

        # Verify that the file exists and is indeed a root metadata file.
        root: Metadata[Root]
        with open(custom_payload) as f:
            data = json.loads(f.read())
            root = Metadata.from_dict(data["metadata"]["root"])
            root.verify_delegate("root", root)

        os.remove(custom_payload)

    def test_metadata_update_full_upload_and_run_ceremony(
        self, client, test_context, md_update_input, monkeypatch
    ):
        input_step1, input_step2, input_step3, input_step4 = md_update_input
        # We won't be able to check generate_payload calls as the function
        # will be called from a RootInfo object we don't have access to.
        fake_generate_payload = pretend.call_recorder(
            lambda *a: {"data": "foo"}
        )
        monkeypatch.setattr(
            f"{self.path}.RootInfo.generate_payload", fake_generate_payload
        )
        metadata.send_payload = pretend.call_recorder(lambda **kw: "task_id")
        metadata.task_status = pretend.call_recorder(lambda *a: None)

        test_result = client.invoke(
            metadata.update,
            ["--upload", "--run-ceremony"],
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        finish_msg = "Ceremony done. 🔐 🎉. Root metadata update completed."
        assert finish_msg in test_result.output
        assert test_result.exit_code == 0
        assert metadata.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.metadata.value,
                payload={"data": "foo"},
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update",
                token=test_context.get("token"),
            )
        ]
        assert metadata.task_status.calls == [
            pretend.call(
                "task_id", test_context["settings"], "Metadata Update status: "
            )
        ]
