# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend  # type: ignore

from repository_service_tuf.cli.admin import ceremony
from repository_service_tuf.helpers.api_client import URL


class TestCeremonyFunctions:
    def test__key_already_in_use(self, test_setup):
        ceremony.setup = test_setup
        result = ceremony._key_already_in_use({"keyid": "ema"})
        assert result is False

    def test__key_already_in_use_exists_in_role(self, test_setup):
        test_setup.root_keys["ema"] = ceremony.RSTUFKey(key={"keyid": "ema"})
        ceremony.setup = test_setup
        result = ceremony._key_already_in_use({"keyid": "ema"})
        assert result is True

    def test__key_already_in_use_exists_in_online_key(self, test_setup):
        test_setup.online_key = ceremony.RSTUFKey(key={"keyid": "ema"})

        ceremony.setup = test_setup
        result = ceremony._key_already_in_use({"keyid": "ema"})
        assert result is True


class TestCeremonyInteraction:
    """Test the Ceremony Interaction"""

    def test_ceremony(self, client, test_context):
        test_result = client.invoke(ceremony.ceremony, obj=test_context)
        assert test_result.exit_code == 1
        assert (
            "Repository Metadata and Settings for the Repository Service "
            "for TUF"
        ) in test_result.output

    def test_ceremony_start_no(self, client, test_context, test_inputs):
        input_step1, _, _, _ = test_inputs
        # overwrite step 1
        # >Do you want to start the ceremony?
        input_step1[1] = "n"

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(input_step1),
            obj=test_context,
        )
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_not_ready_load_the_keys(
        self, client, test_context, test_inputs
    ):
        input_step1, input_step2, input_step3, _ = test_inputs
        # overwrite step 1:
        # >Ready to start loading the keys?
        input_step3[0] = "n"
        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(input_step1 + input_step2 + input_step3),
            obj=test_context,
        )
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_default_values(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        test_result = client.invoke(
            ceremony.ceremony,
            "--save",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_using_root_key2_public_key(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, _, input_step4 = test_inputs

        input_step3 = [
            "y",  # Ready to start loading the root keys? [y/n]
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
            "",  # Select to use private key or public? [private/public] (public)  # noqa
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "fake_id",  # # Enter root`s key id
            "fake_hash",  # Enter root`s public key hash
            "root key 2",  # Give a name/tag to the key [Optional]
            "",
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            "--save",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_using_root_key2_public_key_empty_retry(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, _, input_step4 = test_inputs

        input_step3 = [
            "y",  # Ready to start loading the root keys? [y/n]
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
            "",  # Select to use private key or public? [private/public] (public)  # noqa
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "",  # # Enter root`s key id
            "fake_id",  # # Enter root`s key id
            "",  # Enter root`s public key hash
            "fake_hash",  # Enter root`s public key hash
            "",  # Give a name/tag to the key [Optional]
            "",
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            "--save",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_negative_expiry_and_try_again(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs
        # Adding two additional questions for root expiry because the last
        # given values for the root expiration are below 1.
        input_step1 = [
            "y",  # Do you want more information about roles and responsibilities?  # noqa
            "y",  # Do you want to start the ceremony?
            "-1",  # What is the metadata expiration for the root role?(Days)
            "0",  # What is the metadata expiration for the root role?(Days)
            "",  # What is the metadata expiration for the root role?(Days)
            "",  # What is the number of keys for the root role? (2)
            "",  # What is the key threshold for root role signing?
            "",  # What is the metadata expiration for the targets role?(Days) (365)?  # noqa
            "y",  # Show example?
            "16",  # Choose the number of delegated hash bin roles
            "http://www.example.com/repository",  # What is the targets base URL  # noqa
            "",  # What is the metadata expiration for the snapshot role?(Days) (365)?  # noqa
            "",  # What is the metadata expiration for the timestamp role?(Days) (365)?  # noqa
            "",  # What is the metadata expiration for the bins role?(Days) (365)?  # noqa
            "Y",  # Ready to start loading the keys? Passwords will be required for keys [y/n]  # noqa
        ]
        test_result = client.invoke(
            ceremony.ceremony,
            "--save",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_key_bad_input_try_again(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the input_step2
        input_step3 = [
            "y",  # Ready to start loading the root keys? [y/n]
            "",  # Select the root`s key type [ed25519/ecdsa/rsa]
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "wrong password",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
            "private",  # Select to use private key or public? [private/public] (public)  # noqa
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/JimiHendrix.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_key_with_name(
        self, client, test_context, test_inputs, test_setup
    ):
        # Test a case when the user gives custom names to the keys.
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # update all: Give a name/tag to the key [Optional]
        input_step2[-1] = "Online key"
        input_step3[4] = "Martin's Key"
        input_step3[9] = "Steven's Key"

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_key_duplicated_try_again_yes(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the input_step3 with same key in input_step2 (online key)
        input_step3 = [
            "y",  # Ready to start loading the root keys? [y/n]
            "",  # Select the root`s key type [ed25519/ecdsa/rsa] (ed25519)
            "tests/files/key_storage/online.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
            "",  # Choose 1/2 root key type [ed25519/ecdsa/rsa]
            "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
            "private",  # Select to use private key or public? [private/public] (public)  # noqa
            "",  # Choose 2/2 root key type [ed25519/ecdsa/rsa]
            "tests/files/key_storage/JimiHendrix.key",  # Enter the root`s private key path  # noqa
            "strongPass",  # Enter the root`s private key password
            "",  # Give a name/tag to the key [Optional]
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_validation_reconfigure_online_key(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the step 4
        # Say online key configuration is not correct, update with online-ecdsa
        # key and confirm the configuration
        input_step4 = [
            "n",  # Is the online key configuration correct? [y/n]
            "rsa",  # Choose 1/1 ONLINE key type [ed25519/ecdsa/rsa]
            "tests/files/key_storage/online-rsa.key",  # Enter 1/1 the ONLINE`s private key path  # noqa
            "strongPass",  # Enter 1/1 the ONLINE`s private key password
            "",  # [Optional] Give a name/tag to the key
            "y",  # Is the online key configuration correct? [y/n]
            "y",  # Is the root configuration correct? [y/n]
            "y",  # Is the targets configuration correct? [y/n]
            "y",  # Is the snapshot configuration correct? [y/n]
            "y",  # Is the timestamp configuration correct? [y/n]
            "y",  # Is the bins configuration correct? [y/n]
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_validation_reconfigure_root_keys(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the step 4
        # Say root configuration is not correct, change it to 1 key (it will
        # define the threshold automatically as 1), insert new key settings
        # and confirm the configuration
        input_step4 = [
            "y",  # Is the online key configuration correct? [y/n]
            "n",  # Is the root configuration correct? [y/n]
            "",  # What is the metadata expiration for the root role?(Days)
            "1",  # What is the number of keys for the root role? (2)
            "",  # Choose 1/1 root key type [ed25519/ecdsa/rsa]
            "tests/files/key_storage/JanisJoplin.key",  # Enter 1/1 the root`s private key path  # noqa
            "strongPass",  # Enter 1/2 the root`s private key password
            "",  # [Optional] Give a name/tag to the key
            "y",  # Is the root configuration correct? [y/n]
            "y",  # Is the targets configuration correct? [y/n]
            "y",  # Is the snapshot configuration correct? [y/n]
            "y",  # Is the timestamp configuration correct? [y/n]
            "y",  # Is the bins configuration correct? [y/n]
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output


class TestCeremonyOptions:
    """Test the options"""

    def test_ceremony_option_save(
        self, client, test_context, test_inputs, test_setup, monkeypatch
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        monkeypatch.setattr(
            ceremony,
            "os",
            pretend.stub(
                makedirs=pretend.call_recorder(lambda *a, **kw: None)
            ),
        )

        # mock ceremony process steps.
        # the process is tested in previous the test
        ceremony._run_ceremony_steps = pretend.call_recorder(
            lambda *a: {"k": "v"}
        )
        ceremony.save_payload = pretend.call_recorder(lambda *a: None)

        test_result = client.invoke(
            ceremony.ceremony,
            "--save",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        assert "Bootstrap payload (payload.json) saved." in test_result.output
        assert ceremony.os.makedirs.calls == [
            pretend.call("metadata", exist_ok=True)
        ]
        assert ceremony._run_ceremony_steps.calls == [pretend.call(True)]
        assert ceremony.save_payload.calls == [
            pretend.call("payload.json", {"k": "v"})
        ]

    def test_ceremony_option_save_OSError(
        self, client, test_context, test_inputs, test_setup, monkeypatch
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        monkeypatch.setattr(
            ceremony,
            "os",
            pretend.stub(
                makedirs=pretend.raiser(PermissionError("permission denied"))
            ),
        )

        test_result = client.invoke(
            ceremony.ceremony,
            "--save",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 1, test_result.output
        assert "permission denied" in test_result.output

    def test_ceremony_option_bootstrap(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        ceremony.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": False}}
        )
        ceremony.send_payload = pretend.call_recorder(
            lambda **kw: "fake_task_id"
        )
        ceremony._run_ceremony_steps = pretend.call_recorder(
            lambda *a: {"k": "v"}
        )
        ceremony.save_payload = pretend.call_recorder(lambda *a: None)
        ceremony.task_status = pretend.call_recorder(lambda *a: None)

        test_result = client.invoke(
            ceremony.ceremony,
            ["--bootstrap", "--upload-server", "http://fake-api"],
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        assert "Bootstrap completed." in test_result.output
        assert ceremony.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.bootstrap.value,
                payload={"k": "v"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )
        ]
        assert ceremony._run_ceremony_steps.calls == [pretend.call(False)]
        assert ceremony.save_payload.calls == [
            pretend.call("payload.json", {"k": "v"})
        ]
        assert ceremony.task_status.calls == [
            pretend.call(
                "fake_task_id", test_context["settings"], "Bootstrap status: "
            )
        ]

    def test_ceremony_option_bootstrap_server_already_bootstrap(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        ceremony.bootstrap_status = pretend.call_recorder(
            lambda *a: {
                "data": {"bootstrap": True},
                "message": "System LOCKED for bootstrap",
            }
        )

        test_result = client.invoke(
            ceremony.ceremony,
            ["--bootstrap", "--upload-server", "http://fake-api"],
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 1, test_result.output
        assert "System LOCKED for bootstrap" in test_result.output
        assert ceremony.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]

    def test_ceremony_option_bootstrap_upload(self, client, test_context):
        ceremony.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": False}}
        )
        ceremony.load_payload = pretend.call_recorder(lambda *a: {"k": "v"})
        ceremony.send_payload = pretend.call_recorder(
            lambda **kw: "fake_task_id"
        )
        ceremony.task_status = pretend.call_recorder(lambda *a: None)

        test_result = client.invoke(
            ceremony.ceremony,
            ["--bootstrap", "--upload", "--upload-server", "http://fake-api"],
            input=None,
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert (
            "Bootstrap completed using `payload.json`. 🔐 🎉"
            in test_result.output
        )
        assert ceremony.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.load_payload.calls == [pretend.call("payload.json")]
        assert ceremony.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.bootstrap.value,
                payload={"k": "v"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )
        ]
        assert ceremony.task_status.calls == [
            pretend.call(
                "fake_task_id", test_context["settings"], "Bootstrap status: "
            )
        ]
        # test regression https://github.com/repository-service-tuf/repository-service-tuf-cli/pull/259  # noqa
        assert test_context["settings"].SERVER is not None

    def test_ceremony_option_bootstrap_upload_missing_upload_server(
        self, client, test_context
    ):
        test_result = client.invoke(
            ceremony.ceremony,
            ["--bootstrap", "--upload"],
            input=None,
            obj=test_context,
        )

        assert test_result.exit_code == 1, test_result.output
        assert "Requires '--upload-server'" in test_result.output

    def test_ceremony_option_bootstrap_upload_auth(self, client, test_context):
        ceremony.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": False}}
        )
        ceremony.load_payload = pretend.call_recorder(lambda *a: {"k": "v"})
        ceremony.send_payload = pretend.call_recorder(
            lambda **kw: "fake_task_id"
        )
        ceremony.task_status = pretend.call_recorder(lambda *a: None)

        test_context["settings"].AUTH = True
        test_context["settings"].SERVER = "http://fake-api"

        test_result = client.invoke(
            ceremony.ceremony,
            ["--bootstrap", "--upload"],
            input=None,
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert (
            "Bootstrap completed using `payload.json`. 🔐 🎉"
            in test_result.output
        )
        assert ceremony.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.load_payload.calls == [pretend.call("payload.json")]
        assert ceremony.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.bootstrap.value,
                payload={"k": "v"},
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )
        ]
        assert ceremony.task_status.calls == [
            pretend.call(
                "fake_task_id", test_context["settings"], "Bootstrap status: "
            )
        ]

    def test_ceremony_option_upload_missing_bootstrap(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        ceremony.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": False}}
        )
        test_result = client.invoke(
            ceremony.ceremony,
            "--upload",
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 1, test_result.output
        assert "Requires '-b/--bootstrap' option." in test_result.output
