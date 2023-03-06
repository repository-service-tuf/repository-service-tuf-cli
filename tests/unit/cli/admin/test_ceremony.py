# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend  # type: ignore
import pytest

from repository_service_tuf.cli.admin import ceremony


class TestCeremonyFunctions:
    def test__key_already_in_use(self, test_setup):
        ceremony.setup = test_setup
        result = ceremony._key_already_in_use({"keyid": "ema"})
        assert result is False

    def test__key_already_in_use_exists_in_role(self, test_setup):
        test_setup.keys[ceremony.Roles.ROOT] = [
            ceremony.RSTUFKey(key={"keyid": "ema"})
        ]
        ceremony.setup = test_setup
        result = ceremony._key_already_in_use({"keyid": "ema"})
        assert result is True

    def test__key_already_in_use_exists_in_online_key(self, test_setup):
        test_setup.online_key = ceremony.RSTUFKey(key={"keyid": "ema"})

        ceremony.setup = test_setup
        result = ceremony._key_already_in_use({"keyid": "ema"})
        assert result is True

    def test__load_key(self, monkeypatch):
        monkeypatch.setattr(
            ceremony,
            "import_privatekey_from_file",
            pretend.call_recorder(lambda *a: {"keyid": "ema"}),
        )

        result = ceremony._load_key("/p/key", ceremony.KEY_TYPE_ED25519, "pwd")
        assert result == ceremony.RSTUFKey({"keyid": "ema"}, "/p/key", None)
        assert ceremony.import_privatekey_from_file.calls == [
            pretend.call("/p/key", ceremony.KEY_TYPE_ED25519, "pwd")
        ]

    def test__load_key_CryptoError(self, monkeypatch):
        monkeypatch.setattr(
            ceremony,
            "import_privatekey_from_file",
            pretend.raiser(ceremony.CryptoError("wrong password")),
        )

        result = ceremony._load_key("/p/key", ceremony.KEY_TYPE_ED25519, "pwd")
        assert result == ceremony.RSTUFKey(
            {},
            None,
            error=(
                ":cross_mark: [red]Failed[/]: wrong password Check the "
                "password, type, etc"
            ),
        )

    def test__load_key_OSError(self, monkeypatch):
        monkeypatch.setattr(
            ceremony,
            "import_privatekey_from_file",
            pretend.raiser(OSError("permission denied")),
        )
        result = ceremony._load_key("/p/key", ceremony.KEY_TYPE_ED25519, "pwd")
        assert result == ceremony.RSTUFKey(
            {}, None, error=":cross_mark: [red]Failed[/]: permission denied"
        )

    def test__send_bootstrap(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"
        ceremony.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        ceremony.request_server = pretend.call_recorder(
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

        result = ceremony._send_bootstrap(
            test_context["settings"], {"payload": "data"}
        )
        assert result == "task_id_123"
        assert ceremony.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                ceremony.URL.bootstrap.value,
                ceremony.Methods.post,
                {"payload": "data"},
                headers={"auth": "token"},
            )
        ]

    def test__send_bootstrap_not_202(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"
        ceremony.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        ceremony.request_server = pretend.call_recorder(
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

        with pytest.raises(ceremony.click.ClickException) as err:
            ceremony._send_bootstrap(
                test_context["settings"], {"payload": "data"}
            )

        assert "Error 200" in str(err)
        assert ceremony.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                ceremony.URL.bootstrap.value,
                ceremony.Methods.post,
                {"payload": "data"},
                headers={"auth": "token"},
            )
        ]

    def test__send_bootstrap_no_message(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"
        ceremony.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        ceremony.request_server = pretend.call_recorder(
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

        with pytest.raises(ceremony.click.ClickException) as err:
            ceremony._send_bootstrap(
                test_context["settings"], {"payload": "data"}
            )

        assert "No message available." in str(err)
        assert ceremony.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                ceremony.URL.bootstrap.value,
                ceremony.Methods.post,
                {"payload": "data"},
                headers={"auth": "token"},
            )
        ]

    def test__send_bootstrap_no_task_id(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"
        ceremony.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        ceremony.request_server = pretend.call_recorder(
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

        with pytest.raises(ceremony.click.ClickException) as err:
            ceremony._send_bootstrap(
                test_context["settings"], {"payload": "data"}
            )

        assert "Failed to get `task id`" in str(err)
        assert ceremony.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                ceremony.URL.bootstrap.value,
                ceremony.Methods.post,
                {"payload": "data"},
                headers={"auth": "token"},
            )
        ]

    def test__send_bootstrap_no_data(self, test_context):
        test_context["settings"].SERVER = "http://fake-rstuf"
        ceremony.get_headers = pretend.call_recorder(
            lambda *a: {"auth": "token"}
        )
        ceremony.request_server = pretend.call_recorder(
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

        with pytest.raises(ceremony.click.ClickException) as err:
            ceremony._send_bootstrap(
                test_context["settings"], {"payload": "data"}
            )

        assert "Failed to get task response data" in str(err)
        assert ceremony.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert ceremony.request_server.calls == [
            pretend.call(
                test_context["settings"].SERVER,
                ceremony.URL.bootstrap.value,
                ceremony.Methods.post,
                {"payload": "data"},
                headers={"auth": "token"},
            )
        ]

    def test__load_bootstrap_payload(self, monkeypatch):
        fake_data = [
            pretend.stub(read=pretend.call_recorder(lambda: b"{'k': 'v'}"))
        ]
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: fake_data),
        )
        monkeypatch.setitem(
            ceremony.__builtins__, "open", lambda *a: fake_file_obj
        )
        ceremony.json.load = pretend.call_recorder(lambda *a: {"k": "v"})

        result = ceremony._load_bootstrap_payload("new_file")
        assert result == {"k": "v"}
        assert ceremony.json.load.calls == [pretend.call(fake_data)]

    def test__load_bootstrap_payload_OSError(self, monkeypatch):
        monkeypatch.setitem(
            ceremony.__builtins__,
            "open",
            pretend.raiser(FileNotFoundError("payload.json not found")),
        )
        with pytest.raises(ceremony.click.ClickException) as err:
            ceremony._load_bootstrap_payload("payload.json")

        assert "Error to load payload.json" in str(err)
        assert "payload.json not found" in str(err)

    def test__save_bootstrap_payload(self, monkeypatch):
        fake_data = pretend.stub(
            write=pretend.call_recorder(lambda *a: "{'k': 'v'}")
        )
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            write=pretend.call_recorder(lambda: fake_data),
        )
        monkeypatch.setitem(
            ceremony.__builtins__, "open", lambda *a: fake_file_obj
        )
        monkeypatch.setattr(
            ceremony.json,
            "dumps",
            pretend.call_recorder(lambda *a, **kw: "{'k': 'v'}"),
        )

        result = ceremony._save_bootstrap_payload("new_file", {"k": "v"})
        assert result is None
        assert ceremony.json.dumps.calls == [
            pretend.call({"k": "v"}, indent=2)
        ]

    def test__save_bootstrap_payload_OSError(self, monkeypatch):
        monkeypatch.setitem(
            ceremony.__builtins__,
            "open",
            pretend.raiser(PermissionError("permission denied")),
        )
        with pytest.raises(ceremony.click.ClickException) as err:
            ceremony._save_bootstrap_payload("payload.json", {"k": "v"})

        assert "Failed to save payload.json" in str(err)
        assert "permission denied" in str(err)


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
        input_step1, input_step2, _, _ = test_inputs
        # overwrite step 1:
        # >Ready to start loading the keys? Passwords will be required for keys
        input_step1[-1] = "n"
        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(input_step1 + input_step2),
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
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 0, test_result.output
        assert "Ceremony done. 🔐 🎉." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_key_bad_input_try_again_yes(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the input_step2
        input_step2 = [
            "",  # Choose 1/1 ONLINE key type [ed25519/ecdsa/rsa]
            "tests/files/online.key",  # Enter 1/1 the ONLINE`s private key path  # noqa
            "wrong password",  # Enter 1/1 the ONLINE`s private key password
            "y",  # Try again?
            "",  # Choose 1/1 ONLINE key type [ed25519/ecdsa/rsa]
            "tests/files/online.key",  # Enter 1/1 the ONLINE`s private key path  # noqa
            "strongPass",  # Enter 1/1 the ONLINE`s private key password
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

    def test_ceremony_key_bad_input_try_again_no(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the input_step2
        input_step2 = [
            "",  # Choose 1/1 ONLINE Key type [ed25519/ecdsa/rsa]
            "tests/files/online.key",  # Enter 1/1 the ONLINE`s private key path  # noqa
            "wrong password",  # Enter 1/1 the ONLINE`s private key password
            "n",  # Try again?
        ]

        test_result = client.invoke(
            ceremony.ceremony,
            input="\n".join(
                input_step1 + input_step2 + input_step3 + input_step4
            ),
            obj=test_context,
        )

        assert test_result.exit_code == 1, test_result.output
        assert "Required key not validated." in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_key_duplicated_try_again_yes(
        self, client, test_context, test_inputs, test_setup
    ):
        ceremony.setup = test_setup
        input_step1, input_step2, input_step3, input_step4 = test_inputs

        # overwrite the input_step3 with same key in input_step2 (online key)
        input_step3 = [
            "",  # Choose 1/2 root key type [ed25519/ecdsa/rsa]
            "tests/files/online.key",  # Enter 1/2 the root`s private key path
            "strongPass",  # Enter 1/2 the root`s private key password
            "",  # Choose 1/2 root key type [ed25519/ecdsa/rsa]
            "tests/files/JanisJoplin.key",  # Enter 1/2 the root`s private key path  # noqa
            "strongPass",  # Enter 1/2 the root`s private key password
            "",  # Choose 2/2 root key type [ed25519/ecdsa/rsa]
            "tests/files/JimiHendrix.key",  # Enter 2/2 the root`s private key path  # noqa
            "strongPass",  # Enter 2/2 the root`s private key password:
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
            "tests/files/online-rsa.key",  # Enter 1/1 the ONLINE`s private key path  # noqa
            "strongPass",  # Enter 1/1 the ONLINE`s private key password
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
            "tests/files/JanisJoplin.key",  # Enter 1/1 the root`s private key path  # noqa
            "strongPass",  # Enter 1/2 the root`s private key password
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
        ceremony._save_bootstrap_payload = pretend.call_recorder(
            lambda *a: None
        )

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
        assert ceremony._save_bootstrap_payload.calls == [
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
        ceremony._send_bootstrap = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        ceremony._run_ceremony_steps = pretend.call_recorder(
            lambda *a: {"k": "v"}
        )
        ceremony._save_bootstrap_payload = pretend.call_recorder(
            lambda *a: None
        )
        ceremony.task_status = pretend.call_recorder(lambda *a: None)

        test_result = client.invoke(
            ceremony.ceremony,
            "--bootstrap",
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
        assert ceremony._send_bootstrap.calls == [
            pretend.call(test_context["settings"], {"k": "v"})
        ]
        assert ceremony._run_ceremony_steps.calls == [pretend.call(False)]
        assert ceremony._save_bootstrap_payload.calls == [
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
            "--bootstrap",
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
        ceremony._load_bootstrap_payload = pretend.call_recorder(
            lambda *a: {"k": "v"}
        )
        ceremony._send_bootstrap = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        ceremony.task_status = pretend.call_recorder(lambda *a: None)

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
        assert ceremony._load_bootstrap_payload.calls == [
            pretend.call("payload.json")
        ]
        assert ceremony._send_bootstrap.calls == [
            pretend.call(test_context["settings"], {"k": "v"})
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
