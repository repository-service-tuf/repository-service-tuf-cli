# SPDX-License-Identifier: MIT


import pretend

from repository_service_tuf.cli.artifact import repository

WRITE_CONFIG_SRC_PATH = (
    "repository_service_tuf.cli.artifact.repository.write_config"
)


class TestArtifactRepositoryInteraction:
    """Test the artifact repository command interaction"""

    def test_repository_show_all(self, client, test_context, test_setup):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        test_context["settings"] = config
        test_result = client.invoke(
            repository.show,
            obj=test_context,
        )
        assert "r1" in test_result.output
        assert "r2" in test_result.output
        assert test_result.exit_code == 0

    def test_repository_show_one(self, client, test_context, test_setup):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        test_context["settings"] = config
        test_result = client.invoke(
            repository.show,
            ["r1"],
            obj=test_context,
        )
        assert "r1" in test_result.output
        assert "r2" not in test_result.output
        assert (
            '"artifact_base_url": "http://localhost:8081"'
            in test_result.output
        )
        assert '"hash_prefix": "False"' in test_result.output
        assert '"metadata_url": "http://localhost:8080"' in test_result.output
        assert '"trusted_root": ' in test_result.output
        assert '"some_root"' in test_result.output
        assert test_result.exit_code == 0

    def test_repository_show_current(self, client, test_context, test_setup):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        test_context["settings"] = config
        test_result = client.invoke(
            repository.show,
            ["r1"],
            obj=test_context,
        )
        assert "CURRENT REPOSITORY:" in test_result.output
        assert "r1" in test_result.output
        assert "r2" not in test_result.output
        assert test_result.exit_code == 0

    def test_repository_show_wrong_data_type(
        self, client, test_context, test_setup
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "wrong_root_type",
            "REPOSITORIES": {
                "wrong_root_type": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": b"! d @ jsahkfv",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        test_context["settings"] = config
        test_result = client.invoke(
            repository.show,
            ["wrong_root_type"],
            obj=test_context,
        )
        assert (
            "Repository wrong_root_type has incorrect configuration."
            in test_result.output
        )
        assert test_result.exit_code == 1

    def test_repository_show_no_repos(self, client, test_context, test_setup):
        repository.setup = test_setup

        test_result = client.invoke(
            repository.show,
            obj=test_context,
        )
        assert "There are no configured repositories" in test_result.output
        assert test_result.exit_code == 1

        test_result = client.invoke(
            repository.show,
            ["r1"],
            obj=test_context,
        )
        assert (
            "Repository r1 is missing in your configuration"
            in test_result.output
        )
        assert test_result.exit_code == 1

    def test_repository_set(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup
        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()

        assert check_settings["CURRENT_REPOSITORY"] == "r1"

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.set,
            ["r2"],
            obj=test_context,
        )

        assert "Current repository changed to r2" in test_result.output
        check_settings = test_context["settings"].as_dict()
        assert check_settings.get("CURRENT_REPOSITORY") == "r2"
        assert test_result.exit_code == 0

    def test_repository_add_one_param_only(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": b"ZXhhbXBsZV9wYXRoX3RvX3Jvb3Qvcm9vdC5qc29u",  # noqa
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": b"ZXhhbXBsZV9wYXRoX3RvX3Jvb3Qvcm9vdC5qc29u",  # noqa
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()
        assert "r3" not in check_settings["REPOSITORIES"]

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.add,
            ["-n", "r3", "-r", "example_path_to_root/root.json"],
            obj=test_context,
        )

        assert test_result.exit_code == 2
        assert "Try 'add --help' for help" in test_result.output
        assert "Missing option '-m' / '--metadata-url'." in test_result.output

    def test_repository_add_all_params(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()
        assert "r3" not in check_settings["REPOSITORIES"]

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.add,
            [
                "-n",
                "r3",
                "-r",
                "example_path_to_root/root.json",
                "-a",
                "http://localhost:8081",
                "-m",
                "http://localhost:8080",
            ],
            obj=test_context,
        )

        assert (
            "Successfully added r3 repository to config" in test_result.output
        )
        check_settings = test_context["settings"].as_dict()
        assert "r3" in check_settings["REPOSITORIES"]
        assert check_settings["REPOSITORIES"]["r3"]["trusted_root"] == (
            "ZXhhbXBsZV9wYXRoX3RvX3Jvb3Qvcm9vdC5qc29u"
        )
        assert check_settings["REPOSITORIES"]["r3"]["metadata_url"] == (
            "http://localhost:8080"
        )
        assert (
            check_settings["REPOSITORIES"]["r3"]["artifact_base_url"]
            == "http://localhost:8081"
        )
        assert check_settings["REPOSITORIES"]["r3"]["hash_prefix"] is False
        assert test_result.exit_code == 0

    def test_repository_add_with_hash_prefix(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()
        assert "r3" not in check_settings["REPOSITORIES"]

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.add,
            [
                "-n",
                "r3",
                "-r",
                "example_path_to_root/root.json",
                "-a",
                "http://localhost:8081",
                "-m",
                "http://localhost:8080",
                "-p",
            ],
            obj=test_context,
        )

        assert (
            "Successfully added r3 repository to config" in test_result.output
        )
        check_settings = test_context["settings"].as_dict()
        assert "r3" in check_settings["REPOSITORIES"]
        assert check_settings["REPOSITORIES"]["r3"]["hash_prefix"] is True
        assert test_result.exit_code == 0

    def test_repository_add_with_no_repos(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        check_settings = test_context["settings"].as_dict()
        assert "REPOSITORIES" not in check_settings

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.add,
            [
                "-n",
                "r3",
                "-r",
                "example_path_to_root/root.json",
                "-a",
                "http://localhost:8081",
                "-m",
                "http://localhost:8080",
                "-p",
            ],
            obj=test_context,
        )

        assert (
            "Successfully added r3 repository to config" in test_result.output
        )
        check_settings = test_context["settings"].as_dict()
        assert check_settings["REPOSITORIES"]
        assert "r3" in check_settings["REPOSITORIES"]
        assert check_settings["REPOSITORIES"]["r3"]["trusted_root"] == (
            "ZXhhbXBsZV9wYXRoX3RvX3Jvb3Qvcm9vdC5qc29u"
        )
        assert check_settings["REPOSITORIES"]["r3"]["metadata_url"] == (
            "http://localhost:8080"
        )
        assert (
            check_settings["REPOSITORIES"]["r3"]["artifact_base_url"]
            == "http://localhost:8081"
        )
        assert check_settings["REPOSITORIES"]["r3"]["hash_prefix"] is True
        assert test_result.exit_code == 0

    def test_repository_add_already_configured(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.add,
            [
                "-n",
                "r1",
                "-r",
                "example_path_to_root/root.json",
                "-a",
                "http://localhost:8081",
                "-m",
                "http://example.com",
            ],
            obj=test_context,
        )
        assert "Repository r1 already configured" in test_result.output
        assert "Successfully updated repository r1" in test_result.output
        check_settings = test_context["settings"].as_dict()
        assert check_settings["REPOSITORIES"]["r1"]["metadata_url"] == (
            "http://example.com"
        )
        assert test_result.exit_code == 0

    def test_repository_update_no_repos(
        self, client, test_context, test_setup
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        test_result = client.invoke(
            repository.update,
            [
                "-r",
                "example_path_to_root/root.json",
                "-a",
                "http://localhost:8081",
                "-m",
                "http://example.com",
                "r1",
            ],
            obj=test_context,
        )

        assert (
            "There are no configured repositories to update"
            in test_result.output
        )
        assert test_result.exit_code == 1

    def test_repository_update(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.update,
            [
                "-m",
                "http://example.com",
                "r1",
            ],
            obj=test_context,
        )

        assert "Successfully updated repository r1" in test_result.output
        check_settings = test_context["settings"].as_dict()
        assert check_settings["REPOSITORIES"]["r1"]["metadata_url"] == (
            "http://example.com"
        )
        assert test_result.exit_code == 0

    def test_repository_update_with_root_param(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.update,
            [
                "-r",
                "some_root_as_a_param",
                "r1",
            ],
            obj=test_context,
        )

        assert "Successfully updated repository r1" in test_result.output
        check_settings = test_context["settings"].as_dict()
        assert check_settings["REPOSITORIES"]["r1"]["trusted_root"] == (
            b"c29tZV9yb290X2FzX2FfcGFyYW0="
        )
        assert test_result.exit_code == 0

    def test_repository_update_with_artifact_url(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.update,
            [
                "-a",
                "http://myhost:8081",
                "r1",
            ],
            obj=test_context,
        )

        assert "Successfully updated repository r1" in test_result.output
        check_settings = test_context["settings"].as_dict()
        assert check_settings["REPOSITORIES"]["r1"]["artifact_base_url"] == (
            "http://myhost:8081"
        )
        assert test_result.exit_code == 0

    def test_repository_update_non_existing(
        self, client, test_context, test_setup
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()
        assert "non_existing" not in check_settings.get("REPOSITORIES")

        test_result = client.invoke(
            repository.update,
            [
                "-m",
                "http://example.com",
                "non_existing",
            ],
            obj=test_context,
        )

        assert (
            "Repository non_existing not available in config. "
            in test_result.output
        )
        assert "You can create it instead" in test_result.output
        assert test_result.exit_code == 1

    def test_repository_delete_no_repos(
        self, client, test_context, test_setup
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()

        assert "REPOSITORIES" not in check_settings

        test_result = client.invoke(
            repository.delete,
            ["r1"],
            obj=test_context,
        )

        assert (
            "There are no configured repositories. Nothing to delete"
            in test_result.output
        )
        assert test_result.exit_code == 1

    def test_repository_delete_non_existing(
        self, client, test_context, test_setup
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config
        check_settings = test_context["settings"].as_dict()
        assert "non_existing" not in check_settings.get("REPOSITORIES")

        test_result = client.invoke(
            repository.delete,
            ["non_existing"],
            obj=test_context,
        )

        assert (
            "Repository non_existing not available. Nothing to delete"
            in test_result.output
        )
        assert test_result.exit_code == 1

    def test_repository_delete_existing(
        self, client, test_context, test_setup, monkeypatch
    ):
        repository.setup = test_setup

        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "False",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
                "r2": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "True",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        fake_config = pretend.stub(
            as_dict=pretend.call_recorder(lambda *a: config),
        )
        test_context["settings"] = fake_config

        check_settings = test_context["settings"].as_dict()
        assert "r1" in check_settings["REPOSITORIES"]

        fake_write_config = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(WRITE_CONFIG_SRC_PATH, fake_write_config)

        test_result = client.invoke(
            repository.delete,
            ["r1"],
            obj=test_context,
        )

        assert "Succesfully deleted repository" in test_result.output
        assert (
            "{'artifact_base_url': 'http://localhost:8081'"
            in test_result.output
        )
        assert "'hash_prefix': 'False'" in test_result.output
        assert "'metadata_url': 'http://localhost:8080'" in test_result.output
        assert "'trusted_root'" in test_result.output
        assert "'some_root'" in test_result.output
        check_settings = test_context["settings"].as_dict()
        assert "r1" not in check_settings.get("REPOSITORIES")
        assert test_result.exit_code == 0
