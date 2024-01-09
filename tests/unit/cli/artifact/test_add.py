# SPDX-License-Identifier: MIT

import pretend  # type: ignore

from repository_service_tuf.cli.artifact import add
from repository_service_tuf.helpers.api_client import URL


class TestAddArtifactInteraction:
    """Test the Key Generate Interaction"""

    def test_add(self, client, test_context):
        """
        Test that the add artifact command works as expected given the
        expected arguments/options in the CLI.
        """

        artifact_path = "dummy-artifact"
        path = "target/path"

        input = [
            artifact_path,  # artifact filepath
            "--path",
            path,
            "--api-server",
            "fake-server",
        ]

        add.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(add.add, input, obj=test_context)

        assert result.exit_code == 0, result.output
        assert "Successfully submitted task" in result.output
        assert "RSTUF task ID" in result.output

        assert add.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.ARTIFACTS.value,
                payload={
                    "targets": [
                        {
                            "info": {
                                "length": 14,
                                "hashes": {
                                    "blake2b-256": "5b23eadf78d64e16f4ecf121e6631c68fa8eb64fcd5a0762fd36ef37f61369e9"  # noqa
                                },
                                "custom": None,
                            },
                            "path": f"{path}/{artifact_path}",
                        }
                    ],
                    "add_task_id_to_custom": False,
                    "publish_targets": True,
                },
                expected_msg="New Artifact(s) successfully submitted.",
                command_name="Artifact Addition",
            )
        ]

    def test_add_without_path(self, client, test_context):
        """
        Test that the add artifact command works as expected given the
        expected arguments/options in the CLI.
        """

        artifact_path = "dummy-artifact"

        input = [
            artifact_path,  # artifact filepath
            "--api-server",
            "fake-server",
        ]

        add.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(add.add, input, obj=test_context)

        assert result.exit_code == 0, result.output
        assert "Successfully submitted task" in result.output
        assert "RSTUF task ID" in result.output

        assert add.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.ARTIFACTS.value,
                payload={
                    "targets": [
                        {
                            "info": {
                                "length": 14,
                                "hashes": {
                                    "blake2b-256": "5b23eadf78d64e16f4ecf121e6631c68fa8eb64fcd5a0762fd36ef37f61369e9"  # noqa
                                },
                                "custom": None,
                            },
                            "path": artifact_path,
                        }
                    ],
                    "add_task_id_to_custom": False,
                    "publish_targets": True,
                },
                expected_msg="New Artifact(s) successfully submitted.",
                command_name="Artifact Addition",
            )
        ]

    def test_add_without_api_server(self, client, test_context):
        artifact_path = "dummy-artifact"
        path = "target/path"

        input = [
            artifact_path,  # artifact filepath
            "--path",
            path,
        ]
        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(add.add, input, obj=test_context)

        assert result.exit_code == 1, result.output
        assert "Requires '--api-server'" in result.output
