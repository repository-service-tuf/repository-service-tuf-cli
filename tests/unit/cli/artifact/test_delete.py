# SPDX-License-Identifier: MIT

import pretend  # type: ignore

from repository_service_tuf.cli.artifact import delete
from repository_service_tuf.helpers.api_client import URL


class TestDeleteArtifactInteraction:
    """Test the Key Generate Interaction"""

    def test_delete(self, client, test_context):
        """
        Test that the delete artifact command works as expected given the
        expected arguments/options in the CLI.
        """

        artifact_path = "dummy-artifact"
        path = "target/path"

        input = [
            artifact_path,
            "--path",
            path,
            "--api-server",
            "fake-server",
        ]

        delete.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(delete.delete, input, obj=test_context)

        assert result.exit_code == 0, result.output
        assert "Successfully submitted task" in result.output
        assert "RSTUF task ID" in result.output

        assert delete.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.ARTIFACTS_DELETE.value,
                payload={
                    "targets": [
                        f"{path}/{artifact_path}",
                    ],
                },
                expected_msg="Remove Artifact(s) successfully submitted.",
                command_name="Artifact Deletion",
            )
        ]

    def test_delete_without_path(self, client, test_context):
        """
        Test that the delete artifact command works as expected given the
        expected arguments/options in the CLI.
        """

        artifact_path = "dummy-artifact"

        input = [
            artifact_path,  # artifact filepath
            "--api-server",
            "fake-server",
        ]

        delete.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(delete.delete, input, obj=test_context)

        assert result.exit_code == 0, result.output
        assert "Successfully submitted task" in result.output
        assert "RSTUF task ID" in result.output

        assert delete.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.ARTIFACTS_DELETE.value,
                payload={
                    "targets": [
                        artifact_path,
                    ],
                },
                expected_msg="Remove Artifact(s) successfully submitted.",
                command_name="Artifact Deletion",
            )
        ]

    def test_delete_without_api_server(self, client, test_context):
        """
        Test that the delete artifact command works as expected given the
        expected arguments/options in the CLI.
        """
        settings = test_context["settings"]
        settings.SERVER = "fake-server"

        artifact_path = "dummy-artifact"
        path = "target/path"

        input = [
            artifact_path,
            "--path",
            path,
        ]

        delete.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(delete.delete, input, obj=test_context)

        assert result.exit_code == 0, result.output
        assert "Successfully submitted task" in result.output
        assert "RSTUF task ID" in result.output

        assert delete.send_payload.calls == [
            pretend.call(
                settings=settings,
                url=URL.ARTIFACTS_DELETE.value,
                payload={
                    "targets": [
                        f"{path}/{artifact_path}",
                    ],
                },
                expected_msg="Remove Artifact(s) successfully submitted.",
                command_name="Artifact Deletion",
            )
        ]

    def test_delete_with_api_server_as_input(self, client, test_context):
        """
        Test that the delete artifact command works as expected given the
        expected arguments/options in the CLI.
        """
        artifact_path = "dummy-artifact"
        path = "target/path"
        prompt_api_server_input = "fake-server"

        options_input = [
            artifact_path,
            "--path",
            path,
        ]

        delete.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(
                delete.delete,
                options_input,
                input=prompt_api_server_input,
                obj=test_context,
            )

        assert result.exit_code == 0, result.output
        assert "Successfully submitted task" in result.output
        assert "RSTUF task ID" in result.output

        assert delete.send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=URL.ARTIFACTS_DELETE.value,
                payload={
                    "targets": [
                        f"{path}/{artifact_path}",
                    ],
                },
                expected_msg="Remove Artifact(s) successfully submitted.",
                command_name="Artifact Deletion",
            )
        ]
