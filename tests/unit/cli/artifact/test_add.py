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
        ]

        add.create_artifact_payload_from_filepath = pretend.call_recorder(
            lambda *a, **kw: {"k": "v"}
        )
        add.send_payload = pretend.call_recorder(lambda *a, **kw: "123")

        with client.isolated_filesystem():
            with open(artifact_path, "w") as f:
                f.write("Dummy Artifact")

            result = client.invoke(add.add, input, obj=test_context)

            assert add.create_artifact_payload_from_filepath.calls == [
                pretend.call(filepath=artifact_path, path=path)
            ]

            assert add.send_payload.calls == [
                pretend.call(
                    settings=test_context["settings"],
                    url=URL.artifacts.value,
                    payload={"k": "v"},
                    expected_msg="Target(s) successfully submitted.",
                    command_name="Artifact Addition",
                )
            ]

            assert result.exit_code == 0, result.output
            assert "Successfully submitted task" in result.output
            assert "RSTUF task ID" in result.output
